#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>

//#define MEM_SIZE (2u * 1024u * 1024u) // Memory size will be 2MB

uint32_t MEM_SIZE; // Keeping the same name as the original macro
uint32_t PAGE_SIZE; // Same naming for consistency


//#define GUEST_START_ADDR 0x8000 // Start address for loading the guest
#define GUEST_START_ADDR 0x0 // This one works

// PDE bits
#define PDE64_PRESENT (1u << 0)
#define PDE64_RW (1u << 1)
#define PDE64_USER (1u << 2)
#define PDE64_PS (1u << 7)

// CR4 i CR0
#define CR0_PE (1u << 0)
#define CR0_PG (1u << 31)
#define CR4_PAE (1u << 5)

#define EFER_LME (1u << 8)
#define EFER_LMA (1u << 10)

struct vm {
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	char *mem;
	size_t mem_size;
	struct kvm_run *run;
	int run_mmap_size;
};

int vm_init(struct vm *v, size_t mem_size)
{
	struct kvm_userspace_memory_region region;	

	memset(v, 0, sizeof(*v));
	v->kvm_fd = v->vm_fd = v->vcpu_fd = -1;
	v->mem = MAP_FAILED;
	v->run = MAP_FAILED;
	v->run_mmap_size = 0;
	v->mem_size = mem_size;

	v->kvm_fd = open("/dev/kvm", O_RDWR);
	if (v->kvm_fd < 0) {
		perror("open /dev/kvm");
		return -1;
	}

    int api = ioctl(v->kvm_fd, KVM_GET_API_VERSION, 0);
    if (api != KVM_API_VERSION) {
        printf("KVM API mismatch: kernel=%d headers=%d\n", api, KVM_API_VERSION);
        return -1;
    }

	v->vm_fd = ioctl(v->kvm_fd, KVM_CREATE_VM, 0);
	if (v->vm_fd < 0) {
		perror("KVM_CREATE_VM");
		return -1;
	}

	v->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (v->mem == MAP_FAILED) {
		perror("mmap mem");
		return -1;
	}

	region.slot = 0;
	region.flags = 0;
	region.guest_phys_addr = 0;
	region.memory_size = v->mem_size;
	region.userspace_addr = (uintptr_t)v->mem;
    if (ioctl(v->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
	}

	v->vcpu_fd = ioctl(v->vm_fd, KVM_CREATE_VCPU, 0);
    if (v->vcpu_fd < 0) {
		perror("KVM_CREATE_VCPU");
        return -1;
	}

	v->run_mmap_size = ioctl(v->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (v->run_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
		return -1;
	}

	v->run = mmap(NULL, v->run_mmap_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, v->vcpu_fd, 0);
	if (v->run == MAP_FAILED) {
		perror("mmap kvm_run");
		return -1;
	}

	return 0;
}

void vm_destroy(struct vm *v) {
	if (v->run && v->run != MAP_FAILED) {
		munmap(v->run, (size_t)v->run_mmap_size);
		v->run = MAP_FAILED;
	}

	if(v->mem && v->mem != MAP_FAILED) {
		munmap(v->mem, v->mem_size);
		v->mem = MAP_FAILED;
	}

	if (v->vcpu_fd >= 0) {
		close(v->vcpu_fd);
		v->vcpu_fd = -1;
	}

	if (v->vm_fd >= 0) {
		close(v->vm_fd);
		v->vm_fd = -1;
	}

	if (v->kvm_fd >= 0) {
		close(v->kvm_fd);
		v->kvm_fd = -1;
	}
}

static void setup_segments_64(struct kvm_sregs *sregs)
{
	// .selector = 0x8,
	struct kvm_segment code = {
		.base = 0,
		.limit = 0xffffffff,
		.present = 1, // Present or loaded into memory
		.type = 11, // Code: execute, read, accessed
		.dpl = 0, // Descriptor Privilage Level: 0 (0, 1, 2, 3)
		.db = 0, // Default size - has value 0 in long mode
		.s = 1, // Code/data segment type
		.l = 1, // Long mode - 1
		.g = 1, // 4KB granularity
	};
	struct kvm_segment data = code;
	data.type = 3; // Data: read, write, accessed
	data.l = 0;
	// data.selector = 0x10; // Data segment selector

	sregs->cs = code;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = data;
}

// Enabling long mode.
static void setup_long_mode(struct vm *v, struct kvm_sregs *sregs, size_t page_size)
{
	// Setting 4 levels of nesting.
	// Each page table has 512 entries, and every entry is 8 bytes.
	// That's why page size is 4KB. These tables must be aligned to 4KB
	uint64_t page = 0;
	uint64_t pml4_addr = 0x1000; // Adrese su proizvoljne.
	uint64_t *pml4 = (void *)(v->mem + pml4_addr);

	uint64_t pdpt_addr = 0x2000;
	uint64_t *pdpt = (void *)(v->mem + pdpt_addr);

	uint64_t pd_addr = 0x3000;
	uint64_t *pd = (void *)(v->mem + pd_addr);

	uint64_t pt_addr = 0x4000;
	uint64_t *pt = (void *)(v->mem + pt_addr);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;



    // ===========
    if (page_size == 4u * 1024u) // 4KB
    {
        pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
        pt[0] = GUEST_START_ADDR | PDE64_PRESENT | PDE64_RW | PDE64_USER;
        pt[511] = 0x6000 | PDE64_PRESENT | PDE64_RW | PDE64_USER; // ?

        page = 0;
        for(int i = 1; i < MEM_SIZE/PAGE_SIZE; i++) {
        	pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
        	page += PAGE_SIZE;
        }
    }
    else if (page_size == 2u * 1024u * 1024u) // 2MB
    {
        pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
        pd[511] = 0x6000 | PDE64_PRESENT | PDE64_RW | PDE64_USER; // ?

        page = 0;
        for(int i = 1; i < MEM_SIZE/PAGE_SIZE; i++) {
        	pd[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
        	page += PAGE_SIZE;
        }
    }
    // ===========

	// Register pointing to PML4 page table. This is where VA to PA mapping starts.
	sregs->cr3  = pml4_addr; 
	sregs->cr4  = CR4_PAE; // "Physical Address Extension" must be 1 for long mode.
	sregs->cr0  = CR0_PE | CR0_PG; // Setting "Protected Mode" and "Paging". 
	sregs->efer = EFER_LME | EFER_LMA; // Setting  "Long Mode Active" and "Long Mode Enable".

	// Initializing segments for 64-bit mode.
	setup_segments_64(sregs);
}

int load_guest_image(struct vm *v, const char *image_path, uint64_t load_addr) {
	FILE *f = fopen(image_path, "rb");
	if (!f) {
		perror("Failed to open guest image");
		return -1;
	}

	if (fseek(f, 0, SEEK_END) < 0) {
		perror("Failed to seek to end of guest image");
		fclose(f);
		return -1;
	}

	long fsz = ftell(f);
	if (fsz < 0) {
		perror("Failed to get size of guest image");
		fclose(f);
		return -1;
	}
	rewind(f);

	if((uint64_t)fsz > v->mem_size - load_addr) {
		printf("Guest image is too large for the VM memory");
		fclose(f);
		return -1;
	}

	if (fread((uint8_t*)v->mem + load_addr, 1, (size_t)fsz, f) != (size_t)fsz) {
		perror("Failed to read guest image");
		fclose(f);
		return -1;
	}
	fclose(f);

	return 0;
}

static int32_t args_error(const char* error)
{
    printf("%s\n", error);
    printf(
        "Usage:\n"
        "<program_name> [options]\n\n"
        "Options:\n"
        " -m, --memory <2|4|8>          Specify between 2, 4 or 8MB memory size.\n"
        " -p, --page <2|4>              Specify between 2MB and 4KB page size.\n"
        " -g, --guest <image_name>.img  Specify image file.\n"
        );
    return -1;
}

static int32_t check_args(int argc, char *argv[], uint32_t* memory_size, uint32_t* page_size, char** guest_img) {
    // Check if command line arguments are valid

    int16_t memf_cnt, pgf_cnt, gstf_cnt;
    memf_cnt = pgf_cnt = gstf_cnt = 0;

    for (size_t i = 1; i < argc; i++)
    {

        if (!strcmp(argv[i], "--memory") || !strcmp(argv[i], "-m"))
        {
            if (++i < argc)
                *memory_size = atoi(argv[i]);
            else 
                return args_error("Error: Invalid memroy size argument.\n");
            
            if (++memf_cnt > 1)
                return args_error("Error: Multiple memory options specified.\n");
            
            if (*memory_size != 2 && *memory_size != 4 && *memory_size != 8)
                return args_error("Error: Invalid memroy size argument.\n");

        }
        else if (!strcmp(argv[i], "--page") || !strcmp(argv[i], "-p"))
        {
            if (++i < argc)
                *page_size = atoi(argv[i]);
            else 
                return args_error("Error: Invalid page size argument.\n");

            if (++pgf_cnt > 1)
                return args_error("Error: Multiple page options specified.\n");

            if (*page_size != 2 && *page_size != 4)
                return args_error("Error: Invalid page size argument.\n");
        }
        else if (!strcmp(argv[i], "--guest") || !strcmp(argv[i], "-g"))
        {
            if (++i < argc) // Nothing for now
                *guest_img = argv[i];
            else 
                return args_error("Error: Invalid guest image path.\n");

            if (++gstf_cnt > 1)
                return args_error("Error: Multiple guest options specified.\n");
        }
        else
        {
            printf("Error: Unknown option: '%s'.", argv[i]);
            return args_error(" Unknown option specified.");
        }
    }

    if (memf_cnt == 0 || pgf_cnt == 0 || gstf_cnt == 0)
        return args_error("Error: Not all options specified.\n");

    return 0;
}

int main(int argc, char *argv[])
{
	struct vm v;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	int stop = 0;
	int ret = 0;
	FILE* img;
	int data;

    uint32_t memsz_arg;
    uint32_t pgsz_arg;
    char* imgname_arg;

	if (check_args(argc, argv, &memsz_arg, &pgsz_arg, &imgname_arg))
        return 1;

    MEM_SIZE = memsz_arg * 1024u * 1024u;
    PAGE_SIZE = pgsz_arg * 1024u;
    if (pgsz_arg == 2) PAGE_SIZE *= 1024u;

	if (vm_init(&v, MEM_SIZE)) {
		printf("Failed to init the VM\n");
		return 1;
	}

	if (ioctl(v.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		vm_destroy(&v);
		return 1;
	}

	setup_long_mode(&v, &sregs, PAGE_SIZE);

    if (ioctl(v.vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		vm_destroy(&v);
		return 1;
	}

	if (load_guest_image(&v, imgname_arg, GUEST_START_ADDR) < 0) {
		printf("Failed to load guest image\n");
		vm_destroy(&v);
		return 1;
	}

	memset(&regs, 0, sizeof(regs));
	regs.rflags = 0x2;
	
	// PC gets mapped to the physical address GUEST_START_ADDR.
	// GUEST_START_ADDR is where the guest program is loaded.
	regs.rip = 0; 
	regs.rsp = 2 << 20; // SP raste nadole

	if (ioctl(v.vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		return 1;
	}

	while(stop == 0) {
		ret = ioctl(v.vcpu_fd, KVM_RUN, 0);
		if (ret == -1) {
			printf("KVM_RUN failed\n");
			vm_destroy(&v);
			return 1;
		}

		switch (v.run->exit_reason) {
			case KVM_EXIT_IO:
				if (v.run->io.direction == KVM_EXIT_IO_OUT && v.run->io.port == 0xE9)
				{
					char *p = (char *)v.run;
					printf("%c", *(p + v.run->io.data_offset));
				}
				else if (v.run->io.direction == KVM_EXIT_IO_IN && v.run->io.port == 0xE9)
                {
					char *p = (char *)v.run;
                    printf("Enter a number:\n");
                    scanf("%c", (char *)(&data));
					//char *data_in = ( p + v.run->io.data_offset );
                    //(*data_in) = data;
					//*(p + v.run->io.data_offset) = data;
					char *data_in = ( ((char *)v.run) + v.run->io.data_offset );
					(*data_in) = data;
				}
				continue;
			case KVM_EXIT_HLT:
				printf("KVM_EXIT_HLT\n");
				stop = 1;
				break;
			case KVM_EXIT_SHUTDOWN:
				printf("Shutdown\n");
				stop = 1;
				break;
			default:
				printf("Default - exit reason: %d\n", v.run->exit_reason);
				break;
    	}
  	}

	vm_destroy(&v);
}
