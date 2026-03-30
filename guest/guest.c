#include <stdint.h>

static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

static void inb(uint16_t port, uint8_t* data) {
	asm("inb %1,%0" : "=a" (*data): "d" (port) );
}


static void outsb(uint16_t port, const uint8_t* data, uint32_t count) {
	asm volatile(
		"cld\n"
		"rep outsb\n"
		: "+S"(data), "+c"(count)
		: "d"(port)
		: "memory"
	);
}

static void insb(uint16_t port, uint8_t* dest, uint32_t count) {
	asm volatile(
		"cld\n"
		"rep ins%z2\n"
		: "+D"(dest), "+c"(count), "=a"(*dest)
		: "d"(port)
		: "memory"
	);
}

static void println(const uint8_t* str, uint32_t count) {
	outsb(0xE9, str, count);
	outb(0xE9, '\n');
}


void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {

	/*
		INSERT CODE BELOW THIS LINE
	*/

	const char *p;
	uint16_t port = 0xE9;

	
	uint8_t tmp;
	inb(port, &tmp);
	outb(port, tmp);
	tmp = '\n';
	outb(port, tmp);
	
	
	for (p = "Hello, world!\n"; *p; ++p)
		outb(port, *p);

	// char buf[16] = "Hello, 2!\n";
	// outsb(port, (const uint8_t*)buf, 10);

	// println((const uint8_t*)"\nEnter a string:", 20);
	// char input[16];
	// insb(port, (uint8_t*)input, 16);
	// println((const uint8_t*)input, 16);
	
	/*
		INSERT CODE ABOVE THIS LINE
	*/

	for (;;)
		asm("hlt");
}
