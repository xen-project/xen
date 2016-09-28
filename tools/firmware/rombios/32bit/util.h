#ifndef UTIL_H
#define UTIL_H

#include <acpi2_0.h>

void outb(uint16_t addr, uint8_t val);
void outw(uint16_t addr, uint16_t val);
void outl(uint16_t addr, uint32_t val);
uint8_t inb(uint16_t addr);
uint16_t inw(uint16_t addr);
uint32_t inl(uint16_t addr);
void mssleep(uint32_t time);

char *itoa(char *a, unsigned int i);
int strcmp(const char *cs, const char *ct);
int strncmp(const char *s1, const char *s2, uint32_t n);
void *memcpy(void *dest, const void *src, unsigned n);
void *memmove(void *dest, const void *src, unsigned n);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, unsigned n);
unsigned strlen(const char *s);
void * memset(void *s, int c, unsigned n);
int memcmp(const void *s1, const void *s2, unsigned n);
void cpuid(uint32_t idx, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx);
void byte_to_hex(char *digits, uint8_t byte);
void uuid_to_string(char *dest, uint8_t *uuid);
int printf(const char *fmt, ...);

static inline uint8_t mmio_readb(uint8_t *addr)
{
	return *(volatile uint8_t *)addr;
}

static inline uint16_t mmio_readw(uint16_t *addr)
{
	return *(volatile uint16_t *)addr;
}

static inline uint32_t mmio_readl(uint32_t *addr)
{
	return *(volatile uint32_t *)addr;
}

struct acpi_20_rsdp *find_rsdp(void);

#endif
