#ifndef __HVMLOADER_UTIL_H__
#define __HVMLOADER_UTIL_H__

#include <stdarg.h>

#undef offsetof
#define offsetof(t, m) ((unsigned long)&((t *)0)->m)

#undef NULL
#define NULL ((void*)0)

extern void __assert_failed(char *assertion, char *file, int line)
    __attribute__((noreturn));
#define ASSERT(p) \
    do { if (!(p)) __assert_failed(#p, __FILE__, __LINE__); } while (0)
extern void __bug(char *file, int line) __attribute__((noreturn));
#define BUG() __bug()

/* I/O output */
void outb(uint16_t addr, uint8_t  val);
void outw(uint16_t addr, uint16_t val);
void outl(uint16_t addr, uint32_t val);

/* I/O input */
uint8_t  inb(uint16_t addr);
uint16_t inw(uint16_t addr);
uint32_t inl(uint16_t addr);

/* CMOS access */
uint8_t cmos_inb(uint8_t idx);
void cmos_outb(uint8_t idx, uint8_t val);

/* APIC access */
uint32_t ioapic_read(uint32_t reg);
void ioapic_write(uint32_t reg, uint32_t val);
uint32_t lapic_read(uint32_t reg);
void lapic_write(uint32_t reg, uint32_t val);

/* PCI access */
uint32_t pci_read(uint32_t devfn, uint32_t reg, uint32_t len);
#define pci_readb(devfn, reg) ((uint8_t) pci_read(devfn, reg, 1))
#define pci_readw(devfn, reg) ((uint16_t)pci_read(devfn, reg, 2))
#define pci_readl(devfn, reg) ((uint32_t)pci_read(devfn, reg, 4))
void pci_write(uint32_t devfn, uint32_t reg, uint32_t len, uint32_t val);
#define pci_writeb(devfn, reg, val) (pci_write(devfn, reg, 1, (uint8_t) val))
#define pci_writew(devfn, reg, val) (pci_write(devfn, reg, 2, (uint16_t)val))
#define pci_writel(devfn, reg, val) (pci_write(devfn, reg, 4, (uint32_t)val))

/* Do cpuid instruction, with operation 'idx' */
void cpuid(uint32_t idx, uint32_t *eax, uint32_t *ebx,
           uint32_t *ecx, uint32_t *edx);

/* HVM-builder info. */
int get_vcpu_nr(void);
int get_acpi_enabled(void);
int get_apic_mode(void);

/* String and memory functions */
int strcmp(const char *cs, const char *ct);
int strncmp(const char *s1, const char *s2, uint32_t n);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, unsigned n);
unsigned strlen(const char *s);
int memcmp(const void *s1, const void *s2, unsigned n);
void *memcpy(void *dest, const void *src, unsigned n);
void *memmove(void *dest, const void *src, unsigned n);
void *memset(void *s, int c, unsigned n);
char *itoa(char *a, unsigned int i);

/* convert a byte to two lowercase hex digits, with no terminating NUL 
   character.  digits[] must have at least two elements. */
void byte_to_hex(char *digits, uint8_t byte);

/* Convert an array of 16 unsigned bytes to a DCE/OSF formatted UUID
   string. Pre-condition: sizeof(dest) >= 37 */
void uuid_to_string(char *dest, uint8_t *uuid);

/* Debug output */
int printf(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
int vprintf(const char *fmt, va_list ap);

/* Reserve a RAM region in the e820 table. */
uint32_t e820_malloc(uint32_t size);

/* General e820 access. */
#include <xen/hvm/e820.h>
#define E820_MAP_NR ((unsigned char *)E820_MAP_PAGE + E820_MAP_NR_OFFSET)
#define E820_MAP    ((struct e820entry *)(E820_MAP_PAGE + E820_MAP_OFFSET))

/* Prepare the 32bit BIOS */
void highbios_setup(void);

#define isdigit(c) ((c) >= '0' && (c) <= '9')

#endif /* __HVMLOADER_UTIL_H__ */
