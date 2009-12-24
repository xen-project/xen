#ifndef __HVMLOADER_UTIL_H__
#define __HVMLOADER_UTIL_H__

#include <stdarg.h>
#include <stdint.h>
#include <xen/hvm/hvm_info_table.h>

#define __STR(...) #__VA_ARGS__
#define STR(...) __STR(__VA_ARGS__)

/* GDT selector values. */
#define SEL_CODE16          0x0008
#define SEL_DATA16          0x0010
#define SEL_CODE32          0x0018
#define SEL_DATA32          0x0020
#define SEL_CODE64          0x0028

#undef offsetof
#define offsetof(t, m) ((unsigned long)&((t *)0)->m)

#undef NULL
#define NULL ((void*)0)

void __assert_failed(char *assertion, char *file, int line)
    __attribute__((noreturn));
#define ASSERT(p) \
    do { if (!(p)) __assert_failed(#p, __FILE__, __LINE__); } while (0)
void __bug(char *file, int line) __attribute__((noreturn));
#define BUG() __bug(__FILE__, __LINE__)
#define BUG_ON(p) do { if (p) BUG(); } while (0)
#define BUILD_BUG_ON(p) ((void)sizeof(char[1 - 2 * !!(p)]))

static inline int test_bit(unsigned int b, void *p)
{
    return !!(((uint8_t *)p)[b>>3] & (1u<<(b&7)));
}

/* MSR access */
void wrmsr(uint32_t idx, uint64_t v);
uint64_t rdmsr(uint32_t idx);

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

/* Get CPU speed in MHz. */
uint16_t get_cpu_mhz(void);

/* Hardware detection. */
int uart_exists(uint16_t uart_base);
int lpt_exists(uint16_t lpt_base);
int hpet_exists(unsigned long hpet_base);

/* Do cpuid instruction, with operation 'idx' */
void cpuid(uint32_t idx, uint32_t *eax, uint32_t *ebx,
           uint32_t *ecx, uint32_t *edx);

/* Read the TSC register. */
static inline uint64_t rdtsc(void)
{
    uint64_t tsc;
    asm volatile ( "rdtsc" : "=A" (tsc) );
    return tsc;
}

/* Relax the CPU and let the compiler know that time passes. */
static inline void cpu_relax(void)
{
    asm volatile ( "rep ; nop" : : : "memory" );
}

/* Memory barriers. */
#define barrier() asm volatile ( "" : : : "memory" )
#define rmb()     barrier()
#define wmb()     barrier()
#define mb()      asm volatile ( "lock; addl $0,0(%%esp)" : : : "memory" )

/*
 * Divide a 64-bit dividend by a 32-bit divisor.
 * (1) Overwrites the 64-bit dividend _in_place_ with the quotient
 * (2) Returns the 32-bit remainder
 */
#define do_div(n, base) ({                                      \
    unsigned long __upper, __low, __high, __mod, __base;        \
    __base = (base);                                            \
    asm ( "" : "=a" (__low), "=d" (__high) : "A" (n) );         \
    __upper = __high;                                           \
    if ( __high )                                               \
    {                                                           \
        __upper = __high % (__base);                            \
        __high = __high / (__base);                             \
    }                                                           \
    asm ( "divl %2"                                             \
          : "=a" (__low), "=d" (__mod)                          \
          : "rm" (__base), "0" (__low), "1" (__upper) );        \
    asm ( "" : "=A" (n) : "a" (__low), "d" (__high) );          \
    __mod;                                                      \
})

/* HVM-builder info. */
struct hvm_info_table *get_hvm_info_table(void);
#define hvm_info (get_hvm_info_table())

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

/* Allocate memory in a reserved region below 4GB. */
void *mem_alloc(uint32_t size, uint32_t align);
#define virt_to_phys(v) ((unsigned long)(v))

/* Prepare the 32bit BIOS */
uint32_t highbios_setup(void);

/* Miscellaneous. */
void cacheattr_init(void);
void create_mp_tables(void);
int hvm_write_smbios_tables(void);
void smp_initialise(void);

#ifndef NDEBUG
void perform_tests(void);
#else
#define perform_tests() ((void)0)
#endif

#define isdigit(c) ((c) >= '0' && (c) <= '9')

extern char _start[], _end[];

#endif /* __HVMLOADER_UTIL_H__ */
