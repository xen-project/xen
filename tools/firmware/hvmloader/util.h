#ifndef __HVMLOADER_UTIL_H__
#define __HVMLOADER_UTIL_H__

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <xen/xen.h>
#include <xen/hvm/hvm_info_table.h>
#include "config.h"
#include "e820.h"

#include <xen-tools/common-macros.h>

/* Request un-prefixed values from errno.h. */
#define XEN_ERRNO(name, value) name = value,
enum {
#include <xen/errno.h>
};

/* Cause xs_wire.h to give us xsd_errors[]. */
#define EINVAL EINVAL

/* GDT selector values. */
#define SEL_CODE16          0x0008
#define SEL_DATA16          0x0010
#define SEL_CODE32          0x0018
#define SEL_DATA32          0x0020
#define SEL_CODE64          0x0028

void __assert_failed(const char *assertion, const char *file, int line)
    __attribute__((noreturn));
#define ASSERT(p) \
    do { if (!(p)) __assert_failed(#p, __FILE__, __LINE__); } while (0)
void __bug(const char *file, int line) __attribute__((noreturn));
#define BUG() __bug(__FILE__, __LINE__)
#define BUG_ON(p) do { if (p) BUG(); } while (0)

static inline int test_bit(unsigned int b, const void *p)
{
    return !!(((const uint8_t *)p)[b>>3] & (1u<<(b&7)));
}

static inline int test_and_clear_bit(int nr, volatile void *addr)
{
    int oldbit;
    asm volatile (
        "lock ; btrl %2,%1 ; sbbl %0,%0"
        : "=r" (oldbit), "=m" (*(volatile long *)addr)
        : "Ir" (nr), "m" (*(volatile long *)addr) : "memory");
    return oldbit;
}

/* MSR access */
static inline void wrmsr(uint32_t idx, uint64_t v)
{
    asm volatile ( "wrmsr" :: "c" (idx), "A" (v) );
}

static inline uint64_t rdmsr(uint32_t idx)
{
    uint64_t res;

    asm volatile ( "rdmsr" : "=A" (res) : "c" (idx) );

    return res;
}

/* I/O output */
static inline void outb(uint16_t port, uint8_t val)
{
    asm volatile ( "outb %[val], %[port]"
                   :
                   : [port] "Nd" (port),
                     [val] "a" (val)
                   : "memory" );
}

static inline void outw(uint16_t port, uint16_t val)
{
    asm volatile ( "outw %[val], %[port]"
                   :
                   : [port] "Nd" (port),
                     [val] "a" (val)
                   : "memory" );
}

static inline void outl(uint16_t port, uint32_t val)
{
    asm volatile ( "outl %[val], %[port]"
                   :
                   : [port] "Nd" (port),
                     [val] "a" (val)
                   : "memory" );
}

/* I/O input */
static inline uint8_t inb(uint16_t port)
{
    uint8_t val;

    asm volatile ( "inb %[port], %[val]"
                   : [val] "=a" (val)
                   : [port] "Nd" (port)
                   : "memory" );

    return val;
}

static inline uint16_t inw(uint16_t port)
{
    uint16_t val;

    asm volatile ( "inw %[port], %[val]"
                   : [val] "=a" (val)
                   : [port] "Nd" (port)
                   : "memory" );

    return val;
}

static inline uint32_t inl(uint16_t port)
{
    uint32_t val;

    asm volatile ( "inl %[port], %[val]"
                   : [val] "=a" (val)
                   : [port] "Nd" (port)
                   : "memory" );

    return val;
}

/* CMOS access */
uint8_t cmos_inb(uint8_t idx);
void cmos_outb(uint8_t idx, uint8_t val);

/* APIC access */
#define IOAPIC_BASE_ADDRESS 0xfec00000
static inline uint32_t ioapic_read(uint32_t reg)
{
    *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x00) = reg;
    return *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x10);
}

static inline void ioapic_write(uint32_t reg, uint32_t val)
{
    *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x00) = reg;
    *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x10) = val;
}

#define LAPIC_BASE_ADDRESS  0xfee00000
static inline uint32_t lapic_read(uint32_t reg)
{
    return *(volatile uint32_t *)(LAPIC_BASE_ADDRESS + reg);
}

static inline void lapic_write(uint32_t reg, uint32_t val)
{
    *(volatile uint32_t *)(LAPIC_BASE_ADDRESS + reg) = val;
}

/* PCI access */
uint32_t pci_read(uint32_t devfn, uint32_t reg, uint32_t len);
#define pci_readb(devfn, reg) ((uint8_t) pci_read(devfn, reg, 1))
#define pci_readw(devfn, reg) ((uint16_t)pci_read(devfn, reg, 2))
#define pci_readl(devfn, reg) ((uint32_t)pci_read(devfn, reg, 4))
void pci_write(uint32_t devfn, uint32_t reg, uint32_t len, uint32_t val);
#define pci_writeb(devfn, reg, val) pci_write(devfn, reg, 1, (uint8_t) (val))
#define pci_writew(devfn, reg, val) pci_write(devfn, reg, 2, (uint16_t)(val))
#define pci_writel(devfn, reg, val) pci_write(devfn, reg, 4, (uint32_t)(val))

/* Get a pointer to the shared-info page */
struct shared_info *get_shared_info(void) __attribute__ ((const));

/* Get CPU speed in MHz. */
uint16_t get_cpu_mhz(void);

/* Hardware detection. */
int uart_exists(uint16_t uart_base);
int lpt_exists(uint16_t lpt_base);
int hpet_exists(unsigned long hpet_base);

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void cpuid_count(
    uint32_t leaf,
    uint32_t subleaf,
    uint32_t *eax,
    uint32_t *ebx,
    uint32_t *ecx,
    uint32_t *edx)
{
    uint32_t tmp;

    if ( !eax )
        eax = &tmp;
    if ( !ebx )
        ebx = &tmp;
    if ( !ecx )
        ecx = &tmp;
    if ( !edx )
        edx = &tmp;

    asm volatile ( "cpuid"
                   : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
                   : "a" (leaf), "c" (subleaf) );
}

/* Generic CPUID function (subleaf 0) */
static inline void cpuid(
    uint32_t leaf,
    uint32_t *eax,
    uint32_t *ebx,
    uint32_t *ecx,
    uint32_t *edx)
{
    cpuid_count(leaf, 0, eax, ebx, ecx, edx);
}

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
#define mb()      asm volatile ( "lock addl $0, -4(%%esp)" ::: "memory" )

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
struct hvm_info_table *get_hvm_info_table(void) __attribute__ ((const));
#define hvm_info (get_hvm_info_table())

/* HVM start info */
extern const struct hvm_start_info *hvm_start_info;

/* String and memory functions */
int strcmp(const char *cs, const char *ct);
int strncmp(const char *s1, const char *s2, uint32_t n);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, unsigned n);
unsigned strlen(const char *s);
long long strtoll(const char *s, char **end, int base);
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
#define PRIllx "%x%08x"
#define PRIllx_arg(ll) (uint32_t)((ll)>>32), (uint32_t)(ll)
int printf(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
int vprintf(const char *fmt, va_list ap);

/* Buffer output */
int snprintf(char *buf, size_t size, const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));

/* Populate specified memory hole with RAM. */
void mem_hole_populate_ram(xen_pfn_t mfn, uint32_t nr_mfns);

/* Allocate a memory hole below 4GB. */
xen_pfn_t mem_hole_alloc(uint32_t nr_mfns);

/* Allocate memory in a reserved region below 4GB. */
void *mem_alloc(uint32_t size, uint32_t align);
#define virt_to_phys(v) ((unsigned long)(v))

/* Allocate memory in a scratch region */
void *scratch_alloc(uint32_t size, uint32_t align);

/* Connect our xenbus client to the backend.  
 * Call once, before any other xenbus actions. */
void xenbus_setup(void);

/* Reset the xenbus connection so the next kernel can start again. */
void xenbus_shutdown(void);

/* Read a xenstore key.  Returns a nul-terminated string (even if the XS
 * data wasn't nul-terminated) or NULL.  The returned string is in a
 * static buffer, so only valid until the next xenstore/xenbus operation.
 * If @default_resp is specified, it is returned in preference to a NULL or
 * empty string received from xenstore.
 */
const char *xenstore_read(const char *path, const char *default_resp);

/* Write a xenstore key.  @value must be a nul-terminated string. Returns
 * zero on success or a xenstore error code on failure.
 */
int xenstore_write(const char *path, const char *value);


/* Get a HVM param.
 */
int hvm_param_get(uint32_t index, uint64_t *value);

/* Set a HVM param.
 */
int hvm_param_set(uint32_t index, uint64_t value);

/* Setup PCI bus */
void pci_setup(void);

/* Setup memory map  */
void memory_map_setup(void);

/* Sync memory map */
void adjust_memory_map(void);

/* Prepare the 32bit BIOS */
uint32_t rombios_highbios_setup(void);

/* Miscellaneous. */
unsigned int cpu_phys_addr(void);
void cacheattr_init(void);
unsigned long create_mp_tables(void *table);
void hvm_write_smbios_tables(
    unsigned long ep, unsigned long smbios_start, unsigned long smbios_end);
unsigned long create_pir_tables(void);

void smp_initialise(void);

#include "e820.h"
int build_e820_table(struct e820entry *e820,
                     unsigned int lowmem_reserved_base,
                     unsigned int bios_image_base);
void dump_e820_table(struct e820entry *e820, unsigned int nr);

#ifndef NDEBUG
void perform_tests(void);
#else
#define perform_tests() ((void)0)
#endif

extern char _start[], _end[];

int get_mem_mapping_layout(struct e820entry entries[],
                           unsigned int *max_entries);

extern struct e820map memory_map;
bool check_overlap(uint64_t start, uint64_t size,
                   uint64_t reserved_start, uint64_t reserved_size);

extern const unsigned char dsdt_anycpu_qemu_xen[], dsdt_anycpu[], dsdt_15cpu[];
extern const int dsdt_anycpu_qemu_xen_len, dsdt_anycpu_len, dsdt_15cpu_len;

unsigned long acpi_pages_allocated(void);

struct acpi_config;
void hvmloader_acpi_build_tables(struct acpi_config *config,
                                 unsigned int physical);

#endif /* __HVMLOADER_UTIL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
