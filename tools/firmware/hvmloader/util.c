/*
 * util.c: Helper library functions for HVMLoader.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include "util.h"
#include "config.h"
#include "hypercall.h"
#include "ctype.h"
#include <stdint.h>
#include <xen/xen.h>
#include <xen/memory.h>
#include <xen/sched.h>

/*
 * Check whether there exists overlap in the specified memory range.
 * Returns true if exists, else returns false.
 */
bool check_overlap(uint64_t start, uint64_t size,
                   uint64_t reserved_start, uint64_t reserved_size)
{
    return (start + size > reserved_start) &&
            (start < reserved_start + reserved_size);
}

void wrmsr(uint32_t idx, uint64_t v)
{
    asm volatile (
        "wrmsr"
        : : "c" (idx), "a" ((uint32_t)v), "d" ((uint32_t)(v>>32)) );
}

uint64_t rdmsr(uint32_t idx)
{
    uint32_t lo, hi;

    asm volatile (
        "rdmsr"
        : "=a" (lo), "=d" (hi) : "c" (idx) );

    return (lo | ((uint64_t)hi << 32));
}

void outb(uint16_t addr, uint8_t val)
{
    asm volatile ( "outb %%al, %%dx" : : "d" (addr), "a" (val) );
}

void outw(uint16_t addr, uint16_t val)
{
    asm volatile ( "outw %%ax, %%dx" : : "d" (addr), "a" (val) );
}

void outl(uint16_t addr, uint32_t val)
{
    asm volatile ( "outl %%eax, %%dx" : : "d" (addr), "a" (val) );
}

uint8_t inb(uint16_t addr)
{
    uint8_t val;
    asm volatile ( "inb %%dx,%%al" : "=a" (val) : "d" (addr) );
    return val;
}

uint16_t inw(uint16_t addr)
{
    uint16_t val;
    asm volatile ( "inw %%dx,%%ax" : "=a" (val) : "d" (addr) );
    return val;
}

uint32_t inl(uint16_t addr)
{
    uint32_t val;
    asm volatile ( "inl %%dx,%%eax" : "=a" (val) : "d" (addr) );
    return val;
}

uint8_t cmos_inb(uint8_t idx)
{
    outb(0x70, idx);
    return inb(0x71);
}

void cmos_outb(uint8_t idx, uint8_t val)
{
    outb(0x70, idx);
    outb(0x71, val);
}

char *itoa(char *a, unsigned int i)
{
    unsigned int _i = i, x = 0;

    do {
        x++;
        _i /= 10;
    } while ( _i != 0 );

    a += x;
    *a-- = '\0';

    do {
        *a-- = (i % 10) + '0';
        i /= 10;
    } while ( i != 0 );

    return a + 1;
}

int strcmp(const char *cs, const char *ct)
{
    signed char res;

    while ( ((res = *cs - *ct++) == 0) && (*cs++ != '\0') )
        continue;

    return res;
}

int strncmp(const char *s1, const char *s2, uint32_t n)
{
    uint32_t ctr;
    for (ctr = 0; ctr < n; ctr++)
        if (s1[ctr] != s2[ctr])
            return (int)(s1[ctr] - s2[ctr]);
    return 0;
}

void *memcpy(void *dest, const void *src, unsigned n)
{
    int t0, t1, t2;

    asm volatile (
        "cld\n"
        "rep; movsl\n"
        "testb $2,%b4\n"
        "je 1f\n"
        "movsw\n"
        "1: testb $1,%b4\n"
        "je 2f\n"
        "movsb\n"
        "2:"
        : "=&c" (t0), "=&D" (t1), "=&S" (t2)
        : "0" (n/4), "q" (n), "1" ((long) dest), "2" ((long) src)
        : "memory" );
    return dest;
}

void *memmove(void *dest, const void *src, unsigned n)
{
    if ( (unsigned long)dest > (unsigned long)src )
        while ( n-- != 0 )
            ((char *)dest)[n] = ((char *)src)[n];
    else
        memcpy(dest, src, n);
    return dest;
}

char *
strcpy(char *dest, const char *src)
{
    char *p = dest;
    while ( *src )
        *p++ = *src++;
    *p = 0;
    return dest;
}

char *
strncpy(char *dest, const char *src, unsigned n)
{
    int i = 0;
    char *p = dest;

    /* write non-NUL characters from src into dest until we run
       out of room in dest or encounter a NUL in src */
    while ( (i < n) && *src )
    {
        *p++ = *src++;
        i++;
    }

    /* pad remaining bytes of dest with NUL bytes */
    while ( i < n )
    {
        *p++ = 0;
        i++;
    }

    return dest;
}

unsigned
strlen(const char *s)
{
    int i = 0;
    while ( *s++ )
        i++;
    return i;
}

static inline int __digit(char c, int base)
{
    int d = -1;

    if ( (c >= '0') && (c <= '9') )
        d = c - '0';

    if ( (c >= 'A') && (c <= 'Z') )
        d = c - 'A' + 10;

    if ( (c >= 'a') && (c <= 'z') )
        d = c - 'a' + 10;

    if (d >= base)
        d = -1;

    return d;
}

long long
strtoll(const char *s, char **end, int base)
{
    long long v = 0;
    int sign = 1;

    while ( (*s != '\0') && isspace(*s) )
        s++;

    if ( *s == '\0' ) goto out;

    if ( *s == '-' ) {
        sign = -1;
        s++;
    } else {
        if ( *s == '+' )
            s++;
    }

    if ( *s == '\0' ) goto out;

    if ( *s == '0' ) {
        s++;
        if ( *s == '\0' ) goto out;

        if ( *s == 'x' ) {
            if ( base != 0 && base != 16) goto out;
            base = 16;
            s++;
        } else {
            if ( base != 0 && base != 8) goto out;
            base = 8;
        }
    } else {
        if (base != 0 && base != 10) goto out;
        base = 10;
    }

    while ( *s != '\0' ) {
        int d = __digit(*s, base);

        if ( d < 0 ) goto out;

        v = (v * base) + d;
        s++;
    }

out:
    if (end) *end = (char *)s;

    return sign * v;
}

void *
memset(void *s, int c, unsigned n)
{
    uint8_t b = (uint8_t) c;
    uint8_t *p = (uint8_t *)s;
    int i;
    for ( i = 0; i < n; i++ )
        *p++ = b;
    return s;
}

int
memcmp(const void *s1, const void *s2, unsigned n)
{
    unsigned i;
    uint8_t *p1 = (uint8_t *) s1;
    uint8_t *p2 = (uint8_t *) s2;

    for ( i = 0; i < n; i++ )
    {
        if ( p1[i] < p2[i] )
            return -1;
        else if ( p1[i] > p2[i] )
            return 1;
    }

    return 0;
}

void
cpuid(uint32_t idx, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    asm volatile (
        "cpuid"
        : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
        : "0" (idx) );
}

static const char hex_digits[] = "0123456789abcdef";

/* Write a two-character hex representation of 'byte' to digits[].
   Pre-condition: sizeof(digits) >= 2 */
void
byte_to_hex(char *digits, uint8_t byte)
{
    digits[0] = hex_digits[byte >> 4];
    digits[1] = hex_digits[byte & 0x0f];
}

/* Convert an array of 16 unsigned bytes to a DCE/OSF formatted UUID
   string.

   Pre-condition: sizeof(dest) >= 37 */
void
uuid_to_string(char *dest, uint8_t *uuid)
{
    int i = 0;
    char *p = dest;

    for ( i = 0; i < 4; i++ )
    {
        byte_to_hex(p, uuid[i]);
        p += 2;
    }
    *p++ = '-';
    for ( i = 4; i < 6; i++ )
    {
        byte_to_hex(p, uuid[i]);
        p += 2;
    }
    *p++ = '-';
    for ( i = 6; i < 8; i++ )
    {
        byte_to_hex(p, uuid[i]);
        p += 2;
    }
    *p++ = '-';
    for ( i = 8; i < 10; i++ )
    {
        byte_to_hex(p, uuid[i]);
        p += 2;
    }
    *p++ = '-';
    for ( i = 10; i < 16; i++ )
    {
        byte_to_hex(p, uuid[i]);
        p += 2;
    }
    *p = '\0';
}

int get_mem_mapping_layout(struct e820entry entries[], uint32_t *max_entries)
{
    int rc;
    struct xen_memory_map memmap = {
        .nr_entries = *max_entries
    };

    set_xen_guest_handle(memmap.buffer, entries);

    rc = hypercall_memory_op(XENMEM_memory_map, &memmap);
    *max_entries = memmap.nr_entries;

    return rc;
}

void mem_hole_populate_ram(xen_pfn_t mfn, uint32_t nr_mfns)
{
    static int over_allocated;
    struct xen_add_to_physmap xatp;
    struct xen_memory_reservation xmr;

    for ( ; nr_mfns-- != 0; mfn++ )
    {
        /* Try to allocate a brand new page in the reserved area. */
        if ( !over_allocated )
        {
            xmr.domid = DOMID_SELF;
            xmr.mem_flags = 0;
            xmr.extent_order = 0;
            xmr.nr_extents = 1;
            set_xen_guest_handle(xmr.extent_start, &mfn);
            if ( hypercall_memory_op(XENMEM_populate_physmap, &xmr) == 1 )
                continue;
            over_allocated = 1;
        }

        /* Otherwise, relocate a page from the ordinary RAM map. */
        if ( hvm_info->high_mem_pgend )
        {
            xatp.idx = --hvm_info->high_mem_pgend;
            if ( xatp.idx == (1ull << (32 - PAGE_SHIFT)) )
                hvm_info->high_mem_pgend = 0;
        }
        else
        {
            xatp.idx = --hvm_info->low_mem_pgend;
        }
        xatp.domid = DOMID_SELF;
        xatp.space = XENMAPSPACE_gmfn;
        xatp.gpfn  = mfn;
        if ( hypercall_memory_op(XENMEM_add_to_physmap, &xatp) != 0 )
            BUG();
    }

    /* Sync memory map[]. */
    adjust_memory_map();
}

static uint32_t alloc_up = RESERVED_MEMORY_DYNAMIC_START - 1;
static uint32_t alloc_down = RESERVED_MEMORY_DYNAMIC_END;

xen_pfn_t mem_hole_alloc(uint32_t nr_mfns)
{
    alloc_down -= nr_mfns << PAGE_SHIFT;
    BUG_ON(alloc_up >= alloc_down);
    return alloc_down >> PAGE_SHIFT;
}

void *mem_alloc(uint32_t size, uint32_t align)
{
    uint32_t s, e;

    /* Align to at least 16 bytes. */
    if ( align < 16 )
        align = 16;

    s = (alloc_up + align) & ~(align - 1);
    e = s + size - 1;

    BUG_ON((e < s) || (e >= alloc_down));

    while ( (alloc_up >> PAGE_SHIFT) != (e >> PAGE_SHIFT) )
    {
        alloc_up += PAGE_SIZE;
        mem_hole_populate_ram(alloc_up >> PAGE_SHIFT, 1);
    }

    alloc_up = e;

    return (void *)(unsigned long)s;
}

void *scratch_alloc(uint32_t size, uint32_t align)
{
    uint32_t s, e;

    /* Align to at least 16 bytes. */
    if ( align < 16 )
        align = 16;

    s = (scratch_start + align - 1) & ~(align - 1);
    e = s + size - 1;

    BUG_ON(e < s);

    scratch_start = e;

    return (void *)(unsigned long)s;
}

uint32_t ioapic_read(uint32_t reg)
{
    *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x00) = reg;
    return *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x10);
}

void ioapic_write(uint32_t reg, uint32_t val)
{
    *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x00) = reg;
    *(volatile uint32_t *)(IOAPIC_BASE_ADDRESS + 0x10) = val;
}

uint32_t lapic_read(uint32_t reg)
{
    return *(volatile uint32_t *)(LAPIC_BASE_ADDRESS + reg);
}

void lapic_write(uint32_t reg, uint32_t val)
{
    *(volatile uint32_t *)(LAPIC_BASE_ADDRESS + reg) = val;
}

#define PCI_CONF1_ADDRESS(bus, devfn, reg) \
    (0x80000000 | (bus << 16) | (devfn << 8) | (reg & ~3))

uint32_t pci_read(uint32_t devfn, uint32_t reg, uint32_t len)
{
    outl(0xcf8, PCI_CONF1_ADDRESS(0, devfn, reg));

    switch ( len )
    {
    case 1: return inb(0xcfc + (reg & 3));
    case 2: return inw(0xcfc + (reg & 2));
    }

    return inl(0xcfc);
}

void pci_write(uint32_t devfn, uint32_t reg, uint32_t len, uint32_t val)
{
    outl(0xcf8, PCI_CONF1_ADDRESS(0, devfn, reg));

    switch ( len )
    {
    case 1: outb(0xcfc + (reg & 3), val); break;
    case 2: outw(0xcfc + (reg & 2), val); break;
    case 4: outl(0xcfc,             val); break;
    }
}

static char *printnum(char *p, unsigned long num, unsigned base)
{
    unsigned long n;

    if ( (n = num/base) > 0 )
        p = printnum(p, n, base);
    *p++ = hex_digits[num % base];
    *p = '\0';
    return p;
}

static void _doprint(void (*emit)(void *, char), void *arg, const char *fmt, va_list ap)
{
    char *str, c;
    int lflag, zflag, nflag;
    char buffer[17];
    unsigned long value;
    int i, slen, pad;

    for ( ; *fmt != '\0'; fmt++ )
    {
        if ( *fmt != '%' )
        {
            emit(arg, *fmt);
            continue;
        }

        pad = zflag = nflag = lflag = 0;
        c = *++fmt;
        if ( (c == '-') || isdigit(c) )
        {
            if ( c == '-' )
            {
                nflag = 1;
                c = *++fmt;
            }
            zflag = c == '0';
            for ( pad = 0; isdigit(c); c = *++fmt )
                pad = (pad * 10) + c - '0';
        }
        if ( c == 'l' ) /* long extension */
        {
            lflag = 1;
            c = *++fmt;
        }
        if ( (c == 'd') || (c == 'u') || (c == 'o') ||
             (c == 'x') || (c == 'X') )
        {
            if ( lflag )
            {
                value = va_arg(ap, unsigned long);
                if ( (c == 'd') && ((long)value < 0) )
                {
                    value = -value;
                    emit(arg, '-');
                }
            }
            else
            {
                value = va_arg(ap, unsigned int);
                if ( (c == 'd') && ((int)value < 0) )
                {
                    value = -(int)value;
                    emit(arg, '-');
                }
            }
            str = buffer;
            printnum(str, value,
                     c == 'o' ? 8 : ((c == 'x') || (c == 'X') ? 16 : 10));
            slen = strlen(str);
            for ( i = pad - slen; i > 0; i-- )
                emit(arg, zflag ? '0' : ' ');
            while ( *str )
            {
                char ch = *str++;
                if ( (ch >= 'a') && (c == 'X') )
                    ch += 'A'-'a';
                emit(arg, ch);
            }
        }
        else if ( c == 's' )
        {
            str = va_arg(ap, char *);
            slen = strlen(str);
            if ( nflag == 0 )
                for ( i = pad - slen; i > 0; i-- )
                    emit(arg, ' ');
            while ( *str )
                emit(arg, *str++);
            if ( nflag )
                for ( i = pad - slen; i > 0; i-- )
                    emit(arg, ' ');
        }
        else if ( c == 'c' )
        {
            emit(arg, va_arg(ap, int));
        }
        else
        {
            emit(arg, *fmt);
        }
    }
}

static void putchar(char c)
{
    outb(0xe9, c);
}

static void __put(void *arg, char c)
{
    putchar(c);
}

int printf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _doprint(__put, NULL, fmt, ap);
    va_end(ap);

    return 0;
}

int vprintf(const char *fmt, va_list ap)
{
    _doprint(__put, NULL, fmt, ap);
    return 0;
}

struct __copy_context {
    char *ptr;
    size_t emitted;
    size_t remaining;
};

static void __copy(void *arg, char c)
{
    struct __copy_context *ctxt = arg;

    ctxt->emitted++;

    if (ctxt->remaining == 0)
        return;
    
    *(ctxt->ptr++) = c;
    --ctxt->remaining;
}

int snprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list ap;
    struct __copy_context ctxt;

    ctxt.ptr = buf;
    ctxt.emitted = 0;
    ctxt.remaining = size;

    va_start(ap, fmt);
    _doprint(__copy, &ctxt, fmt, ap);
    va_end(ap);

    if (ctxt.remaining != 0)
        *ctxt.ptr = '\0';

    return ctxt.emitted;
}

static void __attribute__((noreturn)) crash(void)
{
    struct sched_shutdown shutdown = { .reason = SHUTDOWN_crash };
    printf("*** HVMLoader crashed.\n");
    hypercall_sched_op(SCHEDOP_shutdown, &shutdown);
    printf("*** Failed to crash. Halting.\n");
    for ( ; ; )
        asm volatile ( "hlt" );
}

void __assert_failed(char *assertion, char *file, int line)
{
    printf("*** HVMLoader assertion '%s' failed at %s:%d\n",
           assertion, file, line);
    crash();
}

void __bug(char *file, int line)
{
    printf("*** HVMLoader bug at %s:%d\n", file, line);
    crash();
}

static void validate_hvm_info(struct hvm_info_table *t)
{
    uint8_t *ptr = (uint8_t *)t;
    uint8_t sum = 0;
    int i;

    if ( strncmp(t->signature, "HVM INFO", 8) )
    {
        printf("Bad hvm info signature\n");
        BUG();
    }

    if ( t->length < sizeof(struct hvm_info_table) )
    {
        printf("Bad hvm info length\n");
        BUG();
    }

    for ( i = 0; i < t->length; i++ )
        sum += ptr[i];

    if ( sum != 0 )
    {
        printf("Bad hvm info checksum\n");
        BUG();
    }
}

struct hvm_info_table *get_hvm_info_table(void)
{
    static struct hvm_info_table *table;
    struct hvm_info_table *t;

    if ( table != NULL )
        return table;

    t = (struct hvm_info_table *)HVM_INFO_PADDR;

    validate_hvm_info(t);

    table = t;

    return table;
}

struct shared_info *get_shared_info(void) 
{
    static struct shared_info *shared_info = NULL;
    struct xen_add_to_physmap xatp;

    if ( shared_info != NULL )
        return shared_info;

    xatp.domid = DOMID_SELF;
    xatp.space = XENMAPSPACE_shared_info;
    xatp.idx   = 0;
    xatp.gpfn  = mem_hole_alloc(1);
    shared_info = (struct shared_info *)(xatp.gpfn << PAGE_SHIFT);
    if ( hypercall_memory_op(XENMEM_add_to_physmap, &xatp) != 0 )
        BUG();

    return shared_info;
}

uint16_t get_cpu_mhz(void)
{
    struct shared_info *shared_info = get_shared_info();
    struct vcpu_time_info *info = &shared_info->vcpu_info[0].time;
    uint64_t cpu_khz;
    uint32_t tsc_to_nsec_mul, version;
    int8_t tsc_shift;

    static uint16_t cpu_mhz;
    if ( cpu_mhz != 0 )
        return cpu_mhz;

    /* Get a consistent snapshot of scale factor (multiplier and shift). */
    do {
        version = info->version;
        rmb();
        tsc_to_nsec_mul = info->tsc_to_system_mul;
        tsc_shift       = info->tsc_shift;
        rmb();
    } while ((version & 1) | (version ^ info->version));

    /* Compute CPU speed in kHz. */
    cpu_khz = 1000000ull << 32;
    do_div(cpu_khz, tsc_to_nsec_mul);
    if ( tsc_shift < 0 )
        cpu_khz = cpu_khz << -tsc_shift;
    else
        cpu_khz = cpu_khz >> tsc_shift;

    cpu_mhz = (uint16_t)(((uint32_t)cpu_khz + 500) / 1000);
    return cpu_mhz;
}

int uart_exists(uint16_t uart_base)
{
    uint16_t ier = uart_base + 1;
    uint8_t a, b, c;

    a = inb(ier);
    outb(ier, 0);
    b = inb(ier);
    outb(ier, 0xf);
    c = inb(ier);
    outb(ier, a);

    return ((b == 0) && (c == 0xf));
}

int lpt_exists(uint16_t lpt_base)
{
    /* Idea taken from linux-2.6.31.5:parport_pc.c */
    uint16_t control = lpt_base + 2;
    outb(control, 0xc);
    return ((inb(control) & 0xf) == 0xc);
}

int hpet_exists(unsigned long hpet_base)
{
    uint32_t hpet_id = *(uint32_t *)hpet_base;
    return ((hpet_id >> 16) == 0x8086);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
