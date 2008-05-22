/*
 * QEMU PC System Emulator
 * 
 * Copyright (c) 2003-2004 Fabrice Bellard
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "vl.h"

/* output Bochs bios info messages */
//#define DEBUG_BIOS

#define BIOS_FILENAME "bios.bin"
#define VGABIOS_FILENAME "vgabios.bin"
#define VGABIOS_CIRRUS_FILENAME "vgabios-cirrus.bin"
#define LINUX_BOOT_FILENAME "linux_boot.bin"

/* Leave a chunk of memory at the top of RAM for the BIOS ACPI tables.  */
#define ACPI_DATA_SIZE        0x10000

static fdctrl_t *floppy_controller;
static RTCState *rtc_state;
#ifndef CONFIG_DM
static PITState *pit;
#endif /* !CONFIG_DM */
#ifndef CONFIG_DM
static IOAPICState *ioapic;
#endif /* !CONFIG_DM */
static PCIDevice *i440fx_state;

static void ioport80_write(void *opaque, uint32_t addr, uint32_t data)
{
}

/* MSDOS compatibility mode FPU exception support */
/* XXX: add IGNNE support */
void cpu_set_ferr(CPUX86State *s)
{
    pic_set_irq(13, 1);
}

static void ioportF0_write(void *opaque, uint32_t addr, uint32_t data)
{
    pic_set_irq(13, 0);
}

/* TSC handling */
uint64_t cpu_get_tsc(CPUX86State *env)
{
    /* Note: when using kqemu, it is more logical to return the host TSC
       because kqemu does not trap the RDTSC instruction for
       performance reasons */
#if USE_KQEMU
    if (env->kqemu_enabled) {
        return cpu_get_real_ticks();
    } else 
#endif
    {
        return cpu_get_ticks();
    }
}

#ifndef CONFIG_DM
/* SMM support */
void cpu_smm_update(CPUState *env)
{
    if (i440fx_state && env == first_cpu)
        i440fx_set_smm(i440fx_state, (env->hflags >> HF_SMM_SHIFT) & 1);
}


/* IRQ handling */
int cpu_get_pic_interrupt(CPUState *env)
{
    int intno;

    intno = apic_get_interrupt(env);
    if (intno >= 0) {
        /* set irq request if a PIC irq is still pending */
        /* XXX: improve that */
        pic_update_irq(isa_pic); 
        return intno;
    }
    /* read the irq from the PIC */
    intno = pic_read_irq(isa_pic);
    return intno;
}
#endif /* CONFIG_DM */

static void pic_irq_request(void *opaque, int level)
{
    CPUState *env = opaque;
    if (level)
        cpu_interrupt(env, CPU_INTERRUPT_HARD);
    else
        cpu_reset_interrupt(env, CPU_INTERRUPT_HARD);
}

/* PC cmos mappings */

#define REG_EQUIPMENT_BYTE          0x14

static int cmos_get_fd_drive_type(int fd0)
{
    int val;

    switch (fd0) {
    case 0:
        /* 1.44 Mb 3"5 drive */
        val = 4;
        break;
    case 1:
        /* 2.88 Mb 3"5 drive */
        val = 5;
        break;
    case 2:
        /* 1.2 Mb 5"5 drive */
        val = 2;
        break;
    default:
        val = 0;
        break;
    }
    return val;
}

static void cmos_init_hd(int type_ofs, int info_ofs, BlockDriverState *hd) 
{
    RTCState *s = rtc_state;
    int cylinders, heads, sectors;
    bdrv_get_geometry_hint(hd, &cylinders, &heads, &sectors);
    rtc_set_memory(s, type_ofs, 47);
    rtc_set_memory(s, info_ofs, cylinders);
    rtc_set_memory(s, info_ofs + 1, cylinders >> 8);
    rtc_set_memory(s, info_ofs + 2, heads);
    rtc_set_memory(s, info_ofs + 3, 0xff);
    rtc_set_memory(s, info_ofs + 4, 0xff);
    rtc_set_memory(s, info_ofs + 5, 0xc0 | ((heads > 8) << 3));
    rtc_set_memory(s, info_ofs + 6, cylinders);
    rtc_set_memory(s, info_ofs + 7, cylinders >> 8);
    rtc_set_memory(s, info_ofs + 8, sectors);
}

static int get_bios_disk(char *boot_device, int index) {

    if (index < strlen(boot_device)) {
        switch (boot_device[index]) {
        case 'a':
            return 0x01;            /* floppy */
        case 'c':
            return 0x02;            /* hard drive */
        case 'd':
            return 0x03;            /* cdrom */
        case 'n':
            return 0x04;            /* network */
        }
    }
    return 0x00;                /* no device */
}

/* hd_table must contain 4 block drivers */
static void cmos_init(uint64_t ram_size, char *boot_device, BlockDriverState **hd_table)
{
    RTCState *s = rtc_state;
    int val;
    int fd0, fd1, nb;
    int i;

    /* various important CMOS locations needed by PC/Bochs bios */

    /* memory size */
    val = 640; /* base memory in K */
    rtc_set_memory(s, 0x15, val);
    rtc_set_memory(s, 0x16, val >> 8);

    val = (ram_size / 1024) - 1024;
    if (val > 65535)
        val = 65535;
    rtc_set_memory(s, 0x17, val);
    rtc_set_memory(s, 0x18, val >> 8);
    rtc_set_memory(s, 0x30, val);
    rtc_set_memory(s, 0x31, val >> 8);

    if (ram_size > (16 * 1024 * 1024))
        val = (ram_size / 65536) - ((16 * 1024 * 1024) / 65536);
    else
        val = 0;
    if (val > 65535)
        val = 65535;
    rtc_set_memory(s, 0x34, val);
    rtc_set_memory(s, 0x35, val >> 8);
    
    if (boot_device == NULL) {
        /* default to hd, then cd, then floppy. */
        boot_device = "cda";
    }
    rtc_set_memory(s, 0x3d, get_bios_disk(boot_device, 0) |
                   (get_bios_disk(boot_device, 1) << 4));
    rtc_set_memory(s, 0x38, (get_bios_disk(boot_device, 2) << 4) |
                   (!fd_bootchk ? 0x01 : 0x00));

    /* floppy type */

    fd0 = fdctrl_get_drive_type(floppy_controller, 0);
    fd1 = fdctrl_get_drive_type(floppy_controller, 1);

    val = (cmos_get_fd_drive_type(fd0) << 4) | cmos_get_fd_drive_type(fd1);
    rtc_set_memory(s, 0x10, val);
    
    val = 0;
    nb = 0;
    if (fd0 < 3)
        nb++;
    if (fd1 < 3)
        nb++;
    switch (nb) {
    case 0:
        break;
    case 1:
        val |= 0x01; /* 1 drive, ready for boot */
        break;
    case 2:
        val |= 0x41; /* 2 drives, ready for boot */
        break;
    }
    val |= 0x02; /* FPU is there */
    val |= 0x04; /* PS/2 mouse installed */
    rtc_set_memory(s, REG_EQUIPMENT_BYTE, val);

    /* hard drives */

    rtc_set_memory(s, 0x12, (hd_table[0] ? 0xf0 : 0) | (hd_table[1] ? 0x0f : 0));
    if (hd_table[0])
        cmos_init_hd(0x19, 0x1b, hd_table[0]);
    if (hd_table[1]) 
        cmos_init_hd(0x1a, 0x24, hd_table[1]);

    val = 0;
    for (i = 0; i < 4; i++) {
        if (hd_table[i]) {
            int cylinders, heads, sectors, translation;
            /* NOTE: bdrv_get_geometry_hint() returns the physical
                geometry.  It is always such that: 1 <= sects <= 63, 1
                <= heads <= 16, 1 <= cylinders <= 16383. The BIOS
                geometry can be different if a translation is done. */
            translation = bdrv_get_translation_hint(hd_table[i]);
            if (translation == BIOS_ATA_TRANSLATION_AUTO) {
                bdrv_get_geometry_hint(hd_table[i], &cylinders, &heads, &sectors);
                if (cylinders <= 1024 && heads <= 16 && sectors <= 63) {
                    /* No translation. */
                    translation = 0;
                } else {
                    /* LBA translation. */
                    translation = 1;
                }
            } else {
                translation--;
            }
            val |= translation << (i * 2);
        }
    }
    rtc_set_memory(s, 0x39, val);
}

void ioport_set_a20(int enable)
{
    /* XXX: send to all CPUs ? */
    cpu_x86_set_a20(first_cpu, enable);
}

int ioport_get_a20(void)
{
    return ((first_cpu->a20_mask >> 20) & 1);
}

static void ioport92_write(void *opaque, uint32_t addr, uint32_t val)
{
    ioport_set_a20((val >> 1) & 1);
    /* XXX: bit 0 is fast reset */
}

static uint32_t ioport92_read(void *opaque, uint32_t addr)
{
    return ioport_get_a20() << 1;
}

/***********************************************************/
/* Bochs BIOS debug ports */

void bochs_bios_write(void *opaque, uint32_t addr, uint32_t val)
{
    static const char shutdown_str[8] = "Shutdown";
    static int shutdown_index = 0;
    
    switch(addr) {
        /* Bochs BIOS messages */
    case 0x400:
    case 0x401:
        fprintf(stderr, "BIOS panic at rombios.c, line %d\n", val);
        exit(1);
    case 0x402:
    case 0x403:
#ifdef DEBUG_BIOS
        fprintf(stderr, "%c", val);
#endif
        break;
    case 0x8900:
        /* same as Bochs power off */
        if (val == shutdown_str[shutdown_index]) {
            shutdown_index++;
            if (shutdown_index == 8) {
                shutdown_index = 0;
                qemu_system_shutdown_request();
            }
        } else {
            shutdown_index = 0;
        }
        break;

        /* LGPL'ed VGA BIOS messages */
    case 0x501:
    case 0x502:
        fprintf(stderr, "VGA BIOS panic, line %d\n", val);
        exit(1);
    case 0x500:
    case 0x503:
#ifdef DEBUG_BIOS
        fprintf(stderr, "%c", val);
#endif
        break;
    }
}

void bochs_bios_init(void)
{
    register_ioport_write(0x400, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x401, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x402, 1, 1, bochs_bios_write, NULL);
    register_ioport_write(0x403, 1, 1, bochs_bios_write, NULL);
    register_ioport_write(0x8900, 1, 1, bochs_bios_write, NULL);

    register_ioport_write(0x501, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x502, 1, 2, bochs_bios_write, NULL);
    register_ioport_write(0x500, 1, 1, bochs_bios_write, NULL);
    register_ioport_write(0x503, 1, 1, bochs_bios_write, NULL);
}

#if defined(__i386__) || defined(__x86_64__)
/* Generate an initial boot sector which sets state and jump to
   a specified vector */
static void generate_bootsect(uint32_t gpr[8], uint16_t segs[6], uint16_t ip)
{
    uint8_t bootsect[512], *p;
    int i;

    if (bs_table[0] == NULL) {
        fprintf(stderr, "A disk image must be given for 'hda' when booting "
                "a Linux kernel\n");
        exit(1);
    }

    memset(bootsect, 0, sizeof(bootsect));

    /* Copy the MSDOS partition table if possible */
    bdrv_read(bs_table[0], 0, bootsect, 1);

    /* Make sure we have a partition signature */
    bootsect[510] = 0x55;
    bootsect[511] = 0xaa;

    /* Actual code */
    p = bootsect;
    *p++ = 0xfa;                /* CLI */
    *p++ = 0xfc;                /* CLD */

    for (i = 0; i < 6; i++) {
        if (i == 1)             /* Skip CS */
            continue;

        *p++ = 0xb8;            /* MOV AX,imm16 */
        *p++ = segs[i];
        *p++ = segs[i] >> 8;
        *p++ = 0x8e;            /* MOV <seg>,AX */
        *p++ = 0xc0 + (i << 3);
    }

    for (i = 0; i < 8; i++) {
        *p++ = 0x66;            /* 32-bit operand size */
        *p++ = 0xb8 + i;        /* MOV <reg>,imm32 */
        *p++ = gpr[i];
        *p++ = gpr[i] >> 8;
        *p++ = gpr[i] >> 16;
        *p++ = gpr[i] >> 24;
    }

    *p++ = 0xea;                /* JMP FAR */
    *p++ = ip;                  /* IP */
    *p++ = ip >> 8;
    *p++ = segs[1];             /* CS */
    *p++ = segs[1] >> 8;

    bdrv_set_boot_sector(bs_table[0], bootsect, sizeof(bootsect));
}

/*
 * Evil helper for non-relocatable kernels
 *
 * So it works out like this:
 *
 *  0x100000  - Xen HVM firmware lives here. Kernel wants to boot here
 *
 * You can't both live there and HVM firmware is needed first, thus
 * our plan is
 *
 *  0x200000              - kernel is loaded here by QEMU
 *  0x200000+kernel_size  - helper code is put here by QEMU
 *
 * code32_switch in kernel header is set to point at out helper
 * code at 0x200000+kernel_size
 *
 * Our helper basically does memmove(0x100000,0x200000,kernel_size)
 * and then jmps to  0x1000000.
 *
 * So we've overwritten the HVM firmware (which was no longer
 * needed) and the non-relocatable kernel can happily boot
 * at its usual address.
 *
 * Simple, eh ?
 *
 * Well the assembler needed to do this is fairly short:
 *
 *  # Load segments
 *    cld                         
 *    cli                         
 *    movl $0x18,%eax
 *    mov %ax,%ds                 
 *    mov %ax,%es                 
 *    mov %ax,%fs                 
 *    mov %ax,%gs                 
 *    mov %ax,%ss                 
 *
 *  # Move the kernel into position
 *    xor    %edx,%edx            
 *_doloop:                        
 *    movzbl 0x600000(%edx),%eax  
 *    mov    %al,0x100000(%edx)   
 *    add    $0x1,%edx            
 *    cmp    $0x500000,%edx       
 *    jne    _doloop              
 *
 *  # start kernel
 *    xorl %ebx,%ebx              
 *    mov    $0x100000,%ecx       
 *    jmp    *%ecx                
 *
 */
static void setup_relocator(target_phys_addr_t addr, target_phys_addr_t src, target_phys_addr_t dst, size_t len)
{
  /* Now this assembler corresponds to follow machine code, with our args from QEMU spliced in :-) */
  unsigned char buf[] = {
    /* Load segments */
    0xfc,                         /* cld               */
    0xfa,                         /* cli               */ 
    0xb8, 0x18, 0x00, 0x00, 0x00, /* mov    $0x18,%eax */
    0x8e, 0xd8,                   /* mov    %eax,%ds   */
    0x8e, 0xc0,                   /* mov    %eax,%es   */
    0x8e, 0xe0,                   /* mov    %eax,%fs   */
    0x8e, 0xe8,                   /* mov    %eax,%gs   */
    0x8e, 0xd0,                   /* mov    %eax,%ss   */
    0x31, 0xd2,                   /* xor    %edx,%edx  */
  
    /* Move the kernel into position */
    0x0f, 0xb6, 0x82, (src&0xff), ((src>>8)&0xff), ((src>>16)&0xff), ((src>>24)&0xff), /*   movzbl $src(%edx),%eax */
    0x88, 0x82, (dst&0xff), ((dst>>8)&0xff), ((dst>>16)&0xff), ((dst>>24)&0xff),       /*   mov    %al,$dst(%edx)  */
    0x83, 0xc2, 0x01,                                                                  /*   add    $0x1,%edx       */
    0x81, 0xfa, (len&0xff), ((len>>8)&0xff), ((len>>16)&0xff), ((len>>24)&0xff),       /*   cmp    $len,%edx       */
    0x75, 0xe8,                                                                        /*   jne    13 <_doloop>    */

    /* Start kernel */
    0x31, 0xdb,                                                                        /*   xor    %ebx,%ebx       */
    0xb9, (dst&0xff), ((dst>>8)&0xff), ((dst>>16)&0xff), ((dst>>24)&0xff),             /*   mov    $dst,%ecx  */
    0xff, 0xe1,                                                                        /*   jmp    *%ecx           */
  };
  cpu_physical_memory_rw(addr, buf, sizeof(buf), 1);
  fprintf(stderr, "qemu: helper at 0x%x of size %d bytes, to move kernel of %d bytes from 0x%x to 0x%x\n",
	  (int)addr, (int)sizeof(buf), (int)len, (int)src, (int)dst);
}


static long get_file_size(FILE *f)
{
    long where, size;

    /* XXX: on Unix systems, using fstat() probably makes more sense */

    where = ftell(f);
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, where, SEEK_SET);

    return size;
}

static int fread2guest(target_phys_addr_t dst_addr, size_t nbytes, FILE *f)
{
    size_t offset = 0;
    while (nbytes) {
        uint8_t buf[4096];
	size_t count = nbytes > sizeof(buf) ? sizeof(buf) : nbytes;
	if (fread(buf, 1, count, f) != count)
	    return -1;

	cpu_physical_memory_rw(dst_addr+offset, buf, count, 1);
	offset += count;
	nbytes -= count;
    }
    return 0;
}

static void load_linux(const char *kernel_filename,
                       const char *initrd_filename,
                       const char *kernel_cmdline)
{
    uint16_t protocol;
    uint32_t gpr[8];
    uint16_t seg[6];
    uint16_t real_seg;
    int setup_size, kernel_size, initrd_size, cmdline_size;
    uint32_t initrd_max;
    uint8_t header[1024];
    target_phys_addr_t real_addr, reloc_prot_addr, prot_addr, cmdline_addr, initrd_addr;
    size_t ncmdline;
    FILE *f, *fi;

    /* Align to 16 bytes as a paranoia measure */
    cmdline_size = (strlen(kernel_cmdline)+16) & ~15;

    /* load the kernel header */
    f = fopen(kernel_filename, "rb");
    if (!f || !(kernel_size = get_file_size(f)) ||
        fread(header, 1, 1024, f) != 1024) {
        fprintf(stderr, "qemu: could not load kernel '%s'\n",
                kernel_filename);
        exit(1);
    }

    /* kernel protocol version */
    fprintf(stderr, "header magic: %#x\n", ldl_p(header+0x202));
    if (ldl_p(header+0x202) == 0x53726448)
        protocol = lduw_p(header+0x206);
    else
        protocol = 0;
    fprintf(stderr, "header protocol: %x\n", protocol);
    if (protocol < 0x200 || !(header[0x211] & 0x01)) {
        /* Low kernel */
        real_addr    = 0x90000;
        cmdline_addr = 0x9a000 - cmdline_size;
        prot_addr    = 0x10000;
	reloc_prot_addr = prot_addr;
    } else if (protocol < 0x202) {
        /* High but ancient kernel */
        real_addr    = 0x90000;
        cmdline_addr = 0x9a000 - cmdline_size;
        prot_addr    = 0x100000;
	reloc_prot_addr = 0x200000;
    } else {
        /* High and recent kernel */
        real_addr    = 0x10000;
        cmdline_addr = 0x20000;
        prot_addr    = 0x100000;
	reloc_prot_addr = 0x200000;
    }

    fprintf(stderr,
            "qemu: real_addr     = %#zx\n"
            "qemu: cmdline_addr  = %#zx\n"
            "qemu: prot_addr     = %#zx\n",
            real_addr,
            cmdline_addr,
            prot_addr);

    /* highest address for loading the initrd */
    if (protocol >= 0x203)
        initrd_max = ldl_p(header+0x22c);
    else
        initrd_max = 0x37ffffff;

    if (initrd_max >= ram_size-ACPI_DATA_SIZE)
        initrd_max = ram_size-ACPI_DATA_SIZE-1;


    /* kernel command line */
    ncmdline = strlen(kernel_cmdline);
    if (ncmdline > 4095) {
        ncmdline = 4095;
	((uint8_t*)kernel_cmdline)[4095] = '\0';
    }
    fprintf(stderr, "qemu: kernel_cmdline: %#zx ('%s')\n", ncmdline, kernel_cmdline);
    cpu_physical_memory_rw(cmdline_addr, (uint8_t*)kernel_cmdline, ncmdline+1, 1);

    if (protocol >= 0x202) {
        stl_p(header+0x228, cmdline_addr);
    } else {
        stw_p(header+0x20, 0xA33F);
        stw_p(header+0x22, cmdline_addr-real_addr);
    }

    /* loader type */
    /* High nybble = B reserved for Qemu; low nybble is revision number.
       If this code is substantially changed, you may want to consider
       incrementing the revision. */
    if (protocol >= 0x200)
        header[0x210] = 0xB0;

    /* heap */
    if (protocol >= 0x201) {
        header[0x211] |= 0x80;  /* CAN_USE_HEAP */
        stw_p(header+0x224, cmdline_addr-real_addr-0x200);
    }

    /* load initrd */
    if (initrd_filename) {
        if (protocol < 0x200) {
            fprintf(stderr, "qemu: linux kernel too old to load a ram disk\n");
            exit(1);
        }

        fi = fopen(initrd_filename, "rb");
        if (!fi) {
            fprintf(stderr, "qemu: could not load initial ram disk '%s'\n",
                    initrd_filename);
            exit(1);
        }

        initrd_size = get_file_size(fi);
        initrd_addr = ((initrd_max-initrd_size) & ~4095);

        fprintf(stderr, "qemu: loading initrd (%#x bytes) at %#zx\n",
                initrd_size, initrd_addr);

	if (fread2guest(initrd_addr, initrd_size, fi) < 0) {
	    fprintf(stderr, "qemu: read error on initial ram disk '%s'\n",
		    initrd_filename);
	    exit(1);
	}
        fclose(fi);

        stl_p(header+0x218, initrd_addr);
        stl_p(header+0x21c, initrd_size);
    }


    setup_size = header[0x1f1];
    if (setup_size == 0)
        setup_size = 4;

    setup_size = (setup_size+1)*512;
    kernel_size -= setup_size;  /* Size of protected-mode code */

    /* Urgh, Xen's HVM firmware lives at 0x100000, but that's also the
     * address Linux wants to start life at prior to relocatable support
     */
    if (prot_addr != reloc_prot_addr) {
        if (protocol >= 0x205 && (header[0x234] & 1)) {
	    /* Relocatable automatically */
	    stl_p(header+0x214, reloc_prot_addr);
	    fprintf(stderr, "qemu: kernel is relocatable\n");
	} else {
	    /* Setup a helper which moves  kernel back to
	     * its expected addr after firmware has got out
	     * of the way. We put a helper at  reloc_prot_addr+kernel_size.
	     * It moves kernel from reloc_prot_addr to prot_addr and
	     * then jumps to prot_addr. Yes this is sick.
	     */
	    fprintf(stderr, "qemu: kernel is NOT relocatable\n");
	    stl_p(header+0x214, reloc_prot_addr + kernel_size);
	    setup_relocator(reloc_prot_addr + kernel_size, reloc_prot_addr, prot_addr, kernel_size);
	}
    }


    fprintf(stderr, "qemu: loading kernel real mode (%#x bytes) at %#zx\n",
	    setup_size-1024, real_addr);
    fprintf(stderr, "qemu: loading kernel protected mode (%#x bytes) at %#zx\n",
	    kernel_size, reloc_prot_addr);

    /* store the finalized header and load the rest of the kernel */
    cpu_physical_memory_rw(real_addr, header, 1024, 1);
    if (fread2guest(real_addr+1024, setup_size-1024, f) < 0 ||
        fread2guest(reloc_prot_addr, kernel_size, f) < 0) {
	fprintf(stderr, "qemu: loading kernel protected mode (%#x bytes) at %#zx\n",
		kernel_size, reloc_prot_addr);
	exit(1);
    }
    fclose(f);

    /* generate bootsector to set up the initial register state */
    real_seg = (real_addr) >> 4;
    seg[0] = seg[2] = seg[3] = seg[4] = seg[4] = real_seg;
    seg[1] = real_seg+0x20;     /* CS */
    memset(gpr, 0, sizeof gpr);
    gpr[4] = cmdline_addr-real_addr-16; /* SP (-16 is paranoia) */

    generate_bootsect(gpr, seg, 0);
}
#else /* __ia64__ */
static void load_linux(const char *kernel_filename,
                       const char *initrd_filename,
                       const char *kernel_cmdline)
{
    /* Direct Linux boot is unsupported. */
}
#endif

static void main_cpu_reset(void *opaque)
{
    CPUState *env = opaque;
    cpu_reset(env);
}

static const int ide_iobase[2] = { 0x1f0, 0x170 };
static const int ide_iobase2[2] = { 0x3f6, 0x376 };
static const int ide_irq[2] = { 14, 15 };

#define NE2000_NB_MAX 6

static int ne2000_io[NE2000_NB_MAX] = { 0x300, 0x320, 0x340, 0x360, 0x280, 0x380 };
static int ne2000_irq[NE2000_NB_MAX] = { 9, 10, 11, 3, 4, 5 };

static int serial_io[MAX_SERIAL_PORTS] = { 0x3f8, 0x2f8, 0x3e8, 0x2e8 };
static int serial_irq[MAX_SERIAL_PORTS] = { 4, 3, 4, 3 };

static int parallel_io[MAX_PARALLEL_PORTS] = { 0x378, 0x278, 0x3bc };
static int parallel_irq[MAX_PARALLEL_PORTS] = { 7, 7, 7 };

#ifdef HAS_AUDIO
static void audio_init (PCIBus *pci_bus)
{
    struct soundhw *c;
    int audio_enabled = 0;

    for (c = soundhw; !audio_enabled && c->name; ++c) {
        audio_enabled = c->enabled;
    }

    if (audio_enabled) {
        AudioState *s;

        s = AUD_init ();
        if (s) {
            for (c = soundhw; c->name; ++c) {
                if (c->enabled) {
                    if (c->isa) {
                        c->init.init_isa (s);
                    }
                    else {
                        if (pci_bus) {
                            c->init.init_pci (pci_bus, s);
                        }
                    }
                }
            }
        }
    }
}
#endif

static void pc_init_ne2k_isa(NICInfo *nd)
{
    static int nb_ne2k = 0;

    if (nb_ne2k == NE2000_NB_MAX)
        return;
    isa_ne2000_init(ne2000_io[nb_ne2k], ne2000_irq[nb_ne2k], nd);
    nb_ne2k++;
}

#define NOBIOS 1

/* PC hardware initialisation */
static void pc_init1(uint64_t ram_size, int vga_ram_size, char *boot_device,
                     DisplayState *ds, const char **fd_filename, int snapshot,
                     const char *kernel_filename, const char *kernel_cmdline,
                     const char *initrd_filename,
                     int pci_enabled, const char *direct_pci)
{
#ifndef NOBIOS
    char buf[1024];
    int ret, initrd_size;
#endif /* !NOBIOS */
    int linux_boot, i;
#ifndef NOBIOS
    unsigned long bios_offset, vga_bios_offset, option_rom_offset;
    int bios_size, isa_bios_size;
#endif /* !NOBIOS */
    PCIBus *pci_bus;
    int piix3_devfn = -1;
    CPUState *env;
    NICInfo *nd;
    int rc;

    linux_boot = (kernel_filename != NULL);

    /* init CPUs */
    for(i = 0; i < smp_cpus; i++) {
        env = cpu_init();
#ifndef CONFIG_DM
        if (i != 0)
            env->hflags |= HF_HALTED_MASK;
        if (smp_cpus > 1) {
            /* XXX: enable it in all cases */
            env->cpuid_features |= CPUID_APIC;
        }
#endif /* !CONFIG_DM */
        register_savevm("cpu", i, 4, cpu_save, cpu_load, env);
        qemu_register_reset(main_cpu_reset, env);
#ifndef CONFIG_DM
        if (pci_enabled) {
            apic_init(env);
        }
#endif /* !CONFIG_DM */
    }

    /* allocate RAM */
#ifndef CONFIG_DM		/* HVM domain owns memory */
    cpu_register_physical_memory(0, ram_size, 0);
#endif

#ifndef NOBIOS
    /* BIOS load */
    bios_offset = ram_size + vga_ram_size;
    vga_bios_offset = bios_offset + 256 * 1024;

    snprintf(buf, sizeof(buf), "%s/%s", bios_dir, BIOS_FILENAME);
    bios_size = get_image_size(buf);
    if (bios_size <= 0 || 
        (bios_size % 65536) != 0 ||
        bios_size > (256 * 1024)) {
        goto bios_error;
    }
    ret = load_image(buf, phys_ram_base + bios_offset);
    if (ret != bios_size) {
    bios_error:
        fprintf(stderr, "qemu: could not load PC bios '%s'\n", buf);
        exit(1);
    }

    /* VGA BIOS load */
    if (cirrus_vga_enabled) {
        snprintf(buf, sizeof(buf), "%s/%s", bios_dir, VGABIOS_CIRRUS_FILENAME);
    } else {
        snprintf(buf, sizeof(buf), "%s/%s", bios_dir, VGABIOS_FILENAME);
    }
    ret = load_image(buf, phys_ram_base + vga_bios_offset);
#endif /* !NOBIOS */
    
    /* setup basic memory access */
#ifndef CONFIG_DM		/* HVM domain owns memory */
    cpu_register_physical_memory(0xc0000, 0x10000, 
                                 vga_bios_offset | IO_MEM_ROM);
#endif

#ifndef NOBIOS
    /* map the last 128KB of the BIOS in ISA space */
    isa_bios_size = bios_size;
    if (isa_bios_size > (128 * 1024))
        isa_bios_size = 128 * 1024;
    cpu_register_physical_memory(0xd0000, (192 * 1024) - isa_bios_size, 
                                 IO_MEM_UNASSIGNED);
    cpu_register_physical_memory(0x100000 - isa_bios_size, 
                                 isa_bios_size, 
                                 (bios_offset + bios_size - isa_bios_size) | IO_MEM_ROM);

    option_rom_offset = 0;
    for (i = 0; i < nb_option_roms; i++) {
	int offset = bios_offset + bios_size + option_rom_offset;
	int size;

	size = load_image(option_rom[i], phys_ram_base + offset);
	if ((size + option_rom_offset) > 0x10000) {
	    fprintf(stderr, "Too many option ROMS\n");
	    exit(1);
	}
	cpu_register_physical_memory(0xd0000 + option_rom_offset,
				     size, offset | IO_MEM_ROM);
	option_rom_offset += size + 2047;
	option_rom_offset -= (option_rom_offset % 2048);
    }

    /* map all the bios at the top of memory */
    cpu_register_physical_memory((uint32_t)(-bios_size), 
                                 bios_size, bios_offset | IO_MEM_ROM);
#endif
    
    bochs_bios_init();

    if (linux_boot)
        load_linux(kernel_filename, initrd_filename, kernel_cmdline);

    if (pci_enabled) {
        pci_bus = i440fx_init(&i440fx_state);
        piix3_devfn = piix3_init(pci_bus, -1);
    } else {
        pci_bus = NULL;
    }

    /* init basic PC hardware */
    register_ioport_write(0x80, 1, 1, ioport80_write, NULL);

    register_ioport_write(0xf0, 1, 1, ioportF0_write, NULL);

    if (cirrus_vga_enabled) {
        if (pci_enabled) {
            pci_cirrus_vga_init(pci_bus, 
                                ds, NULL, ram_size, 
                                vga_ram_size);
        } else {
            isa_cirrus_vga_init(ds, NULL, ram_size, 
                                vga_ram_size);
        }
    } else {
        if (pci_enabled) {
            pci_vga_init(pci_bus, ds, NULL, ram_size, 
                         vga_ram_size, 0, 0);
        } else {
            isa_vga_init(ds, NULL, ram_size, 
                         vga_ram_size);
        }
    }

#ifdef CONFIG_PASSTHROUGH
    /* Pass-through Initialization
     * init libpci even direct_pci is null, as can hotplug a dev runtime
     */
    if ( pci_enabled )
    {
        rc = pt_init(pci_bus, direct_pci); 
        if ( rc < 0 )
        {
            fprintf(logfile, "Error: Initialization failed for pass-through devices\n");
            exit(1);
        }
    }
#endif

    rtc_state = rtc_init(0x70, 8);

    register_ioport_read(0x92, 1, 1, ioport92_read, NULL);
    register_ioport_write(0x92, 1, 1, ioport92_write, NULL);

#ifndef CONFIG_DM
    if (pci_enabled) {
        ioapic = ioapic_init();
    }
#endif /* !CONFIG_DM */
    isa_pic = pic_init(pic_irq_request, first_cpu);
#ifndef CONFIG_DM
    pit = pit_init(0x40, 0);
    pcspk_init(pit);
#endif /* !CONFIG_DM */
#ifndef CONFIG_DM
    if (pci_enabled) {
        pic_set_alt_irq_func(isa_pic, ioapic_set_irq, ioapic);
    }
#endif /* !CONFIG_DM */

    if (pci_enabled)
        pci_xen_platform_init(pci_bus);

    for(i = 0; i < MAX_SERIAL_PORTS; i++) {
        if (serial_hds[i]) {
            serial_init(&pic_set_irq_new, isa_pic,
                        serial_io[i], serial_irq[i], serial_hds[i]);
        }
    }

    for(i = 0; i < MAX_PARALLEL_PORTS; i++) {
        if (parallel_hds[i]) {
            parallel_init(parallel_io[i], parallel_irq[i], parallel_hds[i]);
        }
    }

    for(i = 0; i < nb_nics; i++) {
        nd = &nd_table[i];
        if (!nd->model) {
            if (pci_enabled) {
                nd->model = "ne2k_pci";
            } else {
                nd->model = "ne2k_isa";
            }
        }
        if (strcmp(nd->model, "ne2k_isa") == 0) {
            pc_init_ne2k_isa(nd);
        } else if (pci_enabled) {
            pci_nic_init(pci_bus, nd, -1);
        } else {
            fprintf(stderr, "qemu: Unsupported NIC: %s\n", nd->model);
            exit(1);
        }
    }

    if (pci_enabled) {
        pci_piix3_ide_init(pci_bus, bs_table, piix3_devfn + 1);
    } else {
        for(i = 0; i < 2; i++) {
            isa_ide_init(ide_iobase[i], ide_iobase2[i], ide_irq[i],
                         bs_table[2 * i], bs_table[2 * i + 1]);
        }
    }

#ifdef HAS_TPM
    if (has_tpm_device())
        tpm_tis_init(&pic_set_irq_new, isa_pic, 11);
#endif

    kbd_init();
    DMA_init(0);
#ifdef HAS_AUDIO
    audio_init(pci_enabled ? pci_bus : NULL);
#endif

    floppy_controller = fdctrl_init(6, 2, 0, 0x3f0, fd_table);

    cmos_init(ram_size, boot_device, bs_table);

    /* using PIIX4 acpi model */
    if (pci_enabled && acpi_enabled)
        pci_piix4_acpi_init(pci_bus, piix3_devfn + 2);

    if (pci_enabled && usb_enabled) {
        usb_uhci_init(pci_bus, piix3_devfn + (acpi_enabled ? 3 : 2));
    }

#ifndef CONFIG_DM
    if (pci_enabled && acpi_enabled) {
        uint8_t *eeprom_buf = qemu_mallocz(8 * 256); /* XXX: make this persistent */
        piix4_pm_init(pci_bus, piix3_devfn + 3);
        for (i = 0; i < 8; i++) {
            SMBusDevice *eeprom = smbus_eeprom_device_init(0x50 + i,
                eeprom_buf + (i * 256));
            piix4_smbus_register_device(eeprom, 0x50 + i);
        }
    }
    
    if (i440fx_state) {
        i440fx_init_memory_mappings(i440fx_state);
    }
#if 0
    /* ??? Need to figure out some way for the user to
       specify SCSI devices.  */
    if (pci_enabled) {
        void *scsi;
        BlockDriverState *bdrv;

        scsi = lsi_scsi_init(pci_bus, -1);
        bdrv = bdrv_new("scsidisk");
        bdrv_open(bdrv, "scsi_disk.img", 0);
        lsi_scsi_attach(scsi, bdrv, -1);
        bdrv = bdrv_new("scsicd");
        bdrv_open(bdrv, "scsi_cd.iso", 0);
        bdrv_set_type_hint(bdrv, BDRV_TYPE_CDROM);
        lsi_scsi_attach(scsi, bdrv, -1);
    }
#endif
#else
    if (pci_enabled) {
        void *scsi = NULL;
        for (i = 0; i < MAX_SCSI_DISKS ; i++) {
            if (!bs_table[i + MAX_DISKS])
                continue;
            if (!scsi)
                scsi = lsi_scsi_init(pci_bus, -1);
            lsi_scsi_attach(scsi, bs_table[i + MAX_DISKS], -1);
        }
    }
#endif /* !CONFIG_DM */
}

static void pc_init_pci(uint64_t ram_size, int vga_ram_size, char *boot_device,
                        DisplayState *ds, const char **fd_filename, 
                        int snapshot, 
                        const char *kernel_filename, 
                        const char *kernel_cmdline,
                        const char *initrd_filename,
                        const char *direct_pci)
{
    pc_init1(ram_size, vga_ram_size, boot_device,
             ds, fd_filename, snapshot,
             kernel_filename, kernel_cmdline,
             initrd_filename, 1,
             direct_pci);
}

static void pc_init_isa(uint64_t ram_size, int vga_ram_size, char *boot_device,
                        DisplayState *ds, const char **fd_filename, 
                        int snapshot, 
                        const char *kernel_filename, 
                        const char *kernel_cmdline,
                        const char *initrd_filename,
                        const char *unused)
{
    pc_init1(ram_size, vga_ram_size, boot_device,
             ds, fd_filename, snapshot,
             kernel_filename, kernel_cmdline,
             initrd_filename, 0, NULL);
}

/* set CMOS shutdown status register (index 0xF) as S3_resume(0xFE)
   BIOS will read it and start S3 resume at POST Entry*/
void cmos_set_s3_resume(void)
{
    if (rtc_state)
        rtc_set_memory(rtc_state, 0xF, 0xFE);
}

QEMUMachine pc_machine = {
    "pc",
    "Standard PC",
    pc_init_pci,
};

QEMUMachine isapc_machine = {
    "isapc",
    "ISA-only PC",
    pc_init_isa,
};
