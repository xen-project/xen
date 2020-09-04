/*
 * Mini-OS support for GRUB.
 *
 * Samuel Thibault <Samuel.Thibault@eu.citrix.com>, May 2008
 */
#include <sys/types.h>
#include <sys/time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>

#include <hypervisor.h>
#include <blkfront.h>
#include <netfront.h>
#include <fbfront.h>
#include <semaphore.h>

#include <osdep.h>
#include <shared.h>
#include <nic.h>
#include <etherboot.h>
#include <terminfo.h>
#include <term.h>

#include "mini-os.h"

extern const char *preset_menu;
char config_file[DEFAULT_FILE_BUFLEN] = "(hd0,0)/boot/grub/menu.lst";
unsigned long boot_drive = NETWORK_DRIVE;
unsigned long install_partition = 0xFFFFFF;

char version_string[] = VERSION;

/* Variables from asm.S */
int saved_entryno;

/*
 * Disk
 */

struct blkfront_dev **blk_dev;
int blk_nb;
static struct blkfront_info *blk_info;

static int vbdcmp(const void *_vbd1, const void *_vbd2) {
    char *vbd1 = *(char **)_vbd1;
    char *vbd2 = *(char **)_vbd2;
    int vbdn1 = atoi(vbd1);
    int vbdn2 = atoi(vbd2);
    return vbdn1 - vbdn2;
}

void init_disk (void)
{
    char **list;
    char *msg;
    int i;
    char *path;

    msg = xenbus_ls(XBT_NIL, "device/vbd", &list);
    if (msg) {
        printk("Error %s while reading list of disks\n", msg);
        free(msg);
        return;
    }
    blk_nb = 0;
    while (list[blk_nb])
        blk_nb++;
    blk_dev = malloc(blk_nb * sizeof(*blk_dev));
    blk_info = malloc(blk_nb * sizeof(*blk_info));

    qsort(list, blk_nb, sizeof(*list), vbdcmp);

    for (i = 0; i < blk_nb; i++) {
        printk("vbd %s is hd%d\n", list[i], i);
        asprintf(&path, "device/vbd/%s", list[i]);
        blk_dev[i] = init_blkfront(path, &blk_info[i]);
        free(path);
        free(list[i]);
    }
}

/* Return the geometry of DRIVE in GEOMETRY. If an error occurs, return
   non-zero, otherwise zero.  */
int get_diskinfo (int drive, struct geometry *geometry)
{
    int i;
    if (!(drive & 0x80))
        return -1;

    i = drive - 0x80;
    if (i >= blk_nb)
        return -1;

    /* Bogus geometry */
    geometry->cylinders = 65535;
    geometry->heads = 255;
    geometry->sectors = 63;

    geometry->total_sectors = blk_info[i].sectors;
    geometry->sector_size = blk_info[i].sector_size;
    geometry->flags = BIOSDISK_FLAG_LBA_EXTENSION;
    if (blk_info[i].info & VDISK_CDROM)
        geometry->flags |= BIOSDISK_FLAG_CDROM;
    return 0;
}

/* Read/write NSEC sectors starting from SECTOR in DRIVE disk with GEOMETRY
   from/into SEGMENT segment. If READ is BIOSDISK_READ, then read it,
   else if READ is BIOSDISK_WRITE, then write it. If an geometry error
   occurs, return BIOSDISK_ERROR_GEOMETRY, and if other error occurs, then
   return the error number. Otherwise, return 0.  */
int
biosdisk (int read, int drive, struct geometry *geometry,
          unsigned int sector, int nsec, int segment)
{
    void *addr = (void *) ((unsigned long)segment << 4);
    struct blkfront_aiocb aiocb;
    int i;

    if (!(drive & 0x80))
        return -1;

    i = drive - 0x80;
    if (i >= blk_nb)
        return -1;

    if (sector + nsec > geometry->total_sectors)
      return -1;

    aiocb.aio_dev = blk_dev[i];
    aiocb.aio_buf = addr;
    aiocb.aio_nbytes = (size_t)nsec * blk_info[i].sector_size;
    aiocb.aio_offset = (off_t)sector * blk_info[i].sector_size;
    aiocb.aio_cb = NULL;

    blkfront_io(&aiocb, read == BIOSDISK_WRITE);

    return 0;
}

static int
load_file(char *name, void **ptr, long *size)
{
    char *buf = NULL;
    int allocated = 1 * 1024 * 1024;
    int len, filled = 0;

    if (!grub_open (name))
        return -1;

    buf = malloc(allocated);

    errnum = 0;
    while (1) {
        len = grub_read (buf + filled, allocated - filled);
        if (! len) {
            if (!errnum)
                break;
            grub_close ();
            return -1;
        }
        filled += len;
        if (filled < allocated)
            break;
        allocated *= 2;
        buf = realloc(buf, allocated);
    }
    grub_close ();
    *ptr = buf;
    *size = filled;
    return 0;
}

void *kernel_image, *module_image;
long  kernel_size, module_size;
char *kernel_arg, *module_arg;
void *multiboot_next_module;
struct xen_multiboot_mod_list *multiboot_next_module_header;

kernel_t
load_image (char *kernel, char *arg, kernel_t suggested_type,
            unsigned long load_flags)
{
    arg = skip_to(0, arg);
    if (kernel_image)
        free(kernel_image);
    kernel_image = NULL;
    if (load_file (kernel, &kernel_image, &kernel_size))
        return KERNEL_TYPE_NONE;
    if (kernel_arg)
        free(kernel_arg);
    kernel_arg = strdup(arg);
    return KERNEL_TYPE_PV;
}

int
load_initrd (char *initrd)
{
    if (module_image)
        free(module_image);
    module_image = NULL;
    multiboot_next_module = NULL;
    multiboot_next_module_header = NULL;
    load_file (initrd, &module_image, &module_size);
    return ! errnum;
}

int
load_module (char *module, char *arg)
{
    void *new_module, *new_module_image;
    long new_module_size, rounded_new_module_size;

    if (load_file (module, &new_module, &new_module_size))
        return 0;
    if (strlen(arg) >= PAGE_SIZE) {
        /* Too big module command line */
        errnum = ERR_WONT_FIT;
        return 0;
    }
    rounded_new_module_size = (new_module_size + PAGE_SIZE - 1) & PAGE_MASK;

    if (module_image && !multiboot_next_module_header) {
        /* Initrd already loaded, drop it */
        free(module_image);
        if (module_arg)
            free(module_arg);
        module_image = NULL;
    }
    if (!module_image)
        /* Reserve one page for the header */
        multiboot_next_module = (void*) PAGE_SIZE;

    /* Allocate more room for the new module plus its arg */
    new_module_image = realloc(module_image,
            (multiboot_next_module - module_image) + rounded_new_module_size + PAGE_SIZE);

    /* Update pointers */
    multiboot_next_module += new_module_image - module_image;
    multiboot_next_module_header = (void*) multiboot_next_module_header + (new_module_image - module_image);
    module_image = new_module_image;

    if ((void*) (multiboot_next_module_header+1) - module_image > PAGE_SIZE) {
        /* Too many modules */
        errnum = ERR_WONT_FIT;
        return 0;
    }

    /* Copy module */
    memcpy(multiboot_next_module, new_module, new_module_size);
    multiboot_next_module_header->mod_start = multiboot_next_module - module_image;
    multiboot_next_module_header->mod_end = multiboot_next_module_header->mod_start + new_module_size - 1;
    multiboot_next_module += rounded_new_module_size;

    /* Copy cmdline */
    strcpy(multiboot_next_module, arg);
    multiboot_next_module_header->cmdline = multiboot_next_module - module_image;
    multiboot_next_module += PAGE_SIZE;

    /* Pad */
    multiboot_next_module_header->pad = 0;

    multiboot_next_module_header++;

    return 1;
}

void
pv_boot (void)
{
    unsigned long flags = 0;
    if (multiboot_next_module_header) {
        /* Termination entry */
        multiboot_next_module_header->mod_start = 0;
        /* Total size */
        module_size = multiboot_next_module - module_image;
        /* It's a multiboot module */
        flags |= SIF_MULTIBOOT_MOD;
    }
    kexec(kernel_image, kernel_size, module_image, module_size, kernel_arg, flags);
}

/*
 * Network
 */

struct netfront_dev *net_dev;

int
minios_probe (struct nic *nic)
{
    char *ip;

    if (net_dev)
        return 1;

    /* Clear the ARP table.  */
    grub_memset ((char *) arptable, 0,
                 MAX_ARP * sizeof (struct arptable_t));

    net_dev = init_netfront(NULL, (void*) -1, nic->node_addr, &ip);
    if (!net_dev)
        return 0;

    return 1;
}

/* reset adapter */
static void minios_reset(struct nic *nic)
{
    /* TODO? */
}

static void minios_disable(struct nic *nic)
{
}

/* Wait for a frame */
static int minios_poll(struct nic *nic)
{
    return !! (nic->packetlen = netfront_receive(net_dev, (void*) nic->packet, ETH_FRAME_LEN));
}

/* Transmit a frame */
struct frame {
        uint8_t dest[ETH_ALEN];
        uint8_t src[ETH_ALEN];
        uint16_t type;
        unsigned char data[];
};
static void minios_transmit (struct nic *nic, const char *d, unsigned int t,
                             unsigned int s, const char *p)
{
    struct frame *frame = alloca(sizeof(*frame) + s);

    memcpy(frame->dest, d, ETH_ALEN);
    memcpy(frame->src, nic->node_addr, ETH_ALEN);
    frame->type = htons(t);
    memcpy(frame->data, p, s);

    netfront_xmit(net_dev, (void*) frame, sizeof(*frame) + s);
}

static char packet[ETH_FRAME_LEN];

struct nic nic = {
    .reset = minios_reset,
    .poll = minios_poll,
    .transmit = minios_transmit,
    .disable = minios_disable,
    .flags = 0,
    .rom_info = NULL,
    .node_addr = arptable[ARP_CLIENT].node,
    .packet = packet,
    .packetlen = 0,
    .priv_data = NULL,
};

int
eth_probe (void)
{
    return minios_probe(&nic);
}

int
eth_poll (void)
{
    return minios_poll (&nic);
}

void
eth_disable (void)
{
    minios_disable (&nic);
}

void
eth_transmit (const char *d, unsigned int t,
              unsigned int s, const void *p)
{
    minios_transmit (&nic, d, t, s, p);
    if (t == IP)
        twiddle();
}

/*
 * Console
 */
void
serial_hw_put (int _c)
{
  char c = _c;
  console_print(NULL, &c, 1);
}

int
serial_hw_fetch (void)
{
    char key;

    if (!xencons_ring_avail(NULL))
        return -1;

    read(STDIN_FILENO, &key, 1);
    switch (key) {
    case 0x7f: key = '\b'; break;
    }
    return key;
}

/*
 * PVFB
 */
struct kbdfront_dev *kbd_dev;
struct fbfront_dev *fb_dev;
static union xenkbd_in_event ev;
static int has_ev;
int console_checkkey (void)
{
    if (has_ev)
        return 1;
    has_ev = kbdfront_receive(kbd_dev, &ev, 1);
    return has_ev;
}

/* static QWERTY layout, that's what most PC BIOSes do anyway */
static char linux2ascii[] = {
    [ 1 ] = 27,
    [ 2 ] = '1',
    [ 3 ] = '2',
    [ 4 ] = '3',
    [ 5 ] = '4',
    [ 6 ] = '5',
    [ 7 ] = '6',
    [ 8 ] = '7',
    [ 9 ] = '8',
    [ 10 ] = '9',
    [ 11 ] = '0',
    [ 12 ] = '-',
    [ 13 ] = '=',
    [ 14 ] = '\b',
    [ 15 ] = '\t',
    [ 16 ] = 'q',
    [ 17 ] = 'w',
    [ 18 ] = 'e',
    [ 19 ] = 'r',
    [ 20 ] = 't',
    [ 21 ] = 'y',
    [ 22 ] = 'u',
    [ 23 ] = 'i',
    [ 24 ] = 'o',
    [ 25 ] = 'p',
    [ 26 ] = '[',
    [ 27 ] = ']',
    [ 28 ] = '\n',

    [ 30 ] = 'a',
    [ 31 ] = 's',
    [ 32 ] = 'd',
    [ 33 ] = 'f',
    [ 34 ] = 'g',
    [ 35 ] = 'h',
    [ 36 ] = 'j',
    [ 37 ] = 'k',
    [ 38 ] = 'l',
    [ 39 ] = ';',
    [ 40 ] = '\'',
    [ 41 ] = '`',

    [ 43 ] = '\\',
    [ 44 ] = 'z',
    [ 45 ] = 'x',
    [ 46 ] = 'c',
    [ 47 ] = 'v',
    [ 48 ] = 'b',
    [ 49 ] = 'n',
    [ 50 ] = 'm',
    [ 51 ] = ',',
    [ 52 ] = '.',
    [ 53 ] = '/',

    [ 55 ] = '*',
    [ 57 ] = ' ',

    [ 71 ] = '7',
    [ 72 ] = '8',
    [ 73 ] = '9',
    [ 74 ] = '-',
    [ 75 ] = '4',
    [ 76 ] = '5',
    [ 77 ] = '6',
    [ 78 ] = '+',
    [ 79 ] = '1',
    [ 80 ] = '2',
    [ 81 ] = '3',
    [ 82 ] = '0',
    [ 83 ] = '.',

    [ 86 ] = '<',

    [ 96 ] = '\n',

    [ 98 ] = '/',

    [ 102 ] = 1,  /* home */
    [ 103 ] = 16, /* up */
    [ 104 ] = 7,  /* page up */
    [ 105 ] = 2,  /* left */
    [ 106 ] = 6,  /* right */
    [ 107 ] = 5,  /* end */
    [ 108 ] = 14, /* down */
    [ 109 ] = 3,  /* page down */

    [ 111 ] = 4,  /* delete */
};

static char linux2ascii_shifted[] = {
    [ 1 ] = 27,
    [ 2 ] = '!',
    [ 3 ] = '@',
    [ 4 ] = '#',
    [ 5 ] = '$',
    [ 6 ] = '%',
    [ 7 ] = '^',
    [ 8 ] = '&',
    [ 9 ] = '*',
    [ 10 ] = '(',
    [ 11 ] = ')',
    [ 12 ] = '_',
    [ 13 ] = '+',
    [ 14 ] = '\b',
    [ 15 ] = '\t',
    [ 16 ] = 'Q',
    [ 17 ] = 'W',
    [ 18 ] = 'E',
    [ 19 ] = 'R',
    [ 20 ] = 'T',
    [ 21 ] = 'Y',
    [ 22 ] = 'U',
    [ 23 ] = 'I',
    [ 24 ] = 'O',
    [ 25 ] = 'P',
    [ 26 ] = '{',
    [ 27 ] = '}',
    [ 28 ] = '\n',

    [ 30 ] = 'A',
    [ 31 ] = 'S',
    [ 32 ] = 'D',
    [ 33 ] = 'F',
    [ 34 ] = 'G',
    [ 35 ] = 'H',
    [ 36 ] = 'J',
    [ 37 ] = 'K',
    [ 38 ] = 'L',
    [ 39 ] = ':',
    [ 40 ] = '"',
    [ 41 ] = '~',

    [ 43 ] = '|',
    [ 44 ] = 'Z',
    [ 45 ] = 'X',
    [ 46 ] = 'C',
    [ 47 ] = 'V',
    [ 48 ] = 'B',
    [ 49 ] = 'N',
    [ 50 ] = 'M',
    [ 51 ] = '<',
    [ 52 ] = '>',
    [ 53 ] = '?',

    [ 55 ] = '*',
    [ 57 ] = ' ',

    [ 71 ] = '7',
    [ 72 ] = '8',
    [ 73 ] = '9',
    [ 74 ] = '-',
    [ 75 ] = '4',
    [ 76 ] = '5',
    [ 77 ] = '6',
    [ 78 ] = '+',
    [ 79 ] = '1',
    [ 80 ] = '2',
    [ 81 ] = '3',
    [ 82 ] = '0',
    [ 83 ] = '.',

    [ 86 ] = '>',

    [ 96 ] = '\n',

    [ 98 ] = '/',

    [ 102 ] = 1,  /* home */
    [ 103 ] = 16, /* up */
    [ 104 ] = 7,  /* page up */
    [ 105 ] = 2,  /* left */
    [ 106 ] = 6,  /* right */
    [ 107 ] = 5,  /* end */
    [ 108 ] = 14, /* down */
    [ 109 ] = 3,  /* page down */

    [ 111 ] = 4,  /* delete */
};

int console_getkey (void)
{
    static int shift, control, alt, caps_lock;

    if (!has_ev)
        has_ev = kbdfront_receive(kbd_dev, &ev, 1);
    if (!has_ev)
        return 0;

    has_ev = 0;
    if (ev.type != XENKBD_TYPE_KEY)
        return 0;

    if (ev.key.keycode == 42 || ev.key.keycode == 54) {
        caps_lock = 0;
        shift = ev.key.pressed;
        return 0;
    }
    if (ev.key.keycode == 58) {
        caps_lock ^= 1;
        return 0;
    }
    if (ev.key.keycode == 29 || ev.key.keycode == 97) {
        control = ev.key.pressed;
        return 0;
    }
    if (ev.key.keycode == 56) {
        alt = ev.key.pressed;
        return 0;
    }

    if (!ev.key.pressed)
        return 0;

    if (ev.key.keycode < sizeof(linux2ascii) / sizeof(*linux2ascii)) {
        char val;
        if (shift || caps_lock)
            val = linux2ascii_shifted[ev.key.keycode];
        else
            val = linux2ascii[ev.key.keycode];
        if (control)
            val &= ~0x60;
        return val;
    }

    return 0;
}

static DECLARE_MUTEX_LOCKED(kbd_sem);
static void kbd_thread(void *p)
{
    kbd_dev = init_kbdfront(NULL, 1);
    up(&kbd_sem);
}

struct fbfront_dev *fb_open(void *fb, int width, int height, int depth)
{
    unsigned long *mfns;
    int linesize = width * (depth / 8);
    int memsize = linesize * height;
    int numpages = (memsize + PAGE_SIZE - 1) / PAGE_SIZE;
    int i;

    create_thread("kbdfront", kbd_thread, &kbd_sem);

    mfns = malloc(numpages * sizeof(*mfns));
    for (i = 0; i < numpages; i++) {
        memset(fb + i * PAGE_SIZE, 0, PAGE_SIZE);
        mfns[i] = virtual_to_mfn(fb + i * PAGE_SIZE);
    }
    fb_dev = init_fbfront(NULL, mfns, width, height, depth, linesize, numpages);
    free(mfns);

    if (!fb_dev)
        return NULL;

    down(&kbd_sem);
    if (!kbd_dev)
        return NULL;

    return fb_dev;
}

void kbd_close(void *foo)
{
    shutdown_kbdfront(kbd_dev);
    kbd_dev = NULL;
}

void fb_close(void)
{
    create_thread("kbdfront close", kbd_close, NULL);
    shutdown_fbfront(fb_dev);
    fb_dev = NULL;
}

/*
 * Misc
 */

int getrtsecs (void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec % 10 + ((tv.tv_sec / 10) % 6) * 0x10;
}

int currticks (void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((tv.tv_sec * 1000000ULL + tv.tv_usec) * TICKS_PER_SEC) / 1000000;
}

void __attribute__ ((noreturn)) grub_reboot (void)
{
    for ( ;; )
    {
        struct sched_shutdown sched_shutdown = { .reason = SHUTDOWN_reboot };
        HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown);
    }
}

#define SCRATCH_MEMSIZE (4 * 1024 * 1024)

/* Note: not allocating it dynamically permits to make sure it lays below 4G
 * for grub's 32bit pointers to work */
char grub_scratch_mem[SCRATCH_MEMSIZE] __attribute__((aligned(PAGE_SIZE)));

int main(int argc, char **argv)
{
    if (argc > 1 && memcmp(argv[1], "--vtpm-label=", 13) == 0) {
        vtpm_label = argv[1] + 13;
        argc--;
        argv++;
    }

    if (argc > 1) {
        strncpy(config_file, argv[1], sizeof(config_file) - 1);
        config_file[sizeof(config_file) - 1] = 0;
        if (!strncmp(config_file, "(nd)", 4))
            preset_menu = "dhcp";
    } else if (start_info.mod_len)
        preset_menu = (void*) start_info.mod_start;
    else
        preset_menu = "dhcp --with-configfile";

    mbi.drives_addr = BOOTSEC_LOCATION + (60 * 1024);
    mbi.drives_length = 0;

    mbi.boot_loader_name = (unsigned long) "GNU GRUB " VERSION;
    mbi.mem_lower = (start_info.nr_pages * PAGE_SIZE) / 1024;
    mbi.mem_upper = 0;
    saved_drive = boot_drive;
    saved_partition = install_partition;

    init_disk();

    /* Try to make sure the client part got launched */
    sleep(1);
    cmain();
    printk("cmain returned!\n");
}
