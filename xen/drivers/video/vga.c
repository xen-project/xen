/******************************************************************************
 * vga.c
 * 
 * VGA support routines.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/vga.h>
#include <xen/pci.h>
#include <asm/io.h>

/* Filled in by arch boot code. */
struct xen_vga_console_info vga_console_info;

static int vgacon_keep;
static unsigned int xpos, ypos;
static unsigned char *video;

static void vga_text_puts(const char *s);
static void vga_noop_puts(const char *s) {}
void (*video_puts)(const char *) = vga_noop_puts;

/*
 * 'vga=<mode-specifier>[,keep]' where <mode-specifier> is one of:
 * 
 *   'vga=ask':
 *      display a vga menu of available modes
 * 
 *   'vga=current':
 *      use the current vga mode without modification
 * 
 *   'vga=text-80x<rows>':
 *      text mode, where <rows> is one of {25,28,30,34,43,50,60}
 * 
 *   'vga=gfx-<width>x<height>x<depth>':
 *      graphics mode, e.g., vga=gfx-1024x768x16
 * 
 *   'vga=mode-<mode>:
 *      specifies a mode as specified in 'vga=ask' menu
 *      (NB. menu modes are displayed in hex, so mode numbers here must
 *           be prefixed with '0x' (e.g., 'vga=mode-0x0318'))
 * 
 * The option 'keep' causes Xen to continue to print to the VGA console even 
 * after domain 0 starts to boot. The default behaviour is to relinquish
 * control of the console to domain 0.
 */
static char __initdata opt_vga[30] = "";
string_param("vga", opt_vga);

/* VGA text-mode definitions. */
static unsigned int columns, lines;
#define ATTRIBUTE   7

#ifdef CONFIG_X86
void vesa_early_init(void);
void vesa_endboot(bool_t keep);
#else
#define vesa_early_init() ((void)0)
#define vesa_endboot(x)   ((void)0)
#endif

void __init video_init(void)
{
    char *p;

    /* Look for 'keep' in comma-separated options. */
    for ( p = opt_vga; p != NULL; p = strchr(p, ',') )
    {
        if ( *p == ',' )
            p++;
        if ( strncmp(p, "keep", 4) == 0 )
            vgacon_keep = 1;
    }

    switch ( vga_console_info.video_type )
    {
    case XEN_VGATYPE_TEXT_MODE_3:
        if ( page_is_ram_type(paddr_to_pfn(0xB8000), RAM_TYPE_CONVENTIONAL) ||
             ((video = ioremap(0xB8000, 0x8000)) == NULL) )
            return;
        outw(0x200a, 0x3d4); /* disable cursor */
        columns = vga_console_info.u.text_mode_3.columns;
        lines   = vga_console_info.u.text_mode_3.rows;
        memset(video, 0, columns * lines * 2);
        video_puts = vga_text_puts;
        break;
    case XEN_VGATYPE_VESA_LFB:
    case XEN_VGATYPE_EFI_LFB:
        vesa_early_init();
        break;
    default:
        memset(&vga_console_info, 0, sizeof(vga_console_info));
        break;
    }
}

void __init video_endboot(void)
{
    if ( video_puts == vga_noop_puts )
        return;

    printk("Xen is %s VGA console.\n",
           vgacon_keep ? "keeping" : "relinquishing");

    if ( !vgacon_keep )
        video_puts = vga_noop_puts;
    else
    {
        int bus, devfn;

        for ( bus = 0; bus < 256; ++bus )
            for ( devfn = 0; devfn < 256; ++devfn )
            {
                const struct pci_dev *pdev;
                u8 b = bus, df = devfn, sb;

                pcidevs_lock();
                pdev = pci_get_pdev(0, bus, devfn);
                pcidevs_unlock();

                if ( !pdev ||
                     pci_conf_read16(0, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                                     PCI_CLASS_DEVICE) != 0x0300 ||
                     !(pci_conf_read16(0, bus, PCI_SLOT(devfn),
                                       PCI_FUNC(devfn), PCI_COMMAND) &
                       (PCI_COMMAND_IO | PCI_COMMAND_MEMORY)) )
                    continue;

                while ( b )
                {
                    switch ( find_upstream_bridge(0, &b, &df, &sb) )
                    {
                    case 0:
                        b = 0;
                        break;
                    case 1:
                        switch ( pci_conf_read8(PCI_SBDF3(0, b, df),
                                                PCI_HEADER_TYPE) )
                        {
                        case PCI_HEADER_TYPE_BRIDGE:
                        case PCI_HEADER_TYPE_CARDBUS:
                            if ( pci_conf_read16(0, b, PCI_SLOT(df),
                                                 PCI_FUNC(df),
                                                 PCI_BRIDGE_CONTROL) &
                                 PCI_BRIDGE_CTL_VGA )
                                continue;
                            break;
                        }
                        break;
                    }
                    break;
                }
                if ( !b )
                {
                    printk(XENLOG_INFO "Boot video device %02x:%02x.%u\n",
                           bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
                    pci_hide_device(0, bus, devfn);
                }
            }
    }

    switch ( vga_console_info.video_type )
    {
    case XEN_VGATYPE_TEXT_MODE_3:
        if ( !vgacon_keep )
            memset(video, 0, columns * lines * 2);
        break;
    case XEN_VGATYPE_VESA_LFB:
    case XEN_VGATYPE_EFI_LFB:
        vesa_endboot(vgacon_keep);
        break;
    default:
        BUG();
    }
}

static void vga_text_puts(const char *s)
{
    char c;

    while ( (c = *s++) != '\0' )
    {
        if ( (c == '\n') || (xpos >= columns) )
        {
            if ( ++ypos >= lines )
            {
                ypos = lines - 1;
                memmove(video, video + 2 * columns, ypos * 2 * columns);
                memset(video + ypos * 2 * columns, 0, 2 * xpos);
            }
            xpos = 0;
        }

        if ( c != '\n' )
        {
            video[(xpos + ypos * columns) * 2]     = c;
            video[(xpos + ypos * columns) * 2 + 1] = ATTRIBUTE;
            xpos++;
        }
    }
}

int __init fill_console_start_info(struct dom0_vga_console_info *ci)
{
    memcpy(ci, &vga_console_info, sizeof(*ci));
    return 1;
}
