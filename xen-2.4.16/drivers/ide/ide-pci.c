/*
 *  linux/drivers/ide/ide-pci.c		Version 1.05	June 9, 2000
 *
 *  Copyright (c) 1998-2000  Andre Hedrick <andre@linux-ide.org>
 *
 *  Copyright (c) 1995-1998  Mark Lord
 *  May be copied or modified under the terms of the GNU General Public License
 */

/*
 *  This module provides support for automatic detection and
 *  configuration of all PCI IDE interfaces present in a system.  
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/ide.h>

#include <asm/io.h>
#include <asm/irq.h>

#define DEVID_PIIXa	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82371FB_0})
#define DEVID_PIIXb	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82371FB_1})
#define DEVID_MPIIX	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82371MX})
#define DEVID_PIIX3	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82371SB_1})
#define DEVID_PIIX4	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82371AB})
#define DEVID_ICH0	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82801AB_1})
#define DEVID_PIIX4E2	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82443MX_1})
#define DEVID_ICH	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82801AA_1})
#define DEVID_PIIX4U2	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82372FB_1})
#define DEVID_PIIX4NX	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82451NX})
#define DEVID_ICH2	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82801BA_9})
#define DEVID_ICH2M	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82801BA_8})
#define DEVID_ICH3M	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82801CA_10})
#define DEVID_ICH3	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82801CA_11})
#define DEVID_ICH4	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82801DB_11})
#define DEVID_CICH	((ide_pci_devid_t){PCI_VENDOR_ID_INTEL,   PCI_DEVICE_ID_INTEL_82801E_11})
#define DEVID_VIA_IDE	((ide_pci_devid_t){PCI_VENDOR_ID_VIA,     PCI_DEVICE_ID_VIA_82C561})
#define DEVID_MR_IDE	((ide_pci_devid_t){PCI_VENDOR_ID_VIA,     PCI_DEVICE_ID_VIA_82C576_1})
#define DEVID_VP_IDE	((ide_pci_devid_t){PCI_VENDOR_ID_VIA,     PCI_DEVICE_ID_VIA_82C586_1})
#define DEVID_PDC20246	((ide_pci_devid_t){PCI_VENDOR_ID_PROMISE, PCI_DEVICE_ID_PROMISE_20246})
#define DEVID_PDC20262	((ide_pci_devid_t){PCI_VENDOR_ID_PROMISE, PCI_DEVICE_ID_PROMISE_20262})
#define DEVID_PDC20265	((ide_pci_devid_t){PCI_VENDOR_ID_PROMISE, PCI_DEVICE_ID_PROMISE_20265})
#define DEVID_PDC20267	((ide_pci_devid_t){PCI_VENDOR_ID_PROMISE, PCI_DEVICE_ID_PROMISE_20267})
#define DEVID_PDC20268  ((ide_pci_devid_t){PCI_VENDOR_ID_PROMISE, PCI_DEVICE_ID_PROMISE_20268})
#define DEVID_PDC20270  ((ide_pci_devid_t){PCI_VENDOR_ID_PROMISE, PCI_DEVICE_ID_PROMISE_20270})
#define DEVID_PDC20269	((ide_pci_devid_t){PCI_VENDOR_ID_PROMISE, PCI_DEVICE_ID_PROMISE_20269})
#define DEVID_PDC20275	((ide_pci_devid_t){PCI_VENDOR_ID_PROMISE, PCI_DEVICE_ID_PROMISE_20275})
#define DEVID_PDC20276	((ide_pci_devid_t){PCI_VENDOR_ID_PROMISE, PCI_DEVICE_ID_PROMISE_20276})
#define DEVID_RZ1000	((ide_pci_devid_t){PCI_VENDOR_ID_PCTECH,  PCI_DEVICE_ID_PCTECH_RZ1000})
#define DEVID_RZ1001	((ide_pci_devid_t){PCI_VENDOR_ID_PCTECH,  PCI_DEVICE_ID_PCTECH_RZ1001})
#define DEVID_SAMURAI	((ide_pci_devid_t){PCI_VENDOR_ID_PCTECH,  PCI_DEVICE_ID_PCTECH_SAMURAI_IDE})
#define DEVID_CMD640	((ide_pci_devid_t){PCI_VENDOR_ID_CMD,     PCI_DEVICE_ID_CMD_640})
#define DEVID_CMD643	((ide_pci_devid_t){PCI_VENDOR_ID_CMD,     PCI_DEVICE_ID_CMD_643})
#define DEVID_CMD646	((ide_pci_devid_t){PCI_VENDOR_ID_CMD,     PCI_DEVICE_ID_CMD_646})
#define DEVID_CMD648	((ide_pci_devid_t){PCI_VENDOR_ID_CMD,     PCI_DEVICE_ID_CMD_648})
#define DEVID_CMD649	((ide_pci_devid_t){PCI_VENDOR_ID_CMD,     PCI_DEVICE_ID_CMD_649})
#define DEVID_CMD680	((ide_pci_devid_t){PCI_VENDOR_ID_CMD,     PCI_DEVICE_ID_CMD_680})
#define DEVID_SIS5513	((ide_pci_devid_t){PCI_VENDOR_ID_SI,      PCI_DEVICE_ID_SI_5513})
#define DEVID_OPTI621	((ide_pci_devid_t){PCI_VENDOR_ID_OPTI,    PCI_DEVICE_ID_OPTI_82C621})
#define DEVID_OPTI621V	((ide_pci_devid_t){PCI_VENDOR_ID_OPTI,    PCI_DEVICE_ID_OPTI_82C558})
#define DEVID_OPTI621X	((ide_pci_devid_t){PCI_VENDOR_ID_OPTI,    PCI_DEVICE_ID_OPTI_82C825})
#define DEVID_TRM290	((ide_pci_devid_t){PCI_VENDOR_ID_TEKRAM,  PCI_DEVICE_ID_TEKRAM_DC290})
#define DEVID_NS87410	((ide_pci_devid_t){PCI_VENDOR_ID_NS,      PCI_DEVICE_ID_NS_87410})
#define DEVID_NS87415	((ide_pci_devid_t){PCI_VENDOR_ID_NS,      PCI_DEVICE_ID_NS_87415})
#define DEVID_HT6565	((ide_pci_devid_t){PCI_VENDOR_ID_HOLTEK,  PCI_DEVICE_ID_HOLTEK_6565})
#define DEVID_AEC6210	((ide_pci_devid_t){PCI_VENDOR_ID_ARTOP,   PCI_DEVICE_ID_ARTOP_ATP850UF})
#define DEVID_AEC6260	((ide_pci_devid_t){PCI_VENDOR_ID_ARTOP,   PCI_DEVICE_ID_ARTOP_ATP860})
#define DEVID_AEC6260R	((ide_pci_devid_t){PCI_VENDOR_ID_ARTOP,   PCI_DEVICE_ID_ARTOP_ATP860R})
#define DEVID_W82C105	((ide_pci_devid_t){PCI_VENDOR_ID_WINBOND, PCI_DEVICE_ID_WINBOND_82C105})
#define DEVID_UM8673F	((ide_pci_devid_t){PCI_VENDOR_ID_UMC,     PCI_DEVICE_ID_UMC_UM8673F})
#define DEVID_UM8886A	((ide_pci_devid_t){PCI_VENDOR_ID_UMC,     PCI_DEVICE_ID_UMC_UM8886A})
#define DEVID_UM8886BF	((ide_pci_devid_t){PCI_VENDOR_ID_UMC,     PCI_DEVICE_ID_UMC_UM8886BF})
#define DEVID_HPT34X	((ide_pci_devid_t){PCI_VENDOR_ID_TTI,     PCI_DEVICE_ID_TTI_HPT343})
#define DEVID_HPT366	((ide_pci_devid_t){PCI_VENDOR_ID_TTI,     PCI_DEVICE_ID_TTI_HPT366})
#define DEVID_ALI15X3	((ide_pci_devid_t){PCI_VENDOR_ID_AL,      PCI_DEVICE_ID_AL_M5229})
#define DEVID_CY82C693	((ide_pci_devid_t){PCI_VENDOR_ID_CONTAQ,  PCI_DEVICE_ID_CONTAQ_82C693})
#define DEVID_HINT	((ide_pci_devid_t){0x3388,                0x8013})
#define DEVID_CS5530	((ide_pci_devid_t){PCI_VENDOR_ID_CYRIX,   PCI_DEVICE_ID_CYRIX_5530_IDE})
#define DEVID_AMD7401	((ide_pci_devid_t){PCI_VENDOR_ID_AMD,     PCI_DEVICE_ID_AMD_COBRA_7401})
#define DEVID_AMD7409	((ide_pci_devid_t){PCI_VENDOR_ID_AMD,     PCI_DEVICE_ID_AMD_VIPER_7409})
#define DEVID_AMD7411	((ide_pci_devid_t){PCI_VENDOR_ID_AMD,     PCI_DEVICE_ID_AMD_VIPER_7411})
#define DEVID_AMD7441	((ide_pci_devid_t){PCI_VENDOR_ID_AMD,     PCI_DEVICE_ID_AMD_VIPER_7441})
#define DEVID_PDCADMA	((ide_pci_devid_t){PCI_VENDOR_ID_PDC,     PCI_DEVICE_ID_PDC_1841})
#define DEVID_SLC90E66	((ide_pci_devid_t){PCI_VENDOR_ID_EFAR,    PCI_DEVICE_ID_EFAR_SLC90E66_1})
#define DEVID_OSB4	((ide_pci_devid_t){PCI_VENDOR_ID_SERVERWORKS, PCI_DEVICE_ID_SERVERWORKS_OSB4IDE})
#define DEVID_CSB5	((ide_pci_devid_t){PCI_VENDOR_ID_SERVERWORKS, PCI_DEVICE_ID_SERVERWORKS_CSB5IDE})
#define DEVID_ITE8172G	((ide_pci_devid_t){PCI_VENDOR_ID_ITE,     PCI_DEVICE_ID_ITE_IT8172G})

#define	IDE_IGNORE	((void *)-1)
#define IDE_NO_DRIVER	((void *)-2)

#ifdef CONFIG_BLK_DEV_AEC62XX
extern unsigned int pci_init_aec62xx(struct pci_dev *, const char *);
extern unsigned int ata66_aec62xx(ide_hwif_t *);
extern void ide_init_aec62xx(ide_hwif_t *);
extern void ide_dmacapable_aec62xx(ide_hwif_t *, unsigned long);
#define PCI_AEC62XX	&pci_init_aec62xx
#define ATA66_AEC62XX	&ata66_aec62xx
#define INIT_AEC62XX	&ide_init_aec62xx
#define DMA_AEC62XX	&ide_dmacapable_aec62xx
#else
#define PCI_AEC62XX	NULL
#define ATA66_AEC62XX	NULL
#define INIT_AEC62XX	IDE_NO_DRIVER
#define DMA_AEC62XX	NULL
#endif

#ifdef CONFIG_BLK_DEV_ALI15X3
extern unsigned int pci_init_ali15x3(struct pci_dev *, const char *);
extern unsigned int ata66_ali15x3(ide_hwif_t *);
extern void ide_init_ali15x3(ide_hwif_t *);
extern void ide_dmacapable_ali15x3(ide_hwif_t *, unsigned long);
#define PCI_ALI15X3	&pci_init_ali15x3
#define ATA66_ALI15X3	&ata66_ali15x3
#define INIT_ALI15X3	&ide_init_ali15x3
#define DMA_ALI15X3	&ide_dmacapable_ali15x3
#else
#define PCI_ALI15X3	NULL
#define ATA66_ALI15X3	NULL
#define INIT_ALI15X3	IDE_NO_DRIVER
#define DMA_ALI15X3	NULL
#endif

#ifdef CONFIG_BLK_DEV_AMD74XX
extern unsigned int pci_init_amd74xx(struct pci_dev *, const char *);
extern unsigned int ata66_amd74xx(ide_hwif_t *);
extern void ide_init_amd74xx(ide_hwif_t *);
extern void ide_dmacapable_amd74xx(ide_hwif_t *, unsigned long);
#define PCI_AMD74XX	&pci_init_amd74xx
#define ATA66_AMD74XX	&ata66_amd74xx
#define INIT_AMD74XX	&ide_init_amd74xx
#define DMA_AMD74XX	&ide_dmacapable_amd74xx
#else
#define PCI_AMD74XX	NULL
#define ATA66_AMD74XX	NULL
#define INIT_AMD74XX	IDE_NO_DRIVER
#define DMA_AMD74XX	NULL
#endif

#ifdef CONFIG_BLK_DEV_CMD64X
extern unsigned int pci_init_cmd64x(struct pci_dev *, const char *);
extern unsigned int ata66_cmd64x(ide_hwif_t *);
extern void ide_init_cmd64x(ide_hwif_t *);
extern void ide_dmacapable_cmd64x(ide_hwif_t *, unsigned long);
#define PCI_CMD64X	&pci_init_cmd64x
#define ATA66_CMD64X	&ata66_cmd64x
#define INIT_CMD64X	&ide_init_cmd64x
#else
#define PCI_CMD64X	NULL
#define ATA66_CMD64X	NULL
#ifdef __sparc_v9__
#define INIT_CMD64X	IDE_IGNORE
#else
#define INIT_CMD64X	IDE_NO_DRIVER
#endif
#endif

#ifdef CONFIG_BLK_DEV_CY82C693
extern unsigned int pci_init_cy82c693(struct pci_dev *, const char *);
extern void ide_init_cy82c693(ide_hwif_t *);
#define PCI_CY82C693	&pci_init_cy82c693
#define INIT_CY82C693	&ide_init_cy82c693
#else
#define PCI_CY82C693	NULL
#define INIT_CY82C693	IDE_NO_DRIVER
#endif

#ifdef CONFIG_BLK_DEV_CS5530
extern unsigned int pci_init_cs5530(struct pci_dev *, const char *);
extern void ide_init_cs5530(ide_hwif_t *);
#define PCI_CS5530	&pci_init_cs5530
#define INIT_CS5530	&ide_init_cs5530
#else
#define PCI_CS5530	NULL
#define INIT_CS5530	IDE_NO_DRIVER
#endif

#ifdef CONFIG_BLK_DEV_HPT34X
extern unsigned int pci_init_hpt34x(struct pci_dev *, const char *);
extern void ide_init_hpt34x(ide_hwif_t *);
#define PCI_HPT34X	&pci_init_hpt34x
#define INIT_HPT34X	&ide_init_hpt34x
#else
#define PCI_HPT34X	NULL
#define INIT_HPT34X	IDE_IGNORE
#endif

#ifdef CONFIG_BLK_DEV_HPT366
extern byte hpt363_shared_irq;
extern byte hpt363_shared_pin;
extern unsigned int pci_init_hpt366(struct pci_dev *, const char *);
extern unsigned int ata66_hpt366(ide_hwif_t *);
extern void ide_init_hpt366(ide_hwif_t *);
extern void ide_dmacapable_hpt366(ide_hwif_t *, unsigned long);
#define PCI_HPT366	&pci_init_hpt366
#define ATA66_HPT366	&ata66_hpt366
#define INIT_HPT366	&ide_init_hpt366
#define DMA_HPT366	&ide_dmacapable_hpt366
#else
static byte hpt363_shared_irq;
static byte hpt363_shared_pin;
#define PCI_HPT366	NULL
#define ATA66_HPT366	NULL
#define INIT_HPT366	IDE_NO_DRIVER
#define DMA_HPT366	NULL
#endif

#ifdef CONFIG_BLK_DEV_NS87415
extern void ide_init_ns87415(ide_hwif_t *);
#define INIT_NS87415	&ide_init_ns87415
#else
#define INIT_NS87415	IDE_IGNORE
#endif

#ifdef CONFIG_BLK_DEV_OPTI621
extern void ide_init_opti621(ide_hwif_t *);
#define INIT_OPTI621	&ide_init_opti621
#else
#define INIT_OPTI621	IDE_NO_DRIVER
#endif

#ifdef CONFIG_BLK_DEV_PDC_ADMA
extern unsigned int pci_init_pdcadma(struct pci_dev *, const char *);
extern unsigned int ata66_pdcadma(ide_hwif_t *);
extern void ide_init_pdcadma(ide_hwif_t *);
extern void ide_dmacapable_pdcadma(ide_hwif_t *, unsigned long);
#define PCI_PDCADMA	&pci_init_pdcadma
#define ATA66_PDCADMA	&ata66_pdcadma
#define INIT_PDCADMA	&ide_init_pdcadma
#define DMA_PDCADMA	&ide_dmacapable_pdcadma
#else
#define PCI_PDCADMA	IDE_IGNORE
#define ATA66_PDCADMA	IDE_IGNORE
#define INIT_PDCADMA	IDE_IGNORE
#define DMA_PDCADMA	IDE_IGNORE
#endif

#ifdef CONFIG_BLK_DEV_PDC202XX
extern unsigned int pci_init_pdc202xx(struct pci_dev *, const char *);
extern unsigned int ata66_pdc202xx(ide_hwif_t *);
extern void ide_init_pdc202xx(ide_hwif_t *);
#define PCI_PDC202XX	&pci_init_pdc202xx
#define ATA66_PDC202XX	&ata66_pdc202xx
#define INIT_PDC202XX	&ide_init_pdc202xx
#else
#define PCI_PDC202XX	NULL
#define ATA66_PDC202XX	NULL
#define INIT_PDC202XX	NULL
#endif

#ifdef CONFIG_BLK_DEV_PIIX
extern unsigned int pci_init_piix(struct pci_dev *, const char *);
extern unsigned int ata66_piix(ide_hwif_t *);
extern void ide_init_piix(ide_hwif_t *);
#define PCI_PIIX	&pci_init_piix
#define ATA66_PIIX	&ata66_piix
#define INIT_PIIX	&ide_init_piix
#else
#define PCI_PIIX	NULL
#define ATA66_PIIX	NULL
#define INIT_PIIX	IDE_NO_DRIVER
#endif

#ifdef CONFIG_BLK_DEV_IT8172
extern unsigned int pci_init_it8172(struct pci_dev *, const char *);
extern unsigned int ata66_it8172(ide_hwif_t *);
extern void ide_init_it8172(ide_hwif_t *);
#define PCI_IT8172	&pci_init_it8172
#define INIT_IT8172	&ide_init_it8172
#else
#define PCI_IT8172	NULL
#define ATA66_IT8172	NULL
#define INIT_IT8172	NULL
#endif

#ifdef CONFIG_BLK_DEV_RZ1000
extern void ide_init_rz1000(ide_hwif_t *);
#define INIT_RZ1000	&ide_init_rz1000
#else
#define INIT_RZ1000	IDE_IGNORE
#endif

#define INIT_SAMURAI	NULL

#ifdef CONFIG_BLK_DEV_SVWKS
extern unsigned int pci_init_svwks(struct pci_dev *, const char *);
extern unsigned int ata66_svwks(ide_hwif_t *);
extern void ide_init_svwks(ide_hwif_t *);
#define PCI_SVWKS	&pci_init_svwks
#define ATA66_SVWKS	&ata66_svwks
#define INIT_SVWKS	&ide_init_svwks
#else
#define PCI_SVWKS	NULL
#define ATA66_SVWKS	NULL
#define INIT_SVWKS	IDE_NO_DRIVER
#endif

#ifdef CONFIG_BLK_DEV_SIS5513
extern unsigned int pci_init_sis5513(struct pci_dev *, const char *);
extern unsigned int ata66_sis5513(ide_hwif_t *);
extern void ide_init_sis5513(ide_hwif_t *);
#define PCI_SIS5513	&pci_init_sis5513
#define ATA66_SIS5513	&ata66_sis5513
#define INIT_SIS5513	&ide_init_sis5513
#else
#define PCI_SIS5513	NULL
#define ATA66_SIS5513	NULL
#define INIT_SIS5513	IDE_NO_DRIVER
#endif

#ifdef CONFIG_BLK_DEV_SLC90E66
extern unsigned int pci_init_slc90e66(struct pci_dev *, const char *);
extern unsigned int ata66_slc90e66(ide_hwif_t *);
extern void ide_init_slc90e66(ide_hwif_t *);
#define PCI_SLC90E66	&pci_init_slc90e66
#define ATA66_SLC90E66	&ata66_slc90e66
#define INIT_SLC90E66	&ide_init_slc90e66
#else
#define PCI_SLC90E66	NULL
#define ATA66_SLC90E66	NULL
#define INIT_SLC90E66	IDE_NO_DRIVER
#endif

#ifdef CONFIG_BLK_DEV_SL82C105
extern unsigned int pci_init_sl82c105(struct pci_dev *, const char *);
extern void dma_init_sl82c105(ide_hwif_t *, unsigned long);
extern void ide_init_sl82c105(ide_hwif_t *);
#define PCI_W82C105	&pci_init_sl82c105
#define DMA_W82C105	&dma_init_sl82c105
#define INIT_W82C105	&ide_init_sl82c105
#else
#define PCI_W82C105	NULL
#define DMA_W82C105	NULL
#define INIT_W82C105	IDE_IGNORE
#endif

#ifdef CONFIG_BLK_DEV_TRM290
extern void ide_init_trm290(ide_hwif_t *);
#define INIT_TRM290	&ide_init_trm290
#else
#define INIT_TRM290	IDE_IGNORE
#endif

#ifdef CONFIG_BLK_DEV_VIA82CXXX
extern unsigned int pci_init_via82cxxx(struct pci_dev *, const char *);
extern unsigned int ata66_via82cxxx(ide_hwif_t *);
extern void ide_init_via82cxxx(ide_hwif_t *);
extern void ide_dmacapable_via82cxxx(ide_hwif_t *, unsigned long);
#define PCI_VIA82CXXX	&pci_init_via82cxxx
#define ATA66_VIA82CXXX	&ata66_via82cxxx
#define INIT_VIA82CXXX	&ide_init_via82cxxx
#define DMA_VIA82CXXX	&ide_dmacapable_via82cxxx
#else
#define PCI_VIA82CXXX	NULL
#define ATA66_VIA82CXXX	NULL
#define INIT_VIA82CXXX	IDE_NO_DRIVER
#define DMA_VIA82CXXX	NULL
#endif

typedef struct ide_pci_enablebit_s {
	byte	reg;	/* byte pci reg holding the enable-bit */
	byte	mask;	/* mask to isolate the enable-bit */
	byte	val;	/* value of masked reg when "enabled" */
} ide_pci_enablebit_t;

typedef struct ide_pci_device_s {
	ide_pci_devid_t		devid;
	char			*name;
	unsigned int		(*init_chipset)(struct pci_dev *dev, const char *name);
	unsigned int		(*ata66_check)(ide_hwif_t *hwif);
	void 			(*init_hwif)(ide_hwif_t *hwif);
	void			(*dma_init)(ide_hwif_t *hwif, unsigned long dmabase);
	ide_pci_enablebit_t	enablebits[2];
	byte			bootable;
	unsigned int		extra;
} ide_pci_device_t;

static ide_pci_device_t ide_pci_chipsets[] __initdata = {
	{DEVID_PIIXa,	"PIIX",		NULL,		NULL,		INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}}, 	ON_BOARD,	0 },
	{DEVID_PIIXb,	"PIIX",		NULL,		NULL,		INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}}, 	ON_BOARD,	0 },
	{DEVID_MPIIX,	"MPIIX",	NULL,		NULL,		INIT_PIIX,	NULL,		{{0x6D,0x80,0x80}, {0x6F,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_PIIX3,	"PIIX3",	PCI_PIIX,	NULL,		INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}}, 	ON_BOARD,	0 },
	{DEVID_PIIX4,	"PIIX4",	PCI_PIIX,	NULL,		INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}}, 	ON_BOARD,	0 },
	{DEVID_ICH0,	"ICH0", 	PCI_PIIX,	NULL,		INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_PIIX4E2,	"PIIX4",	PCI_PIIX,	NULL,		INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_ICH,	"ICH",  	PCI_PIIX,	ATA66_PIIX,	INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_PIIX4U2,	"PIIX4",	PCI_PIIX,	ATA66_PIIX,	INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_PIIX4NX,	"PIIX4",	PCI_PIIX,	NULL,		INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_ICH2,	"ICH2", 	PCI_PIIX,	ATA66_PIIX,	INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_ICH2M,	"ICH2M",	PCI_PIIX,	ATA66_PIIX,	INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_ICH3M,	"ICH3M",	PCI_PIIX,	ATA66_PIIX,	INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_ICH3,	"ICH3", 	PCI_PIIX,	ATA66_PIIX,	INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_ICH4,	"ICH4", 	PCI_PIIX,	ATA66_PIIX,	INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_CICH,	"C-ICH",	PCI_PIIX,	ATA66_PIIX,	INIT_PIIX,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
	{DEVID_VIA_IDE,	"VIA_IDE",	NULL,		NULL,		NULL,		NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_MR_IDE,	"VP_IDE",	PCI_VIA82CXXX,	ATA66_VIA82CXXX,INIT_VIA82CXXX,	DMA_VIA82CXXX,	{{0x40,0x02,0x02}, {0x40,0x01,0x01}}, 	ON_BOARD,	0 },
	{DEVID_VP_IDE,	"VP_IDE",	PCI_VIA82CXXX,	ATA66_VIA82CXXX,INIT_VIA82CXXX,	DMA_VIA82CXXX,	{{0x40,0x02,0x02}, {0x40,0x01,0x01}}, 	ON_BOARD,	0 },
#ifndef CONFIG_PDC202XX_FORCE
        {DEVID_PDC20246,"PDC20246",	PCI_PDC202XX,	NULL,		INIT_PDC202XX,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	OFF_BOARD,	16 },
        {DEVID_PDC20262,"PDC20262",	PCI_PDC202XX,	ATA66_PDC202XX,	INIT_PDC202XX,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	OFF_BOARD,	48 },
        {DEVID_PDC20265,"PDC20265",	PCI_PDC202XX,	ATA66_PDC202XX,	INIT_PDC202XX,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	OFF_BOARD,	48 },
        {DEVID_PDC20267,"PDC20267",	PCI_PDC202XX,	ATA66_PDC202XX,	INIT_PDC202XX,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	OFF_BOARD,	48 },
#else /* !CONFIG_PDC202XX_FORCE */
	{DEVID_PDC20246,"PDC20246",	PCI_PDC202XX,	NULL,		INIT_PDC202XX,	NULL,		{{0x50,0x02,0x02}, {0x50,0x04,0x04}}, 	OFF_BOARD,	16 },
	{DEVID_PDC20262,"PDC20262",	PCI_PDC202XX,	ATA66_PDC202XX,	INIT_PDC202XX,	NULL,		{{0x50,0x02,0x02}, {0x50,0x04,0x04}},	OFF_BOARD,	48 },
	{DEVID_PDC20265,"PDC20265",	PCI_PDC202XX,	ATA66_PDC202XX,	INIT_PDC202XX,	NULL,		{{0x50,0x02,0x02}, {0x50,0x04,0x04}},	OFF_BOARD,	48 },
	{DEVID_PDC20267,"PDC20267",	PCI_PDC202XX,	ATA66_PDC202XX,	INIT_PDC202XX,	NULL,		{{0x50,0x02,0x02}, {0x50,0x04,0x04}},	OFF_BOARD,	48 },
#endif
	{DEVID_PDC20268,"PDC20268",	PCI_PDC202XX,	ATA66_PDC202XX,	INIT_PDC202XX,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	OFF_BOARD,	0 },
	/* Promise used a different PCI ident for the raid card apparently to try and
	   prevent Linux detecting it and using our own raid code. We want to detect
	   it for the ataraid drivers, so we have to list both here.. */
	{DEVID_PDC20270,"PDC20270",	PCI_PDC202XX,	ATA66_PDC202XX,	INIT_PDC202XX,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	OFF_BOARD,	0 },
	{DEVID_PDC20269,"PDC20269",	PCI_PDC202XX,	ATA66_PDC202XX,	 INIT_PDC202XX,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	OFF_BOARD,	0 },
	{DEVID_PDC20275,"PDC20275",	PCI_PDC202XX,	ATA66_PDC202XX,	INIT_PDC202XX,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	OFF_BOARD,	0 },
	{DEVID_PDC20276,"PDC20276",	PCI_PDC202XX,	ATA66_PDC202XX,	INIT_PDC202XX,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	OFF_BOARD,	0 },
	{DEVID_RZ1000,	"RZ1000",	NULL,		NULL,		INIT_RZ1000,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}}, 	ON_BOARD,	0 },
	{DEVID_RZ1001,	"RZ1001",	NULL,		NULL,		INIT_RZ1000,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}}, 	ON_BOARD,	0 },
	{DEVID_SAMURAI,	"SAMURAI",	NULL,		NULL,		INIT_SAMURAI,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_CMD640,	"CMD640",	NULL,		NULL,		IDE_IGNORE,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}}, 	ON_BOARD,	0 },
	{DEVID_NS87410,	"NS87410",	NULL,		NULL,		NULL,		NULL,		{{0x43,0x08,0x08}, {0x47,0x08,0x08}}, 	ON_BOARD,	0 },
	{DEVID_SIS5513,	"SIS5513",	PCI_SIS5513,	ATA66_SIS5513,	INIT_SIS5513,	NULL,		{{0x4a,0x02,0x02}, {0x4a,0x04,0x04}}, 	ON_BOARD,	0 },
	{DEVID_CMD643,	"CMD643",	PCI_CMD64X,	NULL,		INIT_CMD64X,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_CMD646,	"CMD646",	PCI_CMD64X,	NULL,		INIT_CMD64X,	NULL,		{{0x00,0x00,0x00}, {0x51,0x80,0x80}}, 	ON_BOARD,	0 },
	{DEVID_CMD648,	"CMD648",	PCI_CMD64X,	ATA66_CMD64X,	INIT_CMD64X,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_CMD649,	"CMD649",	PCI_CMD64X,	ATA66_CMD64X,	INIT_CMD64X,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
#ifndef CONFIG_BLK_DEV_CMD680
	{DEVID_CMD680,	"CMD680",	NULL,		NULL,		NULL,		NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
#else /* CONFIG_BLK_DEV_CMD680 */
	{DEVID_CMD680,	"CMD680",	PCI_CMD64X,	ATA66_CMD64X,	INIT_CMD64X,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
#endif /* !CONFIG_BLK_DEV_CMD680 */
	{DEVID_HT6565,	"HT6565",	NULL,		NULL,		NULL,		NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}}, 	ON_BOARD,	0 },
	{DEVID_OPTI621,	"OPTI621",	NULL,		NULL,		INIT_OPTI621,	NULL,		{{0x45,0x80,0x00}, {0x40,0x08,0x00}}, 	ON_BOARD,	0 },
	{DEVID_OPTI621X,"OPTI621X",	NULL,		NULL,		INIT_OPTI621,	NULL,		{{0x45,0x80,0x00}, {0x40,0x08,0x00}}, 	ON_BOARD,	0 },
	{DEVID_TRM290,	"TRM290",	NULL,		NULL,		INIT_TRM290,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}}, 	ON_BOARD,	0 },
	{DEVID_NS87415,	"NS87415",	NULL,		NULL,		INIT_NS87415,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}}, 	ON_BOARD,	0 },
	{DEVID_AEC6210,	"AEC6210",	PCI_AEC62XX,	NULL,		INIT_AEC62XX,	DMA_AEC62XX,	{{0x4a,0x02,0x02}, {0x4a,0x04,0x04}}, 	OFF_BOARD,	0 },
	{DEVID_AEC6260,	"AEC6260",	PCI_AEC62XX,	ATA66_AEC62XX,	INIT_AEC62XX,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	NEVER_BOARD,	0 },
	{DEVID_AEC6260R,"AEC6260R",	PCI_AEC62XX,	ATA66_AEC62XX,	INIT_AEC62XX,	NULL,		{{0x4a,0x02,0x02}, {0x4a,0x04,0x04}},	OFF_BOARD,	0 },
	{DEVID_W82C105,	"W82C105",	PCI_W82C105,	NULL,		INIT_W82C105,	DMA_W82C105,	{{0x40,0x01,0x01}, {0x40,0x10,0x10}}, 	ON_BOARD,	0 },
	{DEVID_UM8673F,	"UM8673F",	NULL,		NULL,		NULL,		NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_UM8886A,	"UM8886A",	NULL,		NULL,		NULL,		NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_UM8886BF,"UM8886BF",	NULL,		NULL,		NULL,		NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}}, 	ON_BOARD,	0 },
	{DEVID_HPT34X,	"HPT34X",	PCI_HPT34X,	NULL,		INIT_HPT34X,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	NEVER_BOARD,	16 },
	{DEVID_HPT366,	"HPT366",	PCI_HPT366,	ATA66_HPT366,	INIT_HPT366,	DMA_HPT366,	{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	OFF_BOARD,	240 },
	{DEVID_ALI15X3,	"ALI15X3",	PCI_ALI15X3,	ATA66_ALI15X3,	INIT_ALI15X3,	DMA_ALI15X3,	{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_CY82C693,"CY82C693",	PCI_CY82C693,	NULL,		INIT_CY82C693,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_HINT,	"HINT_IDE",	NULL,		NULL,		NULL,		NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_CS5530,	"CS5530",	PCI_CS5530,	NULL,		INIT_CS5530,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_AMD7401,	"AMD7401",	NULL,		NULL,		NULL,		DMA_AMD74XX,	{{0x40,0x01,0x01}, {0x40,0x02,0x02}},	ON_BOARD,	0 },
	{DEVID_AMD7409,	"AMD7409",	PCI_AMD74XX,	ATA66_AMD74XX,	INIT_AMD74XX,	DMA_AMD74XX,	{{0x40,0x01,0x01}, {0x40,0x02,0x02}},	ON_BOARD,	0 },
	{DEVID_AMD7411,	"AMD7411",	PCI_AMD74XX,	ATA66_AMD74XX,	INIT_AMD74XX,	DMA_AMD74XX,	{{0x40,0x01,0x01}, {0x40,0x02,0x02}},	ON_BOARD,	0 },
	{DEVID_AMD7441,	"AMD7441",	PCI_AMD74XX,	ATA66_AMD74XX,	INIT_AMD74XX,	DMA_AMD74XX,	{{0x40,0x01,0x01}, {0x40,0x02,0x02}},	ON_BOARD,	0 },
	{DEVID_PDCADMA,	"PDCADMA",	PCI_PDCADMA,	ATA66_PDCADMA,	INIT_PDCADMA,	DMA_PDCADMA,	{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	OFF_BOARD,	0 },
	{DEVID_SLC90E66,"SLC90E66",	PCI_SLC90E66,	ATA66_SLC90E66,	INIT_SLC90E66,	NULL,		{{0x41,0x80,0x80}, {0x43,0x80,0x80}},	ON_BOARD,	0 },
        {DEVID_OSB4,    "ServerWorks OSB4",		PCI_SVWKS,	ATA66_SVWKS,	INIT_SVWKS,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_CSB5,	"ServerWorks CSB5",		PCI_SVWKS,	ATA66_SVWKS,	INIT_SVWKS,	NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}},	ON_BOARD,	0 },
	{DEVID_ITE8172G,"IT8172G",	PCI_IT8172,	NULL,	INIT_IT8172,	NULL,		{{0x00,0x00,0x00}, {0x40,0x00,0x01}},	ON_BOARD,	0 },
	{IDE_PCI_DEVID_NULL, "PCI_IDE",	NULL,		NULL,		NULL,		NULL,		{{0x00,0x00,0x00}, {0x00,0x00,0x00}}, 	ON_BOARD,	0 }};

/*
 * This allows offboard ide-pci cards the enable a BIOS, verify interrupt
 * settings of split-mirror pci-config space, place chipset into init-mode,
 * and/or preserve an interrupt if the card is not native ide support.
 */
static unsigned int __init ide_special_settings (struct pci_dev *dev, const char *name)
{
	switch(dev->device) {
		case PCI_DEVICE_ID_TTI_HPT366:
		case PCI_DEVICE_ID_PROMISE_20246:
		case PCI_DEVICE_ID_PROMISE_20262:
		case PCI_DEVICE_ID_PROMISE_20265:
		case PCI_DEVICE_ID_PROMISE_20267:
		case PCI_DEVICE_ID_PROMISE_20268:
		case PCI_DEVICE_ID_PROMISE_20270:
		case PCI_DEVICE_ID_PROMISE_20269:
		case PCI_DEVICE_ID_PROMISE_20275:
		case PCI_DEVICE_ID_PROMISE_20276:
		case PCI_DEVICE_ID_ARTOP_ATP850UF:
		case PCI_DEVICE_ID_ARTOP_ATP860:
		case PCI_DEVICE_ID_ARTOP_ATP860R:
			return dev->irq;
		default:
			break;
	}
	return 0;
}

/*
 * Match a PCI IDE port against an entry in ide_hwifs[],
 * based on io_base port if possible.
 */
static ide_hwif_t __init *ide_match_hwif (unsigned long io_base, byte bootable, const char *name)
{
	int h;
	ide_hwif_t *hwif;

	/*
	 * Look for a hwif with matching io_base specified using
	 * parameters to ide_setup().
	 */
	for (h = 0; h < MAX_HWIFS; ++h) {
		hwif = &ide_hwifs[h];
		if (hwif->io_ports[IDE_DATA_OFFSET] == io_base) {
			if (hwif->chipset == ide_generic)
				return hwif; /* a perfect match */
		}
	}
	/*
	 * Look for a hwif with matching io_base default value.
	 * If chipset is "ide_unknown", then claim that hwif slot.
	 * Otherwise, some other chipset has already claimed it..  :(
	 */
	for (h = 0; h < MAX_HWIFS; ++h) {
		hwif = &ide_hwifs[h];
		if (hwif->io_ports[IDE_DATA_OFFSET] == io_base) {
			if (hwif->chipset == ide_unknown)
				return hwif; /* match */
			printk("%s: port 0x%04lx already claimed by %s\n", name, io_base, hwif->name);
			return NULL;	/* already claimed */
		}
	}
	/*
	 * Okay, there is no hwif matching our io_base,
	 * so we'll just claim an unassigned slot.
	 * Give preference to claiming other slots before claiming ide0/ide1,
	 * just in case there's another interface yet-to-be-scanned
	 * which uses ports 1f0/170 (the ide0/ide1 defaults).
	 *
	 * Unless there is a bootable card that does not use the standard
	 * ports 1f0/170 (the ide0/ide1 defaults). The (bootable) flag.
	 */
	if (bootable) {
		for (h = 0; h < MAX_HWIFS; ++h) {
			hwif = &ide_hwifs[h];
			if (hwif->chipset == ide_unknown)
				return hwif;	/* pick an unused entry */
		}
	} else {
		for (h = 2; h < MAX_HWIFS; ++h) {
			hwif = ide_hwifs + h;
			if (hwif->chipset == ide_unknown)
				return hwif;	/* pick an unused entry */
		}
	}
	for (h = 0; h < 2; ++h) {
		hwif = ide_hwifs + h;
		if (hwif->chipset == ide_unknown)
			return hwif;	/* pick an unused entry */
	}
	printk("%s: too many IDE interfaces, no room in table\n", name);
	return NULL;
}

static int __init ide_setup_pci_baseregs (struct pci_dev *dev, const char *name)
{
	byte reg, progif = 0;

	/*
	 * Place both IDE interfaces into PCI "native" mode:
	 */
	if (pci_read_config_byte(dev, PCI_CLASS_PROG, &progif) || (progif & 5) != 5) {
		if ((progif & 0xa) != 0xa) {
			printk("%s: device not capable of full native PCI mode\n", name);
			return 1;
		}
		printk("%s: placing both ports into native PCI mode\n", name);
		(void) pci_write_config_byte(dev, PCI_CLASS_PROG, progif|5);
		if (pci_read_config_byte(dev, PCI_CLASS_PROG, &progif) || (progif & 5) != 5) {
			printk("%s: rewrite of PROGIF failed, wanted 0x%04x, got 0x%04x\n", name, progif|5, progif);
			return 1;
		}
	}
	/*
	 * Setup base registers for IDE command/control spaces for each interface:
	 */
	for (reg = 0; reg < 4; reg++) {
		struct resource *res = dev->resource + reg;
		if ((res->flags & IORESOURCE_IO) == 0)
			continue;
		if (!res->start) {
			printk("%s: Missing I/O address #%d\n", name, reg);
			return 1;
		}
	}
	return 0;
}

/*
 * ide_setup_pci_device() looks at the primary/secondary interfaces
 * on a PCI IDE device and, if they are enabled, prepares the IDE driver
 * for use with them.  This generic code works for most PCI chipsets.
 *
 * One thing that is not standardized is the location of the
 * primary/secondary interface "enable/disable" bits.  For chipsets that
 * we "know" about, this information is in the ide_pci_device_t struct;
 * for all other chipsets, we just assume both interfaces are enabled.
 */
static void __init ide_setup_pci_device (struct pci_dev *dev, ide_pci_device_t *d)
{
	unsigned int port, at_least_one_hwif_enabled = 0, autodma = 0, pciirq = 0;
	unsigned short pcicmd = 0, tried_config = 0;
	byte tmp = 0;
	ide_hwif_t *hwif, *mate = NULL;
	unsigned int class_rev;
	static int secondpdc = 0;

#ifdef CONFIG_IDEDMA_AUTO
	if (!noautodma)
		autodma = 1;
#endif

	if (d->init_hwif == IDE_NO_DRIVER) {
		printk(KERN_WARNING "%s: detected chipset, but driver not compiled in!\n", d->name);
		d->init_hwif = NULL;
	}

	if (pci_enable_device(dev)) {
		if(pci_enable_device_bars(dev, 1<<4))
		{
			printk(KERN_WARNING "%s: (ide_setup_pci_device:) Could not enable device.\n", d->name);
			return;
		}
		printk(KERN_INFO "%s: BIOS setup was incomplete.\n", d->name);
	}

check_if_enabled:
	if (pci_read_config_word(dev, PCI_COMMAND, &pcicmd)) {
		printk("%s: error accessing PCI regs\n", d->name);
		return;
	}
	if (!(pcicmd & PCI_COMMAND_IO)) {	/* is device disabled? */
		/*
		 * PnP BIOS was *supposed* to have set this device up for us,
		 * but we can do it ourselves, so long as the BIOS has assigned an IRQ
		 *  (or possibly the device is using a "legacy header" for IRQs).
		 * Maybe the user deliberately *disabled* the device,
		 * but we'll eventually ignore it again if no drives respond.
		 */
		if (tried_config++
		 || ide_setup_pci_baseregs(dev, d->name)
		 || pci_write_config_word(dev, PCI_COMMAND, pcicmd | PCI_COMMAND_IO)) {
			printk("%s: device disabled (BIOS)\n", d->name);
			return;
		}
		autodma = 0;	/* default DMA off if we had to configure it here */
		goto check_if_enabled;
	}
	if (tried_config)
		printk("%s: device enabled (Linux)\n", d->name);

	pci_read_config_dword(dev, PCI_CLASS_REVISION, &class_rev);
	class_rev &= 0xff;

	if (IDE_PCI_DEVID_EQ(d->devid, DEVID_HPT34X)) {
		/* see comments in hpt34x.c on why..... */
		char *chipset_names[] = {"HPT343", "HPT345"};
		strcpy(d->name, chipset_names[(pcicmd & PCI_COMMAND_MEMORY) ? 1 : 0]);
		d->bootable = (pcicmd & PCI_COMMAND_MEMORY) ? OFF_BOARD : NEVER_BOARD;
	}

	printk("%s: chipset revision %d\n", d->name, class_rev);

	/*
	 * Can we trust the reported IRQ?
	 */
	pciirq = dev->irq;
	
	if (dev->class >> 8 == PCI_CLASS_STORAGE_RAID)
	{
	    /*  By rights we want to ignore these, but the Promise Fastrak
		 *	people have some strange ideas about proprietary so we have
		 *	to act otherwise on those. The supertrak however we need
		 *	to skip 
		 */
		if (IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20265))
		{
			printk(KERN_INFO "ide: Found promise 20265 in RAID mode.\n");
			if(dev->bus->self && dev->bus->self->vendor == PCI_VENDOR_ID_INTEL &&
			   dev->bus->self->device == PCI_DEVICE_ID_INTEL_I960)
			{
				printk(KERN_INFO "ide: Skipping Promise PDC20265 attached to I2O RAID controller.\n");
				return;
			}
		}
		/* Its attached to something else, just a random bridge.
		   Suspect a fastrak and fall through */
	}

	if ((dev->class & ~(0xfa)) != ((PCI_CLASS_STORAGE_IDE << 8) | 5)) {
		printk("%s: not 100%% native mode: will probe irqs later\n", d->name);
		/*
		 * This allows offboard ide-pci cards the enable a BIOS,
		 * verify interrupt settings of split-mirror pci-config
		 * space, place chipset into init-mode, and/or preserve
		 * an interrupt if the card is not native ide support.
		 */
		pciirq = (d->init_chipset) ? d->init_chipset(dev, d->name) : ide_special_settings(dev, d->name);
	} else if (tried_config) {
		printk("%s: will probe irqs later\n", d->name);
		pciirq = 0;
	} else if (!pciirq) {
		printk("%s: bad irq (%d): will probe later\n", d->name, pciirq);
		pciirq = 0;
	} else {
		if (d->init_chipset)
			(void) d->init_chipset(dev, d->name);
#ifdef __sparc__
		printk("%s: 100%% native mode on irq %s\n",
		       d->name, __irq_itoa(pciirq));
#else
		printk("%s: 100%% native mode on irq %d\n", d->name, pciirq);
#endif
	}

	/*
	 * Set up the IDE ports
	 */
	for (port = 0; port <= 1; ++port) {
		unsigned long base = 0, ctl = 0;
		ide_pci_enablebit_t *e = &(d->enablebits[port]);
	
		/* 
		 * If this is a Promise FakeRaid controller, the 2nd controller will be marked as 
		 * disabled while it is actually there and enabled by the bios for raid purposes. 
		 * Skip the normal "is it enabled" test for those.
		 */
		if ((IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20265)) && (secondpdc++==1) && (port==1)  ) 
			goto controller_ok;
		if ((IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20262)) && (secondpdc++==1) && (port==1)  ) 
			goto controller_ok;
			
		if (e->reg && (pci_read_config_byte(dev, e->reg, &tmp) || (tmp & e->mask) != e->val))
			continue;	/* port not enabled */
controller_ok:			
		if (IDE_PCI_DEVID_EQ(d->devid, DEVID_HPT366) && (port) && (class_rev < 0x03))
			return;
		if ((dev->class >> 8) != PCI_CLASS_STORAGE_IDE || (dev->class & (port ? 4 : 1)) != 0) {
			ctl  = dev->resource[(2*port)+1].start;
			base = dev->resource[2*port].start;
			if (!(ctl & PCI_BASE_ADDRESS_IO_MASK) ||
			    !(base & PCI_BASE_ADDRESS_IO_MASK)) {
				printk("%s: IO baseregs (BIOS) are reported as MEM, report to <andre@linux-ide.org>.\n", d->name);
#if 0
				/* FIXME! This really should check that it really gets the IO/MEM part right! */
				continue;
#endif
			}
		}
		if ((ctl && !base) || (base && !ctl)) {
			printk("%s: inconsistent baseregs (BIOS) for port %d, skipping\n", d->name, port);
			continue;
		}
		if (!ctl)
			ctl = port ? 0x374 : 0x3f4;	/* use default value */
		if (!base)
			base = port ? 0x170 : 0x1f0;	/* use default value */
		if ((hwif = ide_match_hwif(base, d->bootable, d->name)) == NULL)
			continue;	/* no room in ide_hwifs[] */
		if (hwif->io_ports[IDE_DATA_OFFSET] != base) {
			ide_init_hwif_ports(&hwif->hw, base, (ctl | 2), NULL);
			memcpy(hwif->io_ports, hwif->hw.io_ports, sizeof(hwif->io_ports));
			hwif->noprobe = !hwif->io_ports[IDE_DATA_OFFSET];
		}
		hwif->chipset = ide_pci;
		hwif->pci_dev = dev;
		hwif->pci_devid = d->devid;
		hwif->channel = port;
		if (!hwif->irq)
			hwif->irq = pciirq;
		if (mate) {
			hwif->mate = mate;
			mate->mate = hwif;
			if (IDE_PCI_DEVID_EQ(d->devid, DEVID_AEC6210)) {
				hwif->serialized = 1;
				mate->serialized = 1;
			}
		}
		if (IDE_PCI_DEVID_EQ(d->devid, DEVID_UM8886A) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_UM8886BF) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_UM8673F)) {
			hwif->irq = hwif->channel ? 15 : 14;
			goto bypass_umc_dma;
		}
		if (IDE_PCI_DEVID_EQ(d->devid, DEVID_MPIIX))
			goto bypass_piix_dma;
		if (IDE_PCI_DEVID_EQ(d->devid, DEVID_PDCADMA))
			goto bypass_legacy_dma;
		if (hwif->udma_four) {
			printk("%s: ATA-66/100 forced bit set (WARNING)!!\n", d->name);
		} else {
			hwif->udma_four = (d->ata66_check) ? d->ata66_check(hwif) : 0;
		}
#ifdef CONFIG_BLK_DEV_IDEDMA
		if (IDE_PCI_DEVID_EQ(d->devid, DEVID_SIS5513) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_AEC6260) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_PIIX4NX) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_HPT34X)  ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_VIA_IDE) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_MR_IDE)  ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_VP_IDE))
			autodma = 0;
		if (autodma)
			hwif->autodma = 1;

		if (IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20246) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20262) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20265) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20267) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20268) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20270) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20269) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20275) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20276) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_AEC6210) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_AEC6260) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_AEC6260R) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_HPT34X) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_HPT366) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_CS5530) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_CY82C693) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_CMD646) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_CMD648) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_CMD649) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_CMD680) ||
		    IDE_PCI_DEVID_EQ(d->devid, DEVID_OSB4) ||
		    ((dev->class >> 8) == PCI_CLASS_STORAGE_IDE && (dev->class & 0x80))) {
			unsigned long dma_base = ide_get_or_set_dma_base(hwif, (!mate && d->extra) ? d->extra : 0, d->name);
			if (dma_base && !(pcicmd & PCI_COMMAND_MASTER)) {
				/*
 	 			 * Set up BM-DMA capability (PnP BIOS should have done this)
 	 			 */
		    		if (!IDE_PCI_DEVID_EQ(d->devid, DEVID_CS5530))
					hwif->autodma = 0;	/* default DMA off if we had to configure it here */
				(void) pci_write_config_word(dev, PCI_COMMAND, pcicmd | PCI_COMMAND_MASTER);
				if (pci_read_config_word(dev, PCI_COMMAND, &pcicmd) || !(pcicmd & PCI_COMMAND_MASTER)) {
					printk("%s: %s error updating PCICMD\n", hwif->name, d->name);
					dma_base = 0;
				}
			}
			if (dma_base) {
				if (d->dma_init) {
					d->dma_init(hwif, dma_base);
				} else {
					ide_setup_dma(hwif, dma_base, 8);
				}
			} else {
				printk("%s: %s Bus-Master DMA disabled (BIOS)\n", hwif->name, d->name);
			}
		}
#endif	/* CONFIG_BLK_DEV_IDEDMA */
bypass_legacy_dma:
bypass_piix_dma:
bypass_umc_dma:
		if (d->init_hwif)  /* Call chipset-specific routine for each enabled hwif */
			d->init_hwif(hwif);
		mate = hwif;
		at_least_one_hwif_enabled = 1;
	}
	if (!at_least_one_hwif_enabled)
		printk("%s: neither IDE port enabled (BIOS)\n", d->name);
}

static void __init pdc20270_device_order_fixup (struct pci_dev *dev, ide_pci_device_t *d)
{
	struct pci_dev *dev2 = NULL, *findev;
	ide_pci_device_t *d2;

	if ((dev->bus->self &&
	     dev->bus->self->vendor == PCI_VENDOR_ID_DEC) &&
	    (dev->bus->self->device == PCI_DEVICE_ID_DEC_21150)) {
		if (PCI_SLOT(dev->devfn) & 2) {
			return;
		}
		d->extra = 0;
		pci_for_each_dev(findev) {
			if ((findev->vendor == dev->vendor) &&
			    (findev->device == dev->device) &&
			    (PCI_SLOT(findev->devfn) & 2)) {
				byte irq = 0, irq2 = 0;
				dev2 = findev;
				pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &irq);
				pci_read_config_byte(dev2, PCI_INTERRUPT_LINE, &irq2);
                                if (irq != irq2) {
					dev2->irq = dev->irq;
                                        pci_write_config_byte(dev2, PCI_INTERRUPT_LINE, irq);
                                }

			}
		}
	}

	printk("%s: IDE controller on PCI bus %02x dev %02x\n", d->name, dev->bus->number, dev->devfn);
	ide_setup_pci_device(dev, d);
	if (!dev2)
		return;
	d2 = d;
	printk("%s: IDE controller on PCI bus %02x dev %02x\n", d2->name, dev2->bus->number, dev2->devfn);
	ide_setup_pci_device(dev2, d2);
}

static void __init hpt366_device_order_fixup (struct pci_dev *dev, ide_pci_device_t *d)
{
	struct pci_dev *dev2 = NULL, *findev;
	ide_pci_device_t *d2;
	unsigned char pin1 = 0, pin2 = 0;
	unsigned int class_rev;
	char *chipset_names[] = {"HPT366", "HPT366", "HPT368", "HPT370", "HPT370A", "HPT372"};

	if (PCI_FUNC(dev->devfn) & 1)
		return;

	pci_read_config_dword(dev, PCI_CLASS_REVISION, &class_rev);
	class_rev &= 0xff;
	if (class_rev > 5)
		class_rev = 5;
	
	strcpy(d->name, chipset_names[class_rev]);

	switch(class_rev) {
		case 4:
		case 3:	printk("%s: IDE controller on PCI bus %02x dev %02x\n", d->name, dev->bus->number, dev->devfn);
			ide_setup_pci_device(dev, d);
			return;
		default:	break;
	}

	pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &pin1);
	pci_for_each_dev(findev) {
		if ((findev->vendor == dev->vendor) &&
		    (findev->device == dev->device) &&
		    ((findev->devfn - dev->devfn) == 1) &&
		    (PCI_FUNC(findev->devfn) & 1)) {
			dev2 = findev;
			pci_read_config_byte(dev2, PCI_INTERRUPT_PIN, &pin2);
			hpt363_shared_pin = (pin1 != pin2) ? 1 : 0;
			hpt363_shared_irq = (dev->irq == dev2->irq) ? 1 : 0;
			if (hpt363_shared_pin && hpt363_shared_irq) {
				d->bootable = ON_BOARD;
				printk("%s: onboard version of chipset, pin1=%d pin2=%d\n", d->name, pin1, pin2);
#if 0
				/* I forgot why I did this once, but it fixed something. */
				pci_write_config_byte(dev2, PCI_INTERRUPT_PIN, dev->irq);
				printk("PCI: %s: Fixing interrupt %d pin %d to ZERO \n", d->name, dev2->irq, pin2);
				pci_write_config_byte(dev2, PCI_INTERRUPT_LINE, 0);
#endif
			}
			break;
		}
	}
	printk("%s: IDE controller on PCI bus %02x dev %02x\n", d->name, dev->bus->number, dev->devfn);
	ide_setup_pci_device(dev, d);
	if (!dev2)
		return;
	d2 = d;
	printk("%s: IDE controller on PCI bus %02x dev %02x\n", d2->name, dev2->bus->number, dev2->devfn);
	ide_setup_pci_device(dev2, d2);
}

/*
 * ide_scan_pcibus() gets invoked at boot time from ide.c.
 * It finds all PCI IDE controllers and calls ide_setup_pci_device for them.
 */
void __init ide_scan_pcidev (struct pci_dev *dev)
{
	ide_pci_devid_t		devid;
	ide_pci_device_t	*d;

	devid.vid = dev->vendor;
	devid.did = dev->device;
	for (d = ide_pci_chipsets; d->devid.vid && !IDE_PCI_DEVID_EQ(d->devid, devid); ++d);
	if (d->init_hwif == IDE_IGNORE)
		printk("%s: ignored by ide_scan_pci_device() (uses own driver)\n", d->name);
	else if (IDE_PCI_DEVID_EQ(d->devid, DEVID_OPTI621V) && !(PCI_FUNC(dev->devfn) & 1))
		return;
	else if (IDE_PCI_DEVID_EQ(d->devid, DEVID_CY82C693) && (!(PCI_FUNC(dev->devfn) & 1) || !((dev->class >> 8) == PCI_CLASS_STORAGE_IDE)))
		return;	/* CY82C693 is more than only a IDE controller */
	else if (IDE_PCI_DEVID_EQ(d->devid, DEVID_ITE8172G) && (!(PCI_FUNC(dev->devfn) & 1) || !((dev->class >> 8) == PCI_CLASS_STORAGE_IDE)))
		return;	/* IT8172G is also more than only an IDE controller */
	else if (IDE_PCI_DEVID_EQ(d->devid, DEVID_UM8886A) && !(PCI_FUNC(dev->devfn) & 1))
		return;	/* UM8886A/BF pair */
	else if (IDE_PCI_DEVID_EQ(d->devid, DEVID_HPT366))
		hpt366_device_order_fixup(dev, d);
	else if (IDE_PCI_DEVID_EQ(d->devid, DEVID_PDC20270))
		pdc20270_device_order_fixup(dev, d);
	else if (!IDE_PCI_DEVID_EQ(d->devid, IDE_PCI_DEVID_NULL) || (dev->class >> 8) == PCI_CLASS_STORAGE_IDE) {
		if (IDE_PCI_DEVID_EQ(d->devid, IDE_PCI_DEVID_NULL))
			printk("%s: unknown IDE controller on PCI bus %02x device %02x, VID=%04x, DID=%04x\n",
			       d->name, dev->bus->number, dev->devfn, devid.vid, devid.did);
		else
			printk("%s: IDE controller on PCI bus %02x dev %02x\n", d->name, dev->bus->number, dev->devfn);
		ide_setup_pci_device(dev, d);
	}
}

void __init ide_scan_pcibus (int scan_direction)
{
	struct pci_dev *dev;

	if (!scan_direction) {
		pci_for_each_dev(dev) {
			ide_scan_pcidev(dev);
		}
	} else {
		pci_for_each_dev_reverse(dev) {
			ide_scan_pcidev(dev);
		}
	}
}
