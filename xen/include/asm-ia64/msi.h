#ifndef __ASM_MSI_H
#define __ASM_MSI_H

/*
 * MSI Defined Data Structures
 */
#define MSI_ADDRESS_HEADER		0xfee
#define MSI_ADDRESS_HEADER_SHIFT	12
#define MSI_ADDRESS_HEADER_MASK		0xfff000
#define MSI_ADDRESS_DEST_ID_MASK	0xfff0000f
#define MSI_TARGET_CPU_MASK		0xff
#define MSI_TARGET_CPU_SHIFT		4
#define MSI_DELIVERY_MODE		0
#define MSI_LEVEL_MODE			1	/* Edge always assert */
#define MSI_TRIGGER_MODE		0	/* MSI is edge sensitive */
#define MSI_PHYSICAL_MODE		0
#define MSI_LOGICAL_MODE		1
#define MSI_REDIRECTION_HINT_MODE	0

#endif /* __ASM_MSI_H */
