/*
 * PCI Backend - Common data structures for overriding the configuration space
 *
 * Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */

#ifndef __XEN_PCIBACK_CONF_SPACE_H__
#define __XEN_PCIBACK_CONF_SPACE_H__

#include <linux/list.h>

typedef void *(*conf_field_init) (struct pci_dev * dev, int offset);
typedef void (*conf_field_reset) (struct pci_dev * dev, int offset, void *data);
typedef void (*conf_field_free) (struct pci_dev * dev, int offset, void *data);

typedef int (*conf_dword_write) (struct pci_dev * dev, int offset, u32 value,
				 void *data);
typedef int (*conf_word_write) (struct pci_dev * dev, int offset, u16 value,
				void *data);
typedef int (*conf_byte_write) (struct pci_dev * dev, int offset, u8 value,
				void *data);
typedef int (*conf_dword_read) (struct pci_dev * dev, int offset, u32 * value,
				void *data);
typedef int (*conf_word_read) (struct pci_dev * dev, int offset, u16 * value,
			       void *data);
typedef int (*conf_byte_read) (struct pci_dev * dev, int offset, u8 * value,
			       void *data);

/* These are the fields within the configuration space which we
 * are interested in intercepting reads/writes to and changing their
 * values.
 */
struct config_field {
	unsigned int     offset;
	unsigned int     size;
	conf_field_init  init;
	conf_field_reset reset;
	conf_field_free  release;
	union {
		struct {
			conf_dword_write write;
			conf_dword_read read;
		} dw;
		struct {
			conf_word_write write;
			conf_word_read read;
		} w;
		struct {
			conf_byte_write write;
			conf_byte_read read;
		} b;
	} u;
};

struct config_field_entry {
	struct list_head list;
	struct config_field *field;
	void *data;
};

/* Add fields to a device - the add_fields macro expects to get a pointer to
 * the first entry in an array (of which the ending is marked by size==0)
 */
int pciback_config_add_field(struct pci_dev *dev, struct config_field *field);
static inline int pciback_config_add_fields(struct pci_dev *dev,
					    struct config_field *field)
{
	int i, err = 0;
	for (i = 0; field[i].size != 0; i++) {
		err = pciback_config_add_field(dev, &field[i]);
		if (err)
			break;
	}
	return err;
}

/* Initializers which add fields to the virtual configuration space
 * ** We could add initializers to allow a guest domain to touch
 * the capability lists (for power management, the AGP bridge, etc.)
 */
int pciback_config_header_add_fields(struct pci_dev *dev);

/* Read/Write the real configuration space */
int pciback_read_config_byte(struct pci_dev *dev, int offset, u8 * value,
			     void *data);
int pciback_read_config_word(struct pci_dev *dev, int offset, u16 * value,
			     void *data);
int pciback_read_config_dword(struct pci_dev *dev, int offset, u32 * value,
			      void *data);
int pciback_write_config_byte(struct pci_dev *dev, int offset, u8 value,
			      void *data);
int pciback_write_config_word(struct pci_dev *dev, int offset, u16 value,
			      void *data);
int pciback_write_config_dword(struct pci_dev *dev, int offset, u32 value,
			       void *data);

#endif				/* __XEN_PCIBACK_CONF_SPACE_H__ */
