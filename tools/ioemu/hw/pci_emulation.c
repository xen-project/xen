/*
 * Changes to PCI emulation made by Marathon Technologies, June 2008
 */

#include "vl.h"

typedef struct {
    PCIDevice dev;
}   PCI_EMULATION_State;

void parse_pci_emulation_info(char *config_text, PCI_EMULATION_INFO *pci_emulation_info)
{
    char *p;
    int i;
    int ret;
    for (p = config_text, i = 0; *p != '\0'; p++) {
        if (*p == ':') {
            break;
        }
        if (i < sizeof(pci_emulation_info->name) - 1) {
            pci_emulation_info->name[i] = *p;
            i++;
        }
    }
    pci_emulation_info->name[i] = '\0';
    if (*p == '\0') return;
    p++;
    ret = sscanf(p, "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
                 &(pci_emulation_info->vendorid),
                 &(pci_emulation_info->deviceid),
                 &(pci_emulation_info->command),
                 &(pci_emulation_info->status),
                 &(pci_emulation_info->revision),
                 &(pci_emulation_info->classcode),
                 &(pci_emulation_info->headertype),
                 &(pci_emulation_info->subvendorid),
                 &(pci_emulation_info->subsystemid),
                 &(pci_emulation_info->interruputline),
                 &(pci_emulation_info->interruputpin));
#ifdef DEBUG
    fprintf(logfile, "qemu: pciemulation %s:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x\n",
            pci_emulation_info->name,
            pci_emulation_info->vendorid,
            pci_emulation_info->deviceid,
            pci_emulation_info->command,
            pci_emulation_info->status,
            pci_emulation_info->revision,
            pci_emulation_info->classcode,
            pci_emulation_info->headertype,
            pci_emulation_info->subvendorid,
            pci_emulation_info->subsystemid,
            pci_emulation_info->interruputline,
            pci_emulation_info->interruputpin);
#endif
    return;
}

static void pci_emulation_save(QEMUFile *f, void *opaque)
{
    PCIDevice *d = opaque;

    pci_device_save(d, f);
}

static int pci_emulation_load(QEMUFile *f, void *opaque, int version_id)
{
    PCIDevice *d = opaque;

    if (version_id != 1)
        return -EINVAL;

    return pci_device_load(d, f);
}


void pci_emulation_init(PCIBus *bus, PCI_EMULATION_INFO *pci_emulation_info)
{
    int instance_id;
    PCI_EMULATION_State *d;
    uint8_t *pci_conf;

#ifdef DEBUG
    fprintf(logfile, "qemu: pciinit\n");
#endif
    
    d = (PCI_EMULATION_State *)pci_register_device(bus,
                                                   pci_emulation_info->name, 
                                                   sizeof(PCI_EMULATION_State),
                                                   -1, 
                                                    NULL, NULL);
    pci_conf = d->dev.config;
    pci_conf[0x00] = pci_emulation_info->vendorid & 0xff;
    pci_conf[0x01] = (pci_emulation_info->vendorid & 0xff00) >> 8;
    pci_conf[0x02] = pci_emulation_info->deviceid & 0xff;
    pci_conf[0x03] = (pci_emulation_info->deviceid & 0xff00) >> 8;
    pci_conf[0x04] = pci_emulation_info->command & 0xff;
    pci_conf[0x05] = (pci_emulation_info->command & 0xff00) >> 8;
    pci_conf[0x06] = pci_emulation_info->status & 0xff;
    pci_conf[0x07] = (pci_emulation_info->status & 0xff00) >> 8;
    pci_conf[0x08] = pci_emulation_info->revision & 0xff;
    pci_conf[0x09] = pci_emulation_info->classcode & 0xff;
    pci_conf[0x0a] = (pci_emulation_info->classcode & 0xff00) >> 8;
    pci_conf[0x0b] = (pci_emulation_info->classcode & 0xff0000) >> 16;
    pci_conf[0x0e] = pci_emulation_info->headertype & 0xff;
    pci_conf[0x2c] = pci_emulation_info->subvendorid & 0xff;
    pci_conf[0x2d] = (pci_emulation_info->subvendorid & 0xff00) >> 8;
    pci_conf[0x2e] = pci_emulation_info->subsystemid & 0xff;
    pci_conf[0x2f] = (pci_emulation_info->subsystemid & 0xff00) >> 8;
    pci_conf[0x3c] = pci_emulation_info->interruputline & 0xff;
    pci_conf[0x3d] = pci_emulation_info->interruputpin & 0xff;

    instance_id = pci_bus_num(bus) << 8 | d->dev.devfn;
    register_savevm(pci_emulation_info->name, instance_id,
                    1, pci_emulation_save, pci_emulation_load, d);


    return;    
}
