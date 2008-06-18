/*
 * Changes to PCI emulation made by Marathon Technologies, June 2008
 */

typedef struct PCI_EMULATION_INFO_t {
    struct PCI_EMULATION_INFO_t *next;
    char name[32];
    unsigned int vendorid;
    unsigned int deviceid;
    unsigned int command;
    unsigned int status;
    unsigned int revision;
    unsigned int classcode;
    unsigned int headertype;
    unsigned int subvendorid;
    unsigned int subsystemid;
    unsigned int interruputline;
    unsigned int interruputpin;
}   PCI_EMULATION_INFO;
    
void parse_pci_emulation_info(char *config_text, PCI_EMULATION_INFO *pci_emulation_info);
void pci_emulation_init(PCIBus *bus, PCI_EMULATION_INFO *pci_emulation_info);

extern PCI_EMULATION_INFO *PciEmulationInfoHead;
