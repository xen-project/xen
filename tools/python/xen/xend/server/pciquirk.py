from xen.xend.XendLogging import log
from xen.xend.XendError import XendError, VmError
import sys
import os.path
from xen.xend.sxp import *

QUIRK_SYSFS_NODE = "/sys/bus/pci/drivers/pciback/quirks"
QUIRK_CONFIG_FILE = "/etc/xen/xend-pci-quirks.sxp"
PERMISSIVE_CONFIG_FILE = "/etc/xen/xend-pci-permissive.sxp"
PERMISSIVE_SYSFS_NODE = "/sys/bus/pci/drivers/pciback/permissive"

class PCIQuirk:
    def __init__( self, vendor, device, subvendor, subdevice, domain, bus, slot, func):
        self.vendor = vendor
        self.device = device
        self.subvendor = subvendor
        self.subdevice = subdevice
        self.domain = domain
        self.bus = bus
        self.slot = slot
        self.func = func

        self.devid = "%04x:%04x:%04x:%04x" % (vendor, device, subvendor, subdevice)
        self.pciid = "%04x:%02x:%02x.%01x" % (domain, bus, slot, func)
        self.quirks = self.__getQuirksByID()

        self.__sendQuirks()
        self.__sendPermDevs()

    def __matchPCIdev( self, list ):
        ret = False
        if list == None:
            return False
        for id in list:
            if id.startswith(self.devid[:9]): # id's vendor and device ID match
                skey = id.split(':')
                size = len(skey)
                if (size == 2):		# subvendor/subdevice not suplied
                    ret = True
                    break
                elif (size == 4):	# check subvendor/subdevice
                    # check subvendor
                    subven = '%04x' % self.subvendor
                    if ((skey[2] != 'FFFF') and 
                        (skey[2] != 'ffff') and 
                        (skey[2] != subven)):
                            continue
                    # check subdevice
                    subdev = '%04x' % self.subdevice
                    if ((skey[3] != 'FFFF') and 
                        (skey[3] != 'ffff') and 
                        (skey[3] != subdev)):
                            continue
                    ret = True
                    break
                else:
                    log.debug("WARNING: invalid configuration entry: %s" % id)
                    ret = False
                    break
        return ret
        
    def __getQuirksByID( self ):
        if os.path.exists(QUIRK_CONFIG_FILE):
            try:
                fin = file(QUIRK_CONFIG_FILE, 'rb')
                try:
                    pci_quirks_config = parse(fin)
                finally:
                    fin.close()
                if pci_quirks_config is None:
                    pci_quirks_config = ['xend-pci-quirks']
                else:
                    pci_quirks_config.insert(0, 'xend-pci-quirks')
                self.pci_quirks_config = pci_quirks_config
            except Exception, ex:
                raise XendError("Reading config file %s: %s" %
                                (QUIRK_CONFIG_FILE, str(ex)))
        else:
            log.info("Config file does not exist: %s" % QUIRK_CONFIG_FILE)
            self.pci_quirks_config = ['xend-pci-quirks']

        devices = children(self.pci_quirks_config)
        for dev in devices:
            ids = child_at(child(dev,'pci_ids'),0)
            fields = child_at(child(dev,'pci_config_space_fields'),0)
            if self.__matchPCIdev( ids ):
                log.info("Quirks found for PCI device [%s]" % self.devid)
                return fields

        log.info("NO quirks found for PCI device [%s]" % self.devid)
        return []

    def __sendQuirks(self):
        for quirk in self.quirks:
            log.debug("Quirk Info: %04x:%02x:%02x.%1x-%s" % (self.domain,
                      self.bus, self.slot, self.func, quirk))
            try:
                f = file(QUIRK_SYSFS_NODE ,"w")
                f.write( "%04x:%02x:%02x.%1x-%s" % (self.domain, self.bus,
                        self.slot, self.func, quirk) )
                f.close()
            except Exception, e:
                raise VmError("pci: failed to open/write/close quirks " +
                              "sysfs node - " + str(e))

    def __devIsUnconstrained( self ):
        if os.path.exists(PERMISSIVE_CONFIG_FILE):
            try:
                fin = file(PERMISSIVE_CONFIG_FILE, 'rb')
                try:
                    pci_perm_dev_config = parse(fin)
                finally:
                    fin.close()
                if pci_perm_dev_config is None:
                    pci_perm_dev_config = ['']
                else:
                    pci_perm_dev_config.insert(0, '')
                self.pci_perm_dev_config = pci_perm_dev_config
            except Exception, ex:
                raise XendError("Reading config file %s: %s" %
                                (PERMISSIVE_CONFIG_FILE,str(ex)))
        else:
            log.info("Config file does not exist: %s" % PERMISSIVE_CONFIG_FILE)
            self.pci_perm_dev_config = ['xend-pci-perm-devs']

        devices = child_at(child(pci_perm_dev_config, 'unconstrained_dev_ids'),0)
        if self.__matchPCIdev( devices ):
            log.debug("Permissive mode enabled for PCI device [%s]" %
                      self.devid)
            return True
        log.debug("Permissive mode NOT enabled for PCI device [%s]" %
                  self.devid)
        return False

    def __sendPermDevs(self):
        if self.__devIsUnconstrained( ):
            log.debug("Unconstrained device: %04x:%02x:%02x.%1x" %
                      (self.domain, self.bus, self.slot, self.func))
            try:
                f = file(PERMISSIVE_SYSFS_NODE ,"w")
                f.write( "%04x:%02x:%02x.%1x" % (self.domain, self.bus,
                                                 self.slot, self.func))
                f.close()
            except Exception, e:
                raise VmError("pci: failed to open/write/close permissive " +
                              "sysfs node: " + str(e))
