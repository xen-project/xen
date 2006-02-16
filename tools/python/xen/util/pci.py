#!/usr/bin/env python
#
# PCI Device Information Class
# - Helps obtain information about which I/O resources a PCI device needs
#
#   Author: Ryan Wilson <hap9@epoch.ncsc.mil>

import sys
import os, os.path

PROC_MNT_PATH = '/proc/mounts'
PROC_PCI_PATH = '/proc/bus/pci/devices'
PROC_PCI_NUM_RESOURCES = 7

SYSFS_PCI_DEVS_PATH = '/bus/pci/devices'
SYSFS_PCI_DEV_RESOURCE_PATH = '/resource'
SYSFS_PCI_DEV_IRQ_PATH = '/irq'
SYSFS_PCI_DEV_DRIVER_DIR_PATH = '/driver'

PCI_BAR_IO = 0x01
PCI_BAR_IO_MASK = ~0x03
PCI_BAR_MEM_MASK = ~0x0f

# Definitions from Linux: include/linux/pci.h
def PCI_DEVFN(slot, func):
    return ((((slot) & 0x1f) << 3) | ((func) & 0x07))

def find_sysfs_mnt():
    mounts_file = open(PROC_MNT_PATH,'r')

    for line in mounts_file:
        sline = line.split()
        if len(sline)<3:
            continue

        if sline[2]=='sysfs':
            return sline[1]

    return None

class PciDeviceNotFoundError(Exception):
    def __init__(self,domain,bus,slot,func):
        self.domain = domain
        self.bus = bus
        self.slot = slot
        self.func = func
        self.name = "%04x:%02x:%02x.%01x"%(domain, bus, slot, func)
    
    def __str__(self):
        return ('PCI Device %s Not Found' % (self.name))

class PciDeviceParseError(Exception):
    def __init__(self,msg):
        self.message = msg
    def __str__(self):
        return 'Error Parsing PCI Device Info: '+self.message

class PciDevice:
    def __init__(self, domain, bus, slot, func):
        self.domain = domain
        self.bus = bus
        self.slot = slot
        self.func = func
        self.name = "%04x:%02x:%02x.%01x"%(domain, bus, slot, func)
        self.irq = 0
        self.iomem = []
        self.ioports = []
        self.driver = None

        if not self.get_info_from_sysfs():
            self.get_info_from_proc()

    def get_info_from_sysfs(self):
        try:
            sysfs_mnt = find_sysfs_mnt()
        except IOError, (errno, strerr):
            raise PciDeviceParseError(('Failed to locate sysfs mount: %s (%d)' %
                (PROC_PCI_PATH, strerr, errno)))

        if sysfs_mnt == None:
            return False

        path = sysfs_mnt+SYSFS_PCI_DEVS_PATH+'/'+ \
                self.name+SYSFS_PCI_DEV_RESOURCE_PATH
        try:
            resource_file = open(path,'r')

            for i in range(7):
                line = resource_file.readline()
                sline = line.split()
                if len(sline)<3:
                    continue

                start = int(sline[0],16)
                end = int(sline[1],16)
                flags = int(sline[2],16)
                size = end-start+1

                if start!=0:
                    if flags&PCI_BAR_IO:
                        self.ioports.append( (start,size) )
                    else:
                        self.iomem.append( (start,size) )

        except IOError, (errno, strerr):
            raise PciDeviceParseError(('Failed to open & read %s: %s (%d)' %
                (path, strerr, errno)))

        path = sysfs_mnt+SYSFS_PCI_DEVS_PATH+'/'+ \
                self.name+SYSFS_PCI_DEV_IRQ_PATH
        try:
            self.irq = int(open(path,'r').readline())
        except IOError, (errno, strerr):
            raise PciDeviceParseError(('Failed to open & read %s: %s (%d)' %
                (path, strerr, errno)))

        path = sysfs_mnt+SYSFS_PCI_DEVS_PATH+'/'+ \
                self.name+SYSFS_PCI_DEV_DRIVER_DIR_PATH
        try:
            self.driver = os.path.basename(os.readlink(path))
        except IOError, (errno, strerr):
            raise PciDeviceParseError(('Failed to read %s: %s (%d)' %
                (path, strerr, errno)))

        return True
        
    def get_info_from_proc(self):
        bus_devfn = '%02x%02x' % (self.bus,PCI_DEVFN(self.slot,self.func))

        # /proc/bus/pci/devices doesn't expose domains
        if self.domain!=0:
            raise PciDeviceParseError("Can't yet detect resource usage by "+
                    "devices in other domains through proc!")

        try:
            proc_pci_file = open(PROC_PCI_PATH,'r')
        except IOError, (errno, strerr):
            raise PciDeviceParseError(('Failed to open %s: %s (%d)' %
                (PROC_PCI_PATH, strerr, errno)))

        for line in proc_pci_file:
            sline = line.split()
            if len(sline)<(PROC_PCI_NUM_RESOURCES*2+3):
                continue

            if sline[0]==bus_devfn:
                self.dissect_proc_pci_line(sline)
                break
        else:
            raise PciDeviceNotFoundError(self.domain, self.bus,
                    self.slot, self.func)

    def dissect_proc_pci_line(self, sline):
        self.irq = int(sline[2],16)
        start_idx = 3
        for i in range(PROC_PCI_NUM_RESOURCES):
            flags = int(sline[start_idx+i],16)
            size = int(sline[start_idx+i+PROC_PCI_NUM_RESOURCES],16)
            if flags&PCI_BAR_IO:
                start = flags&PCI_BAR_IO_MASK
                if start!=0:
                    self.ioports.append( (start,size) )
            else:
                start = flags&PCI_BAR_MEM_MASK
                if start!=0:
                    self.iomem.append( (start,size) )

        # detect driver module name
        driver_idx = PROC_PCI_NUM_RESOURCES*2+3
        if len(sline)>driver_idx:
            self.driver = sline[driver_idx]

    def __str__(self):
        str = "PCI Device %s\n" % (self.name)
        for (start,size) in self.ioports:
            str = str + "IO Port 0x%02x [size=%d]\n"%(start,size)
        for (start,size) in self.iomem:
            str = str + "IO Mem 0x%02x [size=%d]\n"%(start,size)
        str = str + "IRQ %d"%(self.irq)
        return str

def main():
    if len(sys.argv)<5:
        print "Usage: %s <domain> <bus> <slot> <func>\n"
        sys.exit(2)

    dev = PciDevice(int(sys.argv[1],16), int(sys.argv[2],16),
            int(sys.argv[3],16), int(sys.argv[4],16))
    print str(dev)

if __name__=='__main__':
    main()
