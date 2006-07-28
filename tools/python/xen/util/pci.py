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
SYSFS_PCI_DEV_VENDOR_PATH = '/vendor'
SYSFS_PCI_DEV_DEVICE_PATH = '/device'
SYSFS_PCI_DEV_SUBVENDOR_PATH = '/subsystem_vendor'
SYSFS_PCI_DEV_SUBDEVICE_PATH = '/subsystem_device'

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
        self.vendor = None
        self.device = None
        self.subvendor = None
        self.subdevice = None

        self.get_info_from_sysfs()

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

            for i in range(PROC_PCI_NUM_RESOURCES):
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

        path = sysfs_mnt+SYSFS_PCI_DEVS_PATH+'/'+ \
                self.name+SYSFS_PCI_DEV_VENDOR_PATH
        try:
            self.vendor = int(open(path,'r').readline(), 16)
        except IOError, (errno, strerr):
            raise PciDeviceParseError(('Failed to open & read %s: %s (%d)' %
                (path, strerr, errno)))

        path = sysfs_mnt+SYSFS_PCI_DEVS_PATH+'/'+ \
                self.name+SYSFS_PCI_DEV_DEVICE_PATH
        try:
            self.device = int(open(path,'r').readline(), 16)
        except IOError, (errno, strerr):
            raise PciDeviceParseError(('Failed to open & read %s: %s (%d)' %
                (path, strerr, errno)))

        path = sysfs_mnt+SYSFS_PCI_DEVS_PATH+'/'+ \
                self.name+SYSFS_PCI_DEV_SUBVENDOR_PATH
        try:
            self.subvendor = int(open(path,'r').readline(), 16)
        except IOError, (errno, strerr):
            raise PciDeviceParseError(('Failed to open & read %s: %s (%d)' %
                (path, strerr, errno)))

        path = sysfs_mnt+SYSFS_PCI_DEVS_PATH+'/'+ \
                self.name+SYSFS_PCI_DEV_SUBDEVICE_PATH
        try:
            self.subdevice = int(open(path,'r').readline(), 16)
        except IOError, (errno, strerr):
            raise PciDeviceParseError(('Failed to open & read %s: %s (%d)' %
                (path, strerr, errno)))

        return True

    def __str__(self):
        str = "PCI Device %s\n" % (self.name)
        for (start,size) in self.ioports:
            str = str + "IO Port 0x%02x [size=%d]\n"%(start,size)
        for (start,size) in self.iomem:
            str = str + "IO Mem 0x%02x [size=%d]\n"%(start,size)
        str = str + "IRQ %d\n"%(self.irq)
        str = str + "Vendor ID 0x%04x\n"%(self.vendor)
        str = str + "Device ID 0x%04x\n"%(self.device)
        str = str + "Sybsystem Vendor ID 0x%04x\n"%(self.subvendor)
        str = str + "Subsystem Device ID 0x%04x"%(self.subdevice)
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
