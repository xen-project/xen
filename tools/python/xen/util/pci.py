#!/usr/bin/env python
#
# PCI Device Information Class
# - Helps obtain information about which I/O resources a PCI device needs
#
#   Author: Ryan Wilson <hap9@epoch.ncsc.mil>

import sys
import os, os.path
import resource
import re
import types
import struct
import time

PROC_MNT_PATH = '/proc/mounts'
PROC_PCI_PATH = '/proc/bus/pci/devices'
PROC_PCI_NUM_RESOURCES = 7

SYSFS_PCI_DEVS_PATH = '/bus/pci/devices'
SYSFS_PCI_DEV_RESOURCE_PATH = '/resource'
SYSFS_PCI_DEV_CONFIG_PATH = '/config'
SYSFS_PCI_DEV_IRQ_PATH = '/irq'
SYSFS_PCI_DEV_DRIVER_DIR_PATH = '/driver'
SYSFS_PCI_DEV_VENDOR_PATH = '/vendor'
SYSFS_PCI_DEV_DEVICE_PATH = '/device'
SYSFS_PCI_DEV_SUBVENDOR_PATH = '/subsystem_vendor'
SYSFS_PCI_DEV_SUBDEVICE_PATH = '/subsystem_device'
SYSFS_PCI_DEV_CLASS_PATH = '/class'
SYSFS_PCIBACK_PATH = '/bus/pci/drivers/pciback/'

LSPCI_CMD = 'lspci'

PCI_DEV_REG_EXPRESS_STR = r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}."+ \
            r"[0-9a-fA-F]{1}"
PCI_DEV_FORMAT_STR = '%04x:%02x:%02x.%01x'

DEV_TYPE_PCIe_ENDPOINT  = 0
DEV_TYPE_PCIe_BRIDGE    = 1
DEV_TYPE_PCI_BRIDGE     = 2
DEV_TYPE_PCI            = 3    

PCI_VENDOR_ID = 0x0
PCI_STATUS = 0x6
PCI_CLASS_DEVICE = 0x0a
PCI_CLASS_BRIDGE_PCI = 0x0604

PCI_HEADER_TYPE = 0x0e
PCI_HEADER_TYPE_MASK = 0x7f
PCI_HEADER_TYPE_NORMAL  = 0
PCI_HEADER_TYPE_BRIDGE  = 1
PCI_HEADER_TYPE_CARDBUS = 2

PCI_CAPABILITY_LIST = 0x34
PCI_CB_BRIDGE_CONTROL = 0x3e
PCI_BRIDGE_CTL_BUS_RESET= 0x40

PCI_CAP_ID_EXP = 0x10
PCI_EXP_FLAGS  = 0x2
PCI_EXP_FLAGS_TYPE = 0x00f0
PCI_EXP_TYPE_PCI_BRIDGE = 0x7
PCI_EXP_DEVCAP = 0x4
PCI_EXP_DEVCAP_FLR = (0x1 << 28)
PCI_EXP_DEVCTL = 0x8
PCI_EXP_DEVCTL_FLR = (0x1 << 15)

PCI_CAP_ID_PM = 0x01
PCI_PM_CTRL = 4
PCI_PM_CTRL_NO_SOFT_RESET = 0x0004
PCI_PM_CTRL_STATE_MASK = 0x0003
PCI_D3hot = 3

VENDOR_INTEL  = 0x8086
PCI_CAP_ID_VENDOR_SPECIFIC_CAP = 0x09
PCI_CLASS_ID_USB = 0x0c03
PCI_USB_FLRCTRL = 0x4

PCI_CAP_ID_AF = 0x13
PCI_AF_CAPs   = 0x3
PCI_AF_CAPs_TP_FLR = 0x3
PCI_AF_CTL = 0x4
PCI_AF_CTL_FLR = 0x1

PCI_BAR_0 = 0x10
PCI_BAR_5 = 0x24
PCI_BAR_SPACE = 0x01
PCI_BAR_IO = 0x01
PCI_BAR_IO_MASK = ~0x03
PCI_BAR_MEM = 0x00
PCI_BAR_MEM_MASK = ~0x0f
PCI_STATUS_CAP_MASK = 0x10
PCI_STATUS_OFFSET = 0x6
PCI_CAP_OFFSET = 0x34
MSIX_BIR_MASK = 0x7
MSIX_SIZE_MASK = 0x7ff

# Global variable to store information from lspci
lspci_info = None

# Global variable to store the sysfs mount point
sysfs_mnt_point = None

#Calculate PAGE_SHIFT: number of bits to shift an address to get the page number
PAGE_SIZE = resource.getpagesize()
PAGE_SHIFT = 0
t = PAGE_SIZE
while not (t&1):
    t>>=1
    PAGE_SHIFT+=1

PAGE_MASK=~(PAGE_SIZE - 1)
# Definitions from Linux: include/linux/pci.h
def PCI_DEVFN(slot, func):
    return ((((slot) & 0x1f) << 3) | ((func) & 0x07))

def parse_hex(val):
    try:
        if isinstance(val, types.StringTypes):
            return int(val, 16)
        else:
            return val
    except ValueError:
        return None

def parse_pci_name(pci_name_string):
    pci_match = re.match(r"((?P<domain>[0-9a-fA-F]{1,4})[:,])?" + \
            r"(?P<bus>[0-9a-fA-F]{1,2})[:,]" + \
            r"(?P<slot>[0-9a-fA-F]{1,2})[.,]" + \
            r"(?P<func>[0-7])$", pci_name_string)
    if pci_match is None:
        raise PciDeviceParseError(('Failed to parse pci device name: %s' %
            pci_name_string))
    pci_dev_info = pci_match.groupdict('0')

    domain = parse_hex(pci_dev_info['domain'])
    bus = parse_hex(pci_dev_info['bus'])
    slot = parse_hex(pci_dev_info['slot'])
    func = parse_hex(pci_dev_info['func'])

    return (domain, bus, slot, func)
 

def find_sysfs_mnt():
    global sysfs_mnt_point
    if not sysfs_mnt_point is None:
        return sysfs_mnt_point

    try:
        mounts_file = open(PROC_MNT_PATH,'r')

        for line in mounts_file:
            sline = line.split()
            if len(sline)<3:
                continue
            if sline[2]=='sysfs':
                sysfs_mnt_point= sline[1]
                return sysfs_mnt_point
    except IOError, (errno, strerr):
        raise PciDeviceParseError(('Failed to locate sysfs mount: %s: %s (%d)'%
            (PROC_PCI_PATH, strerr, errno)))
    return None

def get_all_pci_names():
    sysfs_mnt = find_sysfs_mnt()
    pci_names = os.popen('ls ' + sysfs_mnt + SYSFS_PCI_DEVS_PATH).read().split()
    return pci_names

def get_all_pci_devices():
    pci_devs = []
    for pci_name in get_all_pci_names():
        pci_match = re.match(r"((?P<domain>[0-9a-fA-F]{1,4})[:,])?" + \
                r"(?P<bus>[0-9a-fA-F]{1,2})[:,]" + \
                r"(?P<slot>[0-9a-fA-F]{1,2})[.,]" + \
                r"(?P<func>[0-7])$", pci_name)
        if pci_match is None:
            raise PciDeviceParseError(('Failed to parse pci device name: %s' %
                pci_name))
        pci_dev_info = pci_match.groupdict('0')
        domain = parse_hex(pci_dev_info['domain'])
        bus = parse_hex(pci_dev_info['bus'])
        slot = parse_hex(pci_dev_info['slot'])
        func = parse_hex(pci_dev_info['func'])
        try:
            pci_dev = PciDevice(domain, bus, slot, func)
        except:
            continue
        pci_devs.append(pci_dev)

    return pci_devs

def create_lspci_info():
    global lspci_info
    lspci_info = {}

    # Execute 'lspci' command and parse the result.
    # If the command does not exist, lspci_info will be kept blank ({}).
    for paragraph in os.popen(LSPCI_CMD + ' -vmm').read().split('\n\n'):
        device_name = None
        device_info = {}
        for line in paragraph.split('\n'):
            try:
                (opt, value) = line.split(':\t')
                if opt == 'Slot':
                    device_name = PCI_DEV_FORMAT_STR % parse_pci_name(value)
                else:
                    device_info[opt] = value
            except:
                pass
        if device_name is not None:
            lspci_info[device_name] = device_info

def save_pci_conf_space(devs_string):
    pci_list = []
    cfg_list = []
    sysfs_mnt = find_sysfs_mnt()
    for pci_str in devs_string:
        pci_path = sysfs_mnt + SYSFS_PCI_DEVS_PATH + '/' + pci_str + \
                SYSFS_PCI_DEV_CONFIG_PATH
        fd = os.open(pci_path, os.O_RDONLY)
        configs = []
        for i in range(0, 256, 4):
            configs = configs + [os.read(fd,4)]
        os.close(fd)
        pci_list = pci_list + [pci_path]
        cfg_list = cfg_list + [configs]
    return (pci_list, cfg_list)

def restore_pci_conf_space(pci_cfg_list):
    pci_list = pci_cfg_list[0]
    cfg_list = pci_cfg_list[1]
    for i in range(0, len(pci_list)):
        pci_path = pci_list[i]
        configs  = cfg_list[i]
        fd = os.open(pci_path, os.O_WRONLY)
        for dw in configs:
            os.write(fd, dw)
        os.close(fd) 

def find_all_devices_owned_by_pciback():
    sysfs_mnt = find_sysfs_mnt()
    pciback_path = sysfs_mnt + SYSFS_PCIBACK_PATH
    pci_names = os.popen('ls ' + pciback_path).read()
    pci_list = re.findall(PCI_DEV_REG_EXPRESS_STR, pci_names)
    dev_list = []
    for pci in pci_list:
        (dom, b, d, f) = parse_pci_name(pci)
        dev = PciDevice(dom, b, d, f)
        dev_list = dev_list + [dev]
    return dev_list

def transform_list(target, src):
    ''' src: its element is pci string (Format: xxxx:xx:xx:x).
        target: its element is pci string, or a list of pci string.

        If all the elements in src are in target, we remove them from target
        and add src into target; otherwise, we remove from target all the
        elements that also appear in src.
    '''
    result = []
    target_contains_src = True
    for e in src:
        if not e in target:
            target_contains_src = False
            break

    if target_contains_src:
        result = result + [src]
    for e in target:
        if not e in src:
             result = result + [e]
    return  result

def check_FLR_capability(dev_list):
    if len(dev_list) == 0:
        return []

    pci_list = []
    pci_dev_dict = {}
    for dev in dev_list:
        pci_list = pci_list + [dev.name]
        pci_dev_dict[dev.name] = dev

    while True:
        need_transform = False
        for pci in pci_list:
            if isinstance(pci, types.StringTypes):
                dev = pci_dev_dict[pci]
                if dev.bus == 0:
                    continue
                if dev.dev_type == DEV_TYPE_PCIe_ENDPOINT and not dev.pcie_flr:
                    coassigned_pci_list = dev.find_all_the_multi_functions()
                    need_transform = True
                elif dev.dev_type == DEV_TYPE_PCI and not dev.pci_af_flr:
                    coassigned_pci_list = dev.find_coassigned_devices(True)
                    del coassigned_pci_list[0]
                    need_transform = True

                if need_transform:
                    pci_list = transform_list(pci_list, coassigned_pci_list)
        if not need_transform:
            break

    if len(pci_list) == 0:
        return []

    for i in range(0, len(pci_list)):
        if isinstance(pci_list[i], types.StringTypes):
            pci_list[i] = [pci_list[i]]
    
    # Now every element in pci_list is a list of pci string.

    result = []
    for pci_names in pci_list:
        devs = []
        for pci in pci_names:
            devs = devs + [pci_dev_dict[pci]]
        result = result + [devs]
    return result

def check_mmio_bar(devs_list):
    result = []

    for dev_list in devs_list:
        non_aligned_bar_found = False
        for dev in dev_list:
            if dev.has_non_page_aligned_bar:
                non_aligned_bar_found = True
                break
        if not non_aligned_bar_found:
            result = result + [dev_list]

    return result

class PciDeviceNotFoundError(Exception):
    def __init__(self,domain,bus,slot,func):
        self.domain = domain
        self.bus = bus
        self.slot = slot
        self.func = func
        self.name = PCI_DEV_FORMAT_STR %(domain, bus, slot, func)
    
    def __str__(self):
        return ('PCI Device %s Not Found' % (self.name))

class PciDeviceParseError(Exception):
    def __init__(self,msg):
        self.message = msg
    def __str__(self):
        return 'Error Parsing PCI Device Info: '+self.message

class PciDeviceAssignmentError(Exception):
    def __init__(self,msg):
        self.message = msg
    def __str__(self):
        return 'pci: impproper device assignment spcified: ' + \
            self.message

class PciDevice:
    def __init__(self, domain, bus, slot, func):
        self.domain = domain
        self.bus = bus
        self.slot = slot
        self.func = func
        self.name = PCI_DEV_FORMAT_STR % (domain, bus, slot, func)
        self.cfg_space_path = find_sysfs_mnt()+SYSFS_PCI_DEVS_PATH+'/'+ \
            self.name + SYSFS_PCI_DEV_CONFIG_PATH 
        self.irq = 0
        self.iomem = []
        self.ioports = []
        self.driver = None
        self.vendor = None
        self.device = None
        self.subvendor = None
        self.subdevice = None
        self.msix = 0
        self.msix_iomem = []
        self.revision = 0
        self.classcode = None
        self.vendorname = ""
        self.devicename = ""
        self.classname = ""
        self.subvendorname = ""
        self.subdevicename = ""
        self.dev_type = None
        self.has_non_page_aligned_bar = False
        self.pcie_flr = False
        self.pci_af_flr = False
        self.detect_dev_info()
        self.get_info_from_sysfs()
        self.get_info_from_lspci()

    def find_parent(self):
        # i.e.,  /sys/bus/pci/devices/0000:00:19.0 or
        #        /sys/bus/pci/devices/0000:03:04.0
        path = find_sysfs_mnt()+SYSFS_PCI_DEVS_PATH+'/'+ self.name
        # i.e., ../../../devices/pci0000:00/0000:00:19.0
        #  ../../../devices/pci0000:00/0000:00:02.0/0000:01:00.2/0000:03:04.0
        try:
            target = os.readlink(path)
            lst = target.split('/')
            parent = lst[len(lst)-2]
            if parent[0:3] == 'pci':
                # We have reached the upmost one.
                return None
            else:
                lst = parent.split(':')
                dom = int(lst[0], 16)
                bus = int(lst[1], 16)
                lst = lst[2]
                lst = lst.split('.')
                dev =  int(lst[0], 16)
                func =  int(lst[1], 16)
            return (dom, bus, dev, func)
        except OSError, (errno, strerr):
            raise PciDeviceParseError('Can not locate the parent of %s',
                self.name)

    def find_the_uppermost_pci_bridge(self):
        # Find the uppermost PCI/PCI-X bridge
        (dom, b, d, f) = self.find_parent()
        dev = dev_parent = PciDevice(dom, b, d, f)
        while dev_parent.dev_type != DEV_TYPE_PCIe_BRIDGE:
            parent = dev_parent.find_parent()
            if parent is None:
                break
            (dom, b, d, f) = parent
            dev = dev_parent
            dev_parent = PciDevice(dom, b, d, f)
        return dev

    def find_all_devices_behind_the_bridge(self, ignore_bridge):
        sysfs_mnt = find_sysfs_mnt()
        self_path = sysfs_mnt + SYSFS_PCI_DEVS_PATH + '/' + self.name
        pci_names = os.popen('ls ' + self_path).read()
        dev_list = re.findall(PCI_DEV_REG_EXPRESS_STR, pci_names)

        list = [self.name]
        for pci_str in dev_list:
            (dom, b, d, f) = parse_pci_name(pci_str)
            dev = PciDevice(dom, b, d, f)
            if dev.dev_type == DEV_TYPE_PCI_BRIDGE or \
                dev.dev_type == DEV_TYPE_PCIe_BRIDGE:
                sub_list_including_self = \
                    dev.find_all_devices_behind_the_bridge(ignore_bridge)
                if ignore_bridge:
                    del sub_list_including_self[0]
                list = list + [sub_list_including_self]
            else:
                list = list + [dev.name]
        return list
        
    def find_coassigned_devices(self, ignore_bridge = True):
        ''' Here'self' is a PCI device, we need find the uppermost PCI/PCI-X
            bridge, and all devices behind it must be co-assigned to the same
            guest.
        
            Parameter:
                [ignore_bridge]: if set, the returned result doesn't include
            any bridge behind the uppermost PCI/PCI-X bridge.
        
            Note: The first element of the return value is the uppermost
                PCI/PCI-X bridge. If the caller doesn't need the first
                element,  the caller itself can remove it explicitly.
        '''
        dev = self.find_the_uppermost_pci_bridge()
        dev_list = dev.find_all_devices_behind_the_bridge(ignore_bridge)
        dev_list = re.findall(PCI_DEV_REG_EXPRESS_STR, '%s' % dev_list)
        return dev_list

    def do_secondary_bus_reset(self, target_bus, devs):
        # Save the config spaces of all the devices behind the bus.
        (pci_list, cfg_list) = save_pci_conf_space(devs)
        
        #Do the Secondary Bus Reset
        sysfs_mnt = find_sysfs_mnt()
        parent_path = sysfs_mnt + SYSFS_PCI_DEVS_PATH + '/' + \
            target_bus + SYSFS_PCI_DEV_CONFIG_PATH
        fd = os.open(parent_path, os.O_RDWR)
        os.lseek(fd, PCI_CB_BRIDGE_CONTROL, 0)
        br_cntl = (struct.unpack('H', os.read(fd, 2)))[0]
        # Assert Secondary Bus Reset
        os.lseek(fd, PCI_CB_BRIDGE_CONTROL, 0)
        br_cntl |= PCI_BRIDGE_CTL_BUS_RESET
        os.write(fd, struct.pack('H', br_cntl))
        time.sleep(0.200)
        # De-assert Secondary Bus Reset
        os.lseek(fd, PCI_CB_BRIDGE_CONTROL, 0)
        br_cntl &= ~PCI_BRIDGE_CTL_BUS_RESET
        os.write(fd, struct.pack('H', br_cntl))
        time.sleep(0.200)
        os.close(fd)

        # Restore the config spaces
        restore_pci_conf_space((pci_list, cfg_list))
        
    def do_Dstate_transition(self):
        pos = self.find_cap_offset(PCI_CAP_ID_PM)
        if pos == 0:
            return False
        
        (pci_list, cfg_list) = save_pci_conf_space([self.name])
        
        # Enter D3hot without soft reset
        pm_ctl = self.pci_conf_read32(pos + PCI_PM_CTRL)
        pm_ctl |= PCI_PM_CTRL_NO_SOFT_RESET
        pm_ctl &= ~PCI_PM_CTRL_STATE_MASK
        pm_ctl |= PCI_D3hot
        self.pci_conf_write32(pos + PCI_PM_CTRL, pm_ctl)
        time.sleep(0.010)

        # From D3hot to D0
        self.pci_conf_write32(pos + PCI_PM_CTRL, 0)
        time.sleep(0.010)

        restore_pci_conf_space((pci_list, cfg_list))
        return True

    def do_vendor_specific_FLR_method(self):
        pos = self.find_cap_offset(PCI_CAP_ID_VENDOR_SPECIFIC_CAP)
        if pos == 0:
            return

        vendor_id = self.pci_conf_read16(PCI_VENDOR_ID)
        if vendor_id != VENDOR_INTEL:
            return

        class_id = self.pci_conf_read16(PCI_CLASS_DEVICE)
        if class_id != PCI_CLASS_ID_USB:
            return

        (pci_list, cfg_list) = save_pci_conf_space([self.name])

        self.pci_conf_write8(pos + PCI_USB_FLRCTRL, 1)
        time.sleep(0.010)

        restore_pci_conf_space((pci_list, cfg_list))

    def do_FLR_for_integrated_device(self):
        if not self.do_Dstate_transition():
            self.do_vendor_specific_FLR_method()

    def find_all_the_multi_functions(self):
        sysfs_mnt = find_sysfs_mnt()
        pci_names = os.popen('ls ' + sysfs_mnt + SYSFS_PCI_DEVS_PATH).read()
        p = self.name
        p = p[0 : p.rfind('.')] + '.[0-7]'
        funcs = re.findall(p, pci_names)
        return funcs

    def find_cap_offset(self, cap):
        path = find_sysfs_mnt()+SYSFS_PCI_DEVS_PATH+'/'+ \
               self.name+SYSFS_PCI_DEV_CONFIG_PATH

        pos = PCI_CAPABILITY_LIST

        try:
            fd = os.open(path, os.O_RDONLY)
            os.lseek(fd, PCI_STATUS, 0)
            status = struct.unpack('H', os.read(fd, 2))[0]
            if (status & 0x10) == 0:
                # The device doesn't support PCI_STATUS_CAP_LIST
                return 0

            max_cap = 48
            while max_cap > 0:
                os.lseek(fd, pos, 0)
                pos = ord(os.read(fd, 1))
                if pos < 0x40:
                    pos = 0
                    break;
                os.lseek(fd, pos + 0, 0)
                id = ord(os.read(fd, 1))
                if id == 0xff:
                    pos = 0
                    break;

                # Found the capability
                if id == cap:
                    break;

                # Test the next one
                pos = pos + 1
                max_cap = max_cap - 1;

            os.close(fd)
        except OSError, (errno, strerr):
            raise PciDeviceParseError(('Error when accessing sysfs: %s (%d)' %
                (strerr, errno)))
        return pos

    def pci_conf_read8(self, pos):
        fd = os.open(self.cfg_space_path, os.O_RDONLY)
        os.lseek(fd, pos, 0)
        str = os.read(fd, 1)
        os.close(fd)
        val = struct.unpack('B', str)[0]
        return val

    def pci_conf_read16(self, pos):
        fd = os.open(self.cfg_space_path, os.O_RDONLY)
        os.lseek(fd, pos, 0)
        str = os.read(fd, 2)
        os.close(fd)
        val = struct.unpack('H', str)[0]
        return val

    def pci_conf_read32(self, pos):
        fd = os.open(self.cfg_space_path, os.O_RDONLY)
        os.lseek(fd, pos, 0)
        str = os.read(fd, 4)
        os.close(fd)
        val = struct.unpack('I', str)[0]
        return val

    def pci_conf_write8(self, pos, val):
        str = struct.pack('B', val)
        fd = os.open(self.cfg_space_path, os.O_WRONLY)
        os.lseek(fd, pos, 0)
        os.write(fd, str)
        os.close(fd)

    def pci_conf_write16(self, pos, val):
        str = struct.pack('H', val)
        fd = os.open(self.cfg_space_path, os.O_WRONLY)
        os.lseek(fd, pos, 0)
        os.write(fd, str)
        os.close(fd)

    def pci_conf_write32(self, pos, val):
        str = struct.pack('I', val)
        fd = os.open(self.cfg_space_path, os.O_WRONLY)
        os.lseek(fd, pos, 0)
        os.write(fd, str)
        os.close(fd)

    def detect_dev_info(self):
        class_dev = self.pci_conf_read16(PCI_CLASS_DEVICE)
        pos = self.find_cap_offset(PCI_CAP_ID_EXP)
        if class_dev == PCI_CLASS_BRIDGE_PCI:
            if pos == 0:
                self.dev_type = DEV_TYPE_PCI_BRIDGE
            else:
                creg = self.pci_conf_read16(pos + PCI_EXP_FLAGS)
                if ((creg & PCI_EXP_TYPE_PCI_BRIDGE) >> 4) == \
                    PCI_EXP_TYPE_PCI_BRIDGE:
                    self.dev_type = DEV_TYPE_PCI_BRIDGE
                else:
                    self.dev_type = DEV_TYPE_PCIe_BRIDGE
        else:
            if  pos != 0:
                self.dev_type = DEV_TYPE_PCIe_ENDPOINT
            else:
                self.dev_type = DEV_TYPE_PCI
                
        # Force 0000:00:00.0 to be DEV_TYPE_PCIe_BRIDGE
        if self.name == '0000:00:00.0':
            self.dev_type = DEV_TYPE_PCIe_BRIDGE

        if (self.dev_type == DEV_TYPE_PCI_BRIDGE) or \
            (self.dev_type == DEV_TYPE_PCIe_BRIDGE):
            return

        # Try to findthe PCIe FLR capability
        if self.dev_type == DEV_TYPE_PCIe_ENDPOINT:
            dev_cap = self.pci_conf_read32(pos + PCI_EXP_DEVCAP)
            if dev_cap & PCI_EXP_DEVCAP_FLR:
                self.pcie_flr = True
        elif self.dev_type == DEV_TYPE_PCI:
            # Try to find the "PCI Advanced Capabilities"
            pos = self.find_cap_offset(PCI_CAP_ID_AF)
            if pos != 0:
                af_cap = self.pci_conf_read8(pos + PCI_AF_CAPs)
                if (af_cap & PCI_AF_CAPs_TP_FLR) == PCI_AF_CAPs_TP_FLR:
                    self.pci_af_flr = True

        bar_addr = PCI_BAR_0
        while bar_addr <= PCI_BAR_5:
            bar = self.pci_conf_read32(bar_addr)
            if (bar & PCI_BAR_SPACE) == PCI_BAR_MEM:
                bar = bar & PCI_BAR_MEM_MASK
                bar = bar & ~PAGE_MASK
                if bar != 0:
                    self.has_non_page_aligned_bar = True
                    break 
            bar_addr = bar_addr + 4

    def devs_check_driver(self, devs):
        if len(devs) == 0:
            return
        for pci_dev in devs:
            (dom, b, d, f) = parse_pci_name(pci_dev)
            dev = PciDevice(dom, b, d, f)
            if dev.driver == 'pciback':
                continue
            err_msg = 'pci: %s must be co-assigned to the same guest with %s' + \
                ', but it is not owned by pciback.'
            raise PciDeviceAssignmentError(err_msg % (pci_dev, self.name))

    def do_FLR(self):
        """ Perform FLR (Functional Level Reset) for the device.
        """
        if self.dev_type == DEV_TYPE_PCIe_ENDPOINT:
            # If PCIe device supports FLR, we use it.
            if self.pcie_flr:
                (pci_list, cfg_list) = save_pci_conf_space([self.name])
                pos = self.find_cap_offset(PCI_CAP_ID_EXP)
                self.pci_conf_write32(pos + PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_FLR)
                # We must sleep at least 100ms for the completion of FLR
                time.sleep(0.200)
                restore_pci_conf_space((pci_list, cfg_list))
            else:
                if self.bus == 0:
                    self.do_FLR_for_integrated_device()
                else:
                    funcs = self.find_all_the_multi_functions()
                    self.devs_check_driver(funcs)

                    parent = '%04x:%02x:%02x.%01x' % self.find_parent()

                    # Do Secondary Bus Reset.
                    self.do_secondary_bus_reset(parent, funcs)
        # PCI devices
        else:
            # For PCI device on host bus, we test "PCI Advanced Capabilities".
            if self.bus == 0 and self.pci_af_flr:
                (pci_list, cfg_list) = save_pci_conf_space([self.name])
                # We use Advanced Capability to do FLR.
                pos = self.find_cap_offset(PCI_CAP_ID_AF)
                self.pci_conf_write8(pos + PCI_AF_CTL, PCI_AF_CTL_FLR)
                time.sleep(0.200)
                restore_pci_conf_space((pci_list, cfg_list))
            else:
                if self.bus == 0:
                    self.do_FLR_for_integrated_device()
                else:
                    devs = self.find_coassigned_devices(False)
                    # Remove the element 0 which is a bridge
                    target_bus = devs[0]
                    del devs[0]
                    self.devs_check_driver(devs)

                    # Do Secondary Bus Reset.
                    self.do_secondary_bus_reset(target_bus, devs)

    def find_capability(self, type):
        sysfs_mnt = find_sysfs_mnt()
        if sysfs_mnt == None:
            return False
        path = sysfs_mnt+SYSFS_PCI_DEVS_PATH+'/'+ \
               self.name+SYSFS_PCI_DEV_CONFIG_PATH
        try:
            conf_file = open(path, 'rb')
            conf_file.seek(PCI_HEADER_TYPE)
            header_type = ord(conf_file.read(1)) & PCI_HEADER_TYPE_MASK
            if header_type == PCI_HEADER_TYPE_CARDBUS:
                return
            conf_file.seek(PCI_STATUS_OFFSET)
            status = ord(conf_file.read(1))
            if status&PCI_STATUS_CAP_MASK:
                conf_file.seek(PCI_CAP_OFFSET)
                capa_pointer = ord(conf_file.read(1))
                capa_count = 0
                while capa_pointer:
                    if capa_pointer < 0x40:
                        raise PciDeviceParseError(
                            ('Broken capability chain: %s' % self.name))
                    capa_count += 1
                    if capa_count > 96:
                        raise PciDeviceParseError(
                            ('Looped capability chain: %s' % self.name))
                    conf_file.seek(capa_pointer)
                    capa_id = ord(conf_file.read(1))
                    capa_pointer = ord(conf_file.read(1))
                    if capa_id == type:
                        # get the type
                        message_cont_lo = ord(conf_file.read(1))
                        message_cont_hi = ord(conf_file.read(1))
                        self.msix=1
                        self.msix_entries = (message_cont_lo + \
                                             (message_cont_hi << 8)) \
                                             & MSIX_SIZE_MASK
                        t_off=conf_file.read(4)
                        p_off=conf_file.read(4)
                        self.table_offset=ord(t_off[0]) | (ord(t_off[1])<<8) | \
                                          (ord(t_off[2])<<16)|  \
                                          (ord(t_off[3])<<24)
                        self.pba_offset=ord(p_off[0]) | (ord(p_off[1]) << 8)| \
                                        (ord(p_off[2])<<16) | \
                                        (ord(p_off[3])<<24)
                        self.table_index = self.table_offset & MSIX_BIR_MASK
                        self.table_offset = self.table_offset & ~MSIX_BIR_MASK
                        self.pba_index = self.pba_offset & MSIX_BIR_MASK
                        self.pba_offset = self.pba_offset & ~MSIX_BIR_MASK
                        break
        except IOError, (errno, strerr):
            raise PciDeviceParseError(('Failed to locate sysfs mount: %s: %s (%d)' %
                (PROC_PCI_PATH, strerr, errno)))

    def remove_msix_iomem(self, index, start, size):
        if (index == self.table_index):
            table_start = start+self.table_offset
            table_end = table_start + self.msix_entries * 16
            table_start = table_start & PAGE_MASK
            table_end = (table_end + PAGE_SIZE) & PAGE_MASK
            self.msix_iomem.append((table_start, table_end-table_start))
        if (index==self.pba_index):
            pba_start = start + self.pba_offset
            pba_end = pba_start + self.msix_entries/8
            pba_start = pba_start & PAGE_MASK
            pba_end = (pba_end + PAGE_SIZE) & PAGE_MASK
            self.msix_iomem.append((pba_start, pba_end-pba_start))

    def get_info_from_sysfs(self):
        self.find_capability(0x11)
        sysfs_mnt = find_sysfs_mnt()
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
                    if (self.msix):
                        self.remove_msix_iomem(i, start, size)



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
        except OSError, (errno, strerr):
            self.driver = ""

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

        path = sysfs_mnt+SYSFS_PCI_DEVS_PATH+'/'+ \
                self.name+SYSFS_PCI_DEV_CLASS_PATH
        try:
            self.classcode = int(open(path,'r').readline(), 16)
        except IOError, (errno, strerr):
            raise PciDeviceParseError(('Failed to open & read %s: %s (%d)' %
                (path, strerr, errno)))

        return True

    def get_info_from_lspci(self):
        """ Get information such as vendor name, device name, class name, etc.
        Since we cannot obtain these data from sysfs, use 'lspci' command.
        """
        global lspci_info

        if lspci_info is None:
            create_lspci_info()

        try:
            device_info = lspci_info[self.name]
            self.revision = int(device_info['Rev'], 16)
            self.vendorname = device_info['Vendor']
            self.devicename = device_info['Device']
            self.classname = device_info['Class']
            self.subvendorname = device_info['SVendor']
            self.subdevicename = device_info['SDevice']
        except KeyError:
            pass

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
        print "Usage: %s <domain> <bus> <slot> <func>\n" % sys.argv[0]
        sys.exit(2)

    dev = PciDevice(int(sys.argv[1],16), int(sys.argv[2],16),
            int(sys.argv[3],16), int(sys.argv[4],16))
    print str(dev)

if __name__=='__main__':
    main()
