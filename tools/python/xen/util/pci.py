#!/usr/bin/env python
#
# PCI Device Information Class
# - Helps obtain information about which I/O resources a PCI device needs
#
#   Author: Ryan Wilson <hap9@epoch.ncsc.mil>

import sys
import os, os.path
import errno
import resource
import re
import types
import struct
import time
import threading
from xen.util import utils
from xen.xend import uuid
from xen.xend import sxp
from xen.xend.XendConstants import AUTO_PHP_SLOT
from xen.xend.XendSXPDev import dev_dict_to_sxp

# for 2.3 compatibility
try:
    set()
except NameError:
    from sets import Set as set

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
SYSFS_PCISTUB_PATH = '/bus/pci/drivers/pci-stub/'

LSPCI_CMD = 'lspci'

PCI_DEV_REG_EXPRESS_STR = r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}."+ \
            r"[0-9a-fA-F]{1}"

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
PCI_EXP_TYPE_DOWNSTREAM = 0x6
PCI_EXP_TYPE_PCI_BRIDGE = 0x7
PCI_EXP_DEVCAP = 0x4
PCI_EXP_DEVCAP_FLR = (0x1 << 28)
PCI_EXP_DEVCTL = 0x8
PCI_EXP_DEVCTL_FLR = (0x1 << 15)

PCI_EXT_CAP_ID_ACS = 0x000d
PCI_EXT_CAP_ACS_ENABLED = 0x1d  # The bits V, R, C, U.
PCI_EXT_ACS_CTRL = 0x06


PCI_CAP_ID_PM = 0x01
PCI_PM_CTRL = 4
PCI_PM_CTRL_NO_SOFT_RESET = 0x0008
PCI_PM_CTRL_STATE_MASK = 0x0003
PCI_D3hot = 3
PCI_D0hot = 0

VENDOR_INTEL  = 0x8086
PCI_CAP_ID_VENDOR_SPECIFIC_CAP = 0x09
PCI_CLASS_ID_USB = 0x0c03
PCI_USB_FLRCTRL = 0x4

# The VF of Intel 82599 10GbE Controller
# See http://download.intel.com/design/network/datashts/82599_datasheet.pdf
# For 'VF PCIe Configuration Space', see its Table 9.7.
DEVICE_ID_82599 = 0x10ed

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
lspci_info_lock = threading.RLock()

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
def PCI_SLOT(devfn):
    return (devfn >> 3) & 0x1f
def PCI_FUNC(devfn):
    return devfn & 0x7

def PCI_BDF(domain, bus, slot, func):
    return (((domain & 0xffff) << 16) | ((bus & 0xff) << 8) |
            PCI_DEVFN(slot, func))

def check_pci_opts(opts):
    def f((k, v)):
        if k not in ['msitranslate', 'power_mgmt'] or \
           not v.lower() in ['0', '1', 'yes', 'no']:
            raise PciDeviceParseError('Invalid pci option %s=%s: ' % (k, v))

    map(f, opts)

def serialise_pci_opts(opts):
    return ','.join(map(lambda x: '='.join(x), opts))

def split_pci_opts(opts):
    return map(lambda x: x.split('='),
               filter(lambda x: x != '', opts.split(',')))

def pci_opts_list_to_sxp(list):
    return dev_dict_to_sxp({'opts': list})

def pci_opts_list_from_sxp(dev):
    return map(lambda x: sxp.children(x)[0], sxp.children(dev, 'opts'))

def pci_convert_dict_to_sxp(dev, state, sub_state = None):
    pci_sxp = ['pci', dev_dict_to_sxp(dev), ['state', state]]
    if sub_state != None:
        pci_sxp.append(['sub_state', sub_state])
    return pci_sxp

def pci_convert_sxp_to_dict(dev_sxp):
    """Convert pci device sxp to dict
    @param dev_sxp: device configuration
    @type  dev_sxp: SXP object (parsed config)
    @return: dev_config
    @rtype: dictionary
    """
    # Parsing the device SXP's. In most cases, the SXP looks
    # like this:
    #
    # [device, [vif, [mac, xx:xx:xx:xx:xx:xx], [ip 1.3.4.5]]]
    #
    # However, for PCI devices it looks like this:
    #
    # [device, [pci, [dev, [domain, 0], [bus, 0], [slot, 1], [func, 2]]]
    #
    # It seems the reasoning for this difference is because
    # pciif.py needs all the PCI device configurations at
    # the same time when creating the devices.
    #
    # To further complicate matters, Xen 2.0 configuration format
    # uses the following for pci device configuration:
    #
    # [device, [pci, [domain, 0], [bus, 0], [dev, 1], [func, 2]]]

    # For PCI device hotplug support, the SXP of PCI devices is
    # extendend like this:
    #
    # [device, [pci, [dev, [domain, 0], [bus, 0], [slot, 1], [func, 2],
    #                      [vdevfn, 0]],
    #                [state, 'Initialising']]]
    #
    # 'vdevfn' shows the virtual hotplug slot number which the PCI device
    # is inserted in. This is only effective for HVM domains.
    #
    # state 'Initialising' indicates that the device is being attached,
    # while state 'Closing' indicates that the device is being detached.
    #
    # The Dict looks like this:
    #
    # { devs: [{domain: 0, bus: 0, slot: 1, func: 2, vdevfn: 0}],
    #   states: ['Initialising'] }

    dev_config = {}

    pci_devs = []
    for pci_dev in sxp.children(dev_sxp, 'dev'):
        pci_dev_info = dict(pci_dev[1:])
        if 'opts' in pci_dev_info:
            pci_dev_info['opts'] = pci_opts_list_from_sxp(pci_dev)
        # append uuid to each pci device that does't already have one.
        if not pci_dev_info.has_key('uuid'):
            dpci_uuid = pci_dev_info.get('uuid', uuid.createString())
            pci_dev_info['uuid'] = dpci_uuid
        pci_devs.append(pci_dev_info)
    dev_config['devs'] = pci_devs

    pci_states = []
    for pci_state in sxp.children(dev_sxp, 'state'):
        try:
            pci_states.append(pci_state[1])
        except IndexError:
            raise XendError("Error reading state while parsing pci sxp")
    dev_config['states'] = pci_states

    return dev_config

def parse_hex(val):
    try:
        if isinstance(val, types.StringTypes):
            return int(val, 16)
        else:
            return val
    except ValueError:
        return None

AUTO_PHP_FUNC = 1
MANUAL_PHP_FUNC = 2

def parse_pci_pfunc_vfunc(func_str):
    list = func_str.split('=')
    l = len(list)
    if l == 0 or l > 2:
         raise PciDeviceParseError('Invalid function: ' + func_str)
    p = int(list[0], 16)
    if p < 0 or p > 7:
        raise PciDeviceParseError('Invalid physical function in: ' + func_str)
    if l == 1:
        # This defaults to linear mapping of physical to virtual functions
        return (p, p, AUTO_PHP_FUNC)
    else:
        v = int(list[1], 16)
        if v < 0 or v > 7:
            raise PciDeviceParseError('Invalid virtual function in: ' +
                                      func_str)
        return (p, v, MANUAL_PHP_FUNC)

def pci_func_range(start, end):
    if end < start:
        x = pci_func_range(end, start)
        x.reverse()
        return x
    return range(start, end + 1)

def pci_pfunc_vfunc_range(orig, a, b):
    phys = pci_func_range(a[0], b[0])
    virt = pci_func_range(a[1], b[1])
    if len(phys) != len(virt):
        raise PciDeviceParseError('Invalid range in: ' + orig)
    return map(lambda x: x + (MANUAL_PHP_FUNC,), zip(phys, virt))

def pci_func_list_map_fn(key, func_str):
    if func_str == "*":
        return map(lambda x: parse_pci_pfunc_vfunc(x['func']),
                   filter(lambda x:
                          pci_dict_cmp(x, key, ['domain', 'bus', 'slot']),
                          get_all_pci_dict()))
    l = map(parse_pci_pfunc_vfunc, func_str.split("-"))
    if len(l) == 1:
        return l
    if len(l) == 2:
        return pci_pfunc_vfunc_range(func_str, l[0], l[1])
    return []

def pci_func_list_process(pci_dev_str, template, func_str):
    l = reduce(lambda x, y: x + y,
               (map(lambda x: pci_func_list_map_fn(template, x),
                    func_str.split(","))))

    phys = map(lambda x: x[0], l)
    virt = map(lambda x: x[1], l)
    if len(phys) != len(set(phys)) or len(virt) != len(set(virt)):
        raise PciDeviceParseError("Duplicate functions: %s" % pci_dev_str)

    return l

def parse_pci_name_extended(pci_dev_str):
    pci_match = re.match(r"((?P<domain>[0-9a-fA-F]{1,4})[:,])?" +
                         r"(?P<bus>[0-9a-fA-F]{1,2})[:,]" +
                         r"(?P<slot>[0-9a-fA-F]{1,2})[.,]" +
                         r"(?P<func>(\*|[0-7]([,-=][0-7])*))" +
                         r"(@(?P<vdevfn>[01]?[0-9a-fA-F]))?" +
                         r"(,(?P<opts>.*))?$", pci_dev_str)

    if pci_match == None:
        raise PciDeviceParseError("Failed to parse pci device: %s" %
                                  pci_dev_str)

    pci_dev_info = pci_match.groupdict('')

    template = {}
    if pci_dev_info['domain'] != '':
        domain = int(pci_dev_info['domain'], 16)
    else:
        domain = 0
    template['domain'] = "0x%04x" % domain
    template['bus']    = "0x%02x" % int(pci_dev_info['bus'], 16)
    template['slot']   = "0x%02x" % int(pci_dev_info['slot'], 16)
    template['key']    = pci_dev_str
    if pci_dev_info['opts'] != '':
        template['opts'] = split_pci_opts(pci_dev_info['opts'])
        check_pci_opts(template['opts'])

    # This is where virtual function assignment takes place
    func_list = pci_func_list_process(pci_dev_str, template,
                                      pci_dev_info['func'])
    if len(func_list) == 0:
        return []

    # Set the virtual function of the numerically lowest physical function
    # to zero if it has not been manually set
    if not filter(lambda x: x[1] == 0, func_list):
        auto   = filter(lambda x: x[2] == AUTO_PHP_FUNC, func_list)
        manual = filter(lambda x: x[2] == MANUAL_PHP_FUNC, func_list)
        if not auto:
            raise PciDeviceParseError('Virtual device does not include '
                                      'virtual function 0: ' + pci_dev_str)
        auto.sort(lambda x,y: cmp(x[1], y[1]))
        auto[0] = (auto[0][0], 0, AUTO_PHP_FUNC)
        func_list = auto + manual

    # For pci attachment and detachment is it important that virtual
    # function 0 is done last. This is because is virtual function 0 that
    # is used to singnal changes to the guest using ACPI
    func_list.sort(lambda x,y: cmp(PCI_FUNC(y[1]), PCI_FUNC(x[1])))

    # Virtual slot assignment takes place here if specified in the bdf,
    # else it is done inside qemu-xen, as it knows which slots are free
    pci = []
    for (pfunc, vfunc, auto) in func_list:
        pci_dev = template.copy()
        pci_dev['func'] = "0x%x" % pfunc

        if pci_dev_info['vdevfn'] == '':
            vdevfn = AUTO_PHP_SLOT | vfunc
        else:
            vdevfn = PCI_DEVFN(int(pci_dev_info['vdevfn'], 16), vfunc)
        pci_dev['vdevfn'] = "0x%02x" % vdevfn

        pci.append(pci_dev)

    return pci

def parse_pci_name(pci_name_string):
    dev = parse_pci_name_extended(pci_name_string)

    if len(dev) != 1:
        raise PciDeviceParseError(("Failed to parse pci device: %s: "
                                   "multiple functions specified prohibited") %
                                    pci_name_string)

    pci = dev[0]
    if not int(pci['vdevfn'], 16) & AUTO_PHP_SLOT:
        raise PciDeviceParseError(("Failed to parse pci device: %s: " +
                                   "vdevfn provided where prohibited: 0x%02x") %
                                  (pci_name_string,
                                   PCI_SLOT(int(pci['vdevfn'], 16))))
    if 'opts' in pci:
        raise PciDeviceParseError(("Failed to parse pci device: %s: " +
                                   "options provided where prohibited: %s") %
                                  (pci_name_string, pci['opts']))

    return pci

def __pci_dict_to_fmt_str(fmt, dev):
    return fmt % (int(dev['domain'], 16), int(dev['bus'], 16),
                  int(dev['slot'], 16), int(dev['func'], 16))

def pci_dict_to_bdf_str(dev):
    return __pci_dict_to_fmt_str('%04x:%02x:%02x.%01x', dev)

def pci_dict_to_xc_str(dev):
    return __pci_dict_to_fmt_str('0x%x, 0x%x, 0x%x, 0x%x', dev)

def pci_dict_cmp(a, b, keys=['domain', 'bus', 'slot', 'func']):
    return reduce(lambda x, y: x and y,
                  map(lambda k: int(a[k], 16) == int(b[k], 16), keys))

def extract_the_exact_pci_names(pci_names):
    result = []

    if isinstance(pci_names, types.StringTypes):
        pci_names = pci_names.split()
    elif isinstance(pci_names, types.ListType):
        pci_names = re.findall(PCI_DEV_REG_EXPRESS_STR, '%s' % pci_names)
    else:
         raise PciDeviceParseError('Invalid argument: %s' % pci_names)

    for pci in pci_names:
        # The length of DDDD:bb:dd.f is 12.
        if len(pci) !=  12:
            continue
        if re.match(PCI_DEV_REG_EXPRESS_STR, pci) is None:
            continue
        result = result + [pci]
    return result

def find_sysfs_mnt():
    try:
        return utils.find_sysfs_mount()
    except IOError, (errno, strerr):
        raise PciDeviceParseError(('Failed to locate sysfs mount: %s: %s (%d)'%
            (PROC_PCI_PATH, strerr, errno)))
    return None

def get_all_pci_names():
    sysfs_mnt = find_sysfs_mnt()
    pci_names = os.popen('ls ' + sysfs_mnt + SYSFS_PCI_DEVS_PATH).read().split()
    return pci_names

def get_all_pci_dict():
    return map(parse_pci_name, get_all_pci_names())

def get_all_pci_devices():
    return map(PciDevice, get_all_pci_dict())

def _create_lspci_info():
    """Execute 'lspci' command and parse the result.
    If the command does not exist, lspci_info will be kept blank ({}).

    Expects to be protected by lspci_info_lock.
    """
    global lspci_info
    
    lspci_info = {}

    for paragraph in os.popen(LSPCI_CMD + ' -vmm').read().split('\n\n'):
        device_name = None
        device_info = {}
        # FIXME: workaround for pciutils without the -mm option.
        # see: git://git.kernel.org/pub/scm/utils/pciutils/pciutils.git
        # commit: 3fd6b4d2e2fda814047664ffc67448ac782a8089
        first_device = True
        for line in paragraph.split('\n'):
            try:
                (opt, value) = line.split(':\t')
                if opt == 'Slot' or (opt == 'Device' and first_device):
                    device_name = pci_dict_to_bdf_str(parse_pci_name(value))
                    first_device = False
                else:
                    device_info[opt] = value
            except:
                pass
        if device_name is not None:
            lspci_info[device_name] = device_info

def create_lspci_info():
    global lspci_info_lock
    lspci_info_lock.acquire()
    try:
        _create_lspci_info()
    finally:
        lspci_info_lock.release()

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

def find_all_assignable_devices():
    '''  devices owned by pcibak or pci-stub can be directly assigned to
         guest with IOMMU (VT-d or AMD IOMMU), find all these devices.
    '''
    sysfs_mnt = find_sysfs_mnt()
    pciback_path = sysfs_mnt + SYSFS_PCIBACK_PATH
    pcistub_path = sysfs_mnt + SYSFS_PCISTUB_PATH
    pci_names1 = os.popen('ls %s 2>/dev/null' % pciback_path).read()
    pci_names2 = os.popen('ls %s 2>/dev/null' % pcistub_path).read()
    if len(pci_names1) + len(pci_names2) == 0 :
        return None
    pci_list = extract_the_exact_pci_names(pci_names1)
    pci_list = pci_list + extract_the_exact_pci_names(pci_names2)
    dev_list = []
    for pci in pci_list:
        dev = PciDevice(parse_pci_name(pci))
        dev_list = dev_list + [dev]
    return dev_list

def transform_list(target, src):
    ''' src: its element is pci string (Format: xxxx:xx:xx.x).
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
                    coassigned_pci_list = dev.find_coassigned_pci_devices(True)
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

class PciDeviceParseError(Exception):
    def __init__(self,msg):
        self.message = msg
    def __str__(self):
        return self.message

class PciDeviceAssignmentError(Exception):
    def __init__(self,msg):
        self.message = msg
    def __str__(self):
        return 'pci: improper device assignment specified: ' + \
            self.message

class PciDeviceVslotMissing(Exception):
    def __init__(self,msg):
        self.message = msg
    def __str__(self):
        return 'pci: no vslot: ' + self.message

class PciDevice:
    def __init__(self, dev):
        self.domain = int(dev['domain'], 16)
        self.bus = int(dev['bus'], 16)
        self.slot = int(dev['slot'], 16)
        self.func = int(dev['func'], 16)
        self.name = pci_dict_to_bdf_str(dev)
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
        self.is_downstream_port = False
        self.acs_enabled = False
        self.has_non_page_aligned_bar = False
        self.pcie_flr = False
        self.pci_af_flr = False
        self.detect_dev_info()
        if (self.dev_type == DEV_TYPE_PCI_BRIDGE) or \
            (self.dev_type == DEV_TYPE_PCIe_BRIDGE):
            return
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
            return parse_pci_name(parent)
        except OSError, (errno, strerr):
            raise PciDeviceParseError('Can not locate the parent of %s',
                self.name)

    def find_the_uppermost_pci_bridge(self):
        # Find the uppermost PCI/PCI-X bridge
        dev = self.find_parent()
        if dev is None:
            return None
        dev = dev_parent = PciDevice(dev)
        while dev_parent.dev_type != DEV_TYPE_PCIe_BRIDGE:
            parent = dev_parent.find_parent()
            if parent is None:
                break
            dev = dev_parent
            dev_parent = PciDevice(parent)
        return dev

    def find_all_devices_behind_the_bridge(self, ignore_bridge):
        sysfs_mnt = find_sysfs_mnt()
        self_path = sysfs_mnt + SYSFS_PCI_DEVS_PATH + '/' + self.name
        pci_names = os.popen('ls ' + self_path).read()
        dev_list = extract_the_exact_pci_names(pci_names)

        list = [self.name]
        for pci_str in dev_list:
            dev = PciDevice(parse_pci_name(pci_str))
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
        
    def find_coassigned_pci_devices(self, ignore_bridge = True):
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

        # The 'self' device is on bus0.
        if dev is None:
            return [self.name]

        dev_list = dev.find_all_devices_behind_the_bridge(ignore_bridge)
        dev_list = extract_the_exact_pci_names(dev_list)
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
        time.sleep(0.100)
        # De-assert Secondary Bus Reset
        os.lseek(fd, PCI_CB_BRIDGE_CONTROL, 0)
        br_cntl &= ~PCI_BRIDGE_CTL_BUS_RESET
        os.write(fd, struct.pack('H', br_cntl))
        time.sleep(0.100)
        os.close(fd)

        # Restore the config spaces
        restore_pci_conf_space((pci_list, cfg_list))
        
    def do_Dstate_transition(self):
        pos = self.find_cap_offset(PCI_CAP_ID_PM)
        if pos == 0:
            return False
        
        # No_Soft_Reset - When set 1, this bit indicates that
        # devices transitioning from D3hot to D0 because of
        # PowerState commands do not perform an internal reset.
        pm_ctl = self.pci_conf_read32(pos + PCI_PM_CTRL)
        if (pm_ctl & PCI_PM_CTRL_NO_SOFT_RESET) == PCI_PM_CTRL_NO_SOFT_RESET:
            return False

        (pci_list, cfg_list) = save_pci_conf_space([self.name])
        
        # Enter D3hot
        pm_ctl &= ~PCI_PM_CTRL_STATE_MASK
        pm_ctl |= PCI_D3hot
        self.pci_conf_write32(pos + PCI_PM_CTRL, pm_ctl)
        time.sleep(0.010)

        # From D3hot to D0
        pm_ctl &= ~PCI_PM_CTRL_STATE_MASK
        pm_ctl |= PCI_D0hot
        self.pci_conf_write32(pos + PCI_PM_CTRL, pm_ctl)
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
        time.sleep(0.100)

        restore_pci_conf_space((pci_list, cfg_list))

    def do_FLR_for_integrated_device(self):
        if not self.do_Dstate_transition():
            self.do_vendor_specific_FLR_method()

    def find_all_the_multi_functions(self):
        sysfs_mnt = find_sysfs_mnt()
        parentdict = self.find_parent()
        if parentdict is None :
            return [ self.name ]
        parent = pci_dict_to_bdf_str(parentdict)
        pci_names = os.popen('ls ' + sysfs_mnt + SYSFS_PCI_DEVS_PATH + '/' + \
            parent + '/').read()
        funcs = extract_the_exact_pci_names(pci_names)
        return funcs

    def find_coassigned_devices(self):
        if self.dev_type == DEV_TYPE_PCIe_ENDPOINT and not self.pcie_flr:
            return self.find_all_the_multi_functions()
        elif self.dev_type == DEV_TYPE_PCI and not self.pci_af_flr:
            coassigned_pci_list = self.find_coassigned_pci_devices(True)
            if len(coassigned_pci_list) > 1:
                del coassigned_pci_list[0]
            return coassigned_pci_list
        else:
            return [self.name]

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

    def find_ext_cap(self, cap):
        path = find_sysfs_mnt()+SYSFS_PCI_DEVS_PATH+'/'+ \
               self.name+SYSFS_PCI_DEV_CONFIG_PATH

        ttl = 480; # 3840 bytes, minimum 8 bytes per capability
        pos = 0x100

        try:
            fd = os.open(path, os.O_RDONLY)
            os.lseek(fd, pos, 0)
            h = os.read(fd, 4)
            if len(h) == 0: # MMCONF is not enabled?
                return 0
            header = struct.unpack('I', h)[0]
            if header == 0 or header == -1:
                return 0

            while ttl > 0:
                if (header & 0x0000ffff) == cap:
                    return pos
                pos = (header >> 20) & 0xffc
                if pos < 0x100:
                    break
                os.lseek(fd, pos, 0)
                header = struct.unpack('I', os.read(fd, 4))[0]
                ttl = ttl - 1
            os.close(fd)
        except OSError, (errno, strerr):
            raise PciDeviceParseError(('Error when accessing sysfs: %s (%d)' %
                (strerr, errno)))
        return 0

    def is_behind_switch_lacking_acs(self):
        # If there is intermediate PCIe switch, which doesn't support ACS or
        # doesn't enable ACS, between Root Complex and the function, we return
        # True,  meaning the function is not allowed to be assigned to guest due
        # to potential security issue.
        parent = self.find_parent()
        while parent is not None:
            dev_parent = PciDevice(parent)
            if dev_parent.is_downstream_port and not dev_parent.acs_enabled:
                return True
            parent = dev_parent.find_parent()
        return False

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
        try:
            class_dev = self.pci_conf_read16(PCI_CLASS_DEVICE)
        except OSError, (err, strerr):
            if err == errno.ENOENT:
                strerr = "the device doesn't exist?"
            raise PciDeviceParseError('%s: %s' %\
                (self.name, strerr))
        pos = self.find_cap_offset(PCI_CAP_ID_EXP)
        if class_dev == PCI_CLASS_BRIDGE_PCI:
            if pos == 0:
                self.dev_type = DEV_TYPE_PCI_BRIDGE
            else:
                creg = self.pci_conf_read16(pos + PCI_EXP_FLAGS)
                type = (creg & PCI_EXP_FLAGS_TYPE) >> 4
                if type == PCI_EXP_TYPE_PCI_BRIDGE:
                    self.dev_type = DEV_TYPE_PCI_BRIDGE
                else:
                    self.dev_type = DEV_TYPE_PCIe_BRIDGE
                    if type == PCI_EXP_TYPE_DOWNSTREAM:
                        self.is_downstream_port = True
                        pos = self.find_ext_cap(PCI_EXT_CAP_ID_ACS)
                        if pos != 0:
                            ctrl = self.pci_conf_read16(pos + PCI_EXT_ACS_CTRL)
                            if (ctrl & PCI_EXT_CAP_ACS_ENABLED) == \
                                (PCI_EXT_CAP_ACS_ENABLED):
                                self.acs_enabled = True
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
            else:
                # Quirk for the VF of Intel 82599 10GbE Controller.
                # We know it does have PCIe FLR capability even if it doesn't
                # report that (dev_cap.PCI_EXP_DEVCAP_FLR is 0).
                # See the 82599 datasheet.
                dev_path = find_sysfs_mnt()+SYSFS_PCI_DEVS_PATH+'/'+self.name
                vendor_id = parse_hex(os.popen('cat %s/vendor' % dev_path).read())
                device_id = parse_hex(os.popen('cat %s/device' % dev_path).read())
                if  (vendor_id == VENDOR_INTEL) and \
                    (device_id == DEVICE_ID_82599):
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
            dev = PciDevice(parse_pci_name(pci_dev))
            if dev.driver == 'pciback' or dev.driver == 'pci-stub':
                continue
            err_msg = 'pci: %s must be co-assigned to the same guest with %s' + \
                ', but it is not owned by pciback or pci-stub.'
            raise PciDeviceAssignmentError(err_msg % (pci_dev, self.name))

    def do_FLR(self, is_hvm, strict_check):
        """ Perform FLR (Functional Level Reset) for the device.
        """
        if self.dev_type == DEV_TYPE_PCIe_ENDPOINT:
            # If PCIe device supports FLR, we use it.
            if self.pcie_flr:
                (pci_list, cfg_list) = save_pci_conf_space([self.name])
                pos = self.find_cap_offset(PCI_CAP_ID_EXP)
                self.pci_conf_write32(pos + PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_FLR)
                # We must sleep at least 100ms for the completion of FLR
                time.sleep(0.100)
                restore_pci_conf_space((pci_list, cfg_list))
            else:
                if self.bus == 0:
                    self.do_FLR_for_integrated_device()
                else:
                    funcs = self.find_all_the_multi_functions()

                    if not is_hvm and (len(funcs) > 1):
                        return
                    if is_hvm and not strict_check:
                        return

                    self.devs_check_driver(funcs)

                    parent = pci_dict_to_bdf_str(self.find_parent())

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
                time.sleep(0.100)
                restore_pci_conf_space((pci_list, cfg_list))
            else:
                if self.bus == 0:
                    self.do_FLR_for_integrated_device()
                else:
                    devs = self.find_coassigned_pci_devices(False)
                    # Remove the element 0 which is a bridge
                    target_bus = devs[0]
                    del devs[0]

                    if not is_hvm and (len(devs) > 1):
                        return
                    if is_hvm and not strict_check:
                        return

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
        global lspci_info_lock

        lspci_info_lock.acquire()
        try:
            if lspci_info is None:
                _create_lspci_info()

            device_info = lspci_info.get(self.name)
            if device_info:
                try:
                    self.revision = int(device_info.get('Rev', '0'), 16)
                except ValueError:
                    pass
                self.vendorname = device_info.get('Vendor', '')
                self.devicename = device_info.get('Device', '')
                self.classname = device_info.get('Class', '')
                self.subvendorname = device_info.get('SVendor', '')
                self.subdevicename = device_info.get('SDevice', '')
                return True
        finally:
            lspci_info_lock.release()

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
