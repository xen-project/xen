#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2009, FUJITSU LABORATORIES LTD.
#  Author: Noboru Iwamatsu <n_iwamatsu@jp.fujitsu.com>
#============================================================================


"""Support for VUSB Devices.
"""
import os
import os.path
import sys
import re
import string
from xen.util import utils

SYSFS_USB_DEVS_PATH = '/bus/usb/devices'
SYSFS_USB_DEV_BDEVICECLASS_PATH = '/bDeviceClass'
SYSFS_USB_DEV_BDEVICESUBCLASS_PATH = '/bDeviceSubClass'
SYSFS_USB_DEV_DEVNUM_PATH = '/devnum'
SYSFS_USB_DEV_IDVENDOR_PATH = '/idVendor'
SYSFS_USB_DEV_IDPRODUCT_PATH = '/idProduct'
SYSFS_USB_DEV_MANUFACTURER_PATH = '/manufacturer'
SYSFS_USB_DEV_PRODUCT_PATH = '/product'
SYSFS_USB_DEV_SERIAL_PATH = '/serial'
SYSFS_USB_DEV_DRIVER_PATH = '/driver'
SYSFS_USB_DRIVER_BIND_PATH = '/bind'
SYSFS_USB_DRIVER_UNBIND_PATH = '/unbind'
SYSFS_USBBACK_PATH = '/bus/usb/drivers/usbback'
SYSFS_PORTIDS_PATH = '/port_ids'
USBHUB_CLASS_CODE = '09'

def get_usb_bDeviceClass(dev):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_usb_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_USB_DEVS_PATH, dev)
        if os.path.exists(sysfs_usb_dev_path + SYSFS_USB_DEV_BDEVICECLASS_PATH):
            usb_deviceclass = \
                os.popen('cat ' + sysfs_usb_dev_path + \
                              SYSFS_USB_DEV_BDEVICECLASS_PATH).readline()
            return usb_deviceclass.splitlines()[0]
        else:
            return ""
    except:
        return None

def get_usb_bDeviceSubClass(dev):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_usb_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_USB_DEVS_PATH, dev)
        if os.path.exists(sysfs_usb_dev_path + SYSFS_USB_DEV_BDEVICESUBCLASS_PATH):
            usb_devicesubclass = \
                os.popen('cat ' + sysfs_usb_dev_path + \
                              SYSFS_USB_DEV_BDEVICESUBCLASS_PATH).readline()
            return usb_devicesubclass.splitlines()[0]
        else:
            return ""
    except:
        return None

def get_usb_devnum(dev):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_usb_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_USB_DEVS_PATH, dev)
        if os.path.exists(sysfs_usb_dev_path + SYSFS_USB_DEV_DEVNUM_PATH):
            usb_devicesubclass = \
                os.popen('cat ' + sysfs_usb_dev_path + \
                              SYSFS_USB_DEV_DEVNUM_PATH).readline()
            return usb_devicesubclass.splitlines()[0]
        else:
            return ""
    except:
        return None

def get_usb_idvendor(dev):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_usb_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_USB_DEVS_PATH, dev)
        if os.path.exists(sysfs_usb_dev_path + SYSFS_USB_DEV_IDVENDOR_PATH):
            usb_idvendor = \
                os.popen('cat ' + sysfs_usb_dev_path + \
                              SYSFS_USB_DEV_IDVENDOR_PATH).readline()
            return usb_idvendor.splitlines()[0]
        else:
            return ""
    except:
        return None

def get_usb_idproduct(dev):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_usb_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_USB_DEVS_PATH, dev)
        if os.path.exists(sysfs_usb_dev_path + SYSFS_USB_DEV_IDPRODUCT_PATH):
            usb_idproduct = \
                os.popen('cat ' + sysfs_usb_dev_path + \
                              SYSFS_USB_DEV_IDPRODUCT_PATH).readline()
            return usb_idproduct.splitlines()[0]
        else:
            return ""
    except:
        return None

def get_usb_manufacturer(dev):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_usb_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_USB_DEVS_PATH, dev)

        if os.path.exists(sysfs_usb_dev_path + SYSFS_USB_DEV_MANUFACTURER_PATH):
            usb_manufacturer = \
                os.popen('cat ' + sysfs_usb_dev_path + \
                              SYSFS_USB_DEV_MANUFACTURER_PATH).readline()
            return usb_manufacturer.splitlines()[0]
        else:
            return ""
    except:
        return None

def get_usb_product(dev):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_usb_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_USB_DEVS_PATH, dev)
        if os.path.exists(sysfs_usb_dev_path + SYSFS_USB_DEV_PRODUCT_PATH):
            usb_product = \
                os.popen('cat ' + sysfs_usb_dev_path + \
                              SYSFS_USB_DEV_PRODUCT_PATH).readline()
            return usb_product.splitlines()[0]
        else:
            return ""
    except:
        return None

def get_usb_serial(dev):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_usb_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_USB_DEVS_PATH, dev)
        if os.path.exists(sysfs_usb_dev_path + SYSFS_USB_DEV_SERIAL_PATH):
            usb_serial = \
                os.popen('cat ' + sysfs_usb_dev_path + \
                              SYSFS_USB_DEV_SERIAL_PATH).readline()
            return usb_serial.splitlines()[0]
        else:
            return ""
    except:
        return None

def get_usbdevice_info_by_lsusb(dev):
    try:
        vend = get_usb_idvendor(dev)
        prod = get_usb_idproduct(dev)
        output = os.popen('lsusb -d ' + vend + ':' + prod).readline().split()
        text = ""
        if len(output) > 6:
            for str in output[6:]:
                if text != "":
                    text= text + ' '
                text = text + str
            return text
        else:
            return ""
    except:
        return None

def get_usbdevice_info(dev):
    try:
        manuf = get_usb_manufacturer(dev)
        prod = get_usb_product(dev)
        if manuf == "" or prod == "":
            return get_usbdevice_info_by_lsusb(dev)
        else:
            return manuf + ' ' + prod
    except:
        return None

def usb_device_is_hub(dev):
    usb_classcode = get_usb_bDeviceClass(dev)
    if (usb_classcode == USBHUB_CLASS_CODE):
        return True
    else:
        return False

def get_all_usb_names():
    usb_names = []
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        usb_names = os.popen('ls ' + sysfs_mnt + SYSFS_USB_DEVS_PATH).read().split()
    except:
        pass
    return usb_names

def get_usb_devices():
    devs = []
    for name in get_all_usb_names():
        dev_match = re.match(r"(^(?P<bus>[0-9]{1,2})[-,])" + \
                     r"(?P<root_port>[0-9]{1,2})" + \
                     r"(?P<port>([\.,]{1}[0-9]{1,2}){0,5})$", name)
        if dev_match is not None:
            dev = dev_match.group('bus') + '-' \
            + dev_match.group('root_port') \
            + dev_match.group('port') 
            if (usb_device_is_hub(dev)):
                continue
            else:
                devs.append(dev)
    return devs

def get_usb_intfs(dev):
    intfs = []
    try:
        search = re.compile(r'^' + dev + ':')
    except:
        raise UsbDeviceParseError("Invalid expression.")
    for name in get_all_usb_names():
        if search.match(name):
            intfs.append(name)
    return intfs

def get_assigned_buses():
    buses = []
    try:
        sysfs_mnt = utils.find_sysfs_mount()
        if os.path.exists(sysfs_mnt + SYSFS_USBBACK_PATH + SYSFS_PORTIDS_PATH):
            portids = \
                os.popen('cat ' + sysfs_mnt + SYSFS_USBBACK_PATH + SYSFS_PORTIDS_PATH).read().splitlines()
            for portid in portids:
                buses.append(portid.split(':')[0])
    except:
        raise UsbDeviceParseError("Can't get assigned buses from port_ids.")
    return buses

def get_assigned_bus(domid, dev, port):
    bus = ""
    try:
        sysfs_mnt = utils.find_sysfs_mount()
        if os.path.exists(sysfs_mnt + SYSFS_USBBACK_PATH + SYSFS_PORTIDS_PATH):
            portids = \
                os.popen('cat ' + sysfs_mnt + SYSFS_USBBACK_PATH + SYSFS_PORTIDS_PATH).read().splitlines()
        for portid in portids:
            if portid.split(':')[1] == str(domid) and portid.split(':')[2] == str(dev) and portid.split(':')[3] == str(port):
                bus = portid.split(':')[0]
    except:
        raise UsbDeviceParseError("Can't get assigned bus (%d:%d:%d)." % (domid, dev, port))
    return bus

def bus_is_assigned(bus):
    assigned = False    
    try:
        sysfs_mnt = utils.find_sysfs_mount()
        if os.path.exists(sysfs_mnt + SYSFS_USBBACK_PATH + SYSFS_PORTIDS_PATH):
            portids = \
                os.popen('cat ' + sysfs_mnt + SYSFS_USBBACK_PATH + SYSFS_PORTIDS_PATH).read().splitlines()
        for portid in portids:
            if portid.split(':')[0] == bus:
                assigned = True
    except:
        raise UsbDeviceParseError("Can't get assignment status: (%s)." % bus)
    return assigned

def usb_intf_is_binded(intf):
    if os.path.exists(SYSFS_USBBACK_PATH + '/' + intf):
        return True
    else:
        return False

def usb_device_is_connected(dev):
    try:
        sysfs_mnt = utils.find_sysfs_mount()
        sysfs_dev_path = \
                os.path.join(sysfs_mnt + SYSFS_USB_DEVS_PATH, dev)
        if os.path.exists(sysfs_dev_path):
            return True
        else:
            return False
    except:
        raise UsbDeviceParseError("Can't get connection status (%s)." % dev)

def unbind_usb_device(dev):
    try:
        sysfs_mnt = utils.find_sysfs_mount()
        for intf in get_usb_intfs(dev): 
            sysfs_usb_intf_path = \
                os.path.join(sysfs_mnt + SYSFS_USB_DEVS_PATH, intf)
            if os.path.exists(sysfs_usb_intf_path + SYSFS_USB_DEV_DRIVER_PATH):
                fd = os.open(sysfs_usb_intf_path + \
                             SYSFS_USB_DEV_DRIVER_PATH + \
                             SYSFS_USB_DRIVER_UNBIND_PATH, os.O_WRONLY)
                os.write(fd, intf)
                os.close(fd)
    except:
        raise UsbDeviceBindingError("can't unbind intf (%s). " % intf)

def bind_usb_device(dev):
    try:
        sysfs_mnt = utils.find_sysfs_mount()
        for intf in get_usb_intfs(dev): 
            sysfs_usb_intf_path = \
                os.path.join(sysfs_mnt + SYSFS_USB_DEVS_PATH, intf)
            if os.path.exists(sysfs_usb_intf_path + SYSFS_USB_DEV_DRIVER_PATH):
                unbind_usb_device(dev)

            fd = os.open(sysfs_mnt + SYSFS_USBBACK_PATH + \
                         SYSFS_USB_DRIVER_BIND_PATH, os.O_WRONLY)
            os.write(fd, intf)
            os.close(fd)
    except:
        raise UsbDeviceBindingError("can't bind intf (%s). " % intf)

class UsbDeviceParseError(Exception):
    def __init__(self,msg):
        self.message = msg
    def __str__(self):
        return 'vusb: Error parsing USB device info: '+self.message

class UsbDeviceBindingError(Exception):
    def __init__(self,msg):
        self.message = msg
    def __str__(self):
        return 'vusb: Failed to bind/unbind USB device: ' + \
            self.message
