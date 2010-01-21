#!/usr/bin/env python
#  -*- mode: python; -*-

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
# Copyright (C) 2008 FUJITSU Limited
#                     Based on the blkif.py
#============================================================================


"""Support for VSCSI Devices.
"""
import os
import os.path
import sys
import re
import string
from xen.util import utils

SYSFS_SCSI_PATH = "/bus/scsi/devices"
SYSFS_SCSI_DEV_VENDOR_PATH = '/vendor'
SYSFS_SCSI_DEV_MODEL_PATH = '/model'
SYSFS_SCSI_DEV_TYPEID_PATH = '/type'
SYSFS_SCSI_DEV_REVISION_PATH = '/rev'
SYSFS_SCSI_DEV_SCSILEVEL_PATH = '/scsi_level'

SCSI_ID_COMMANDS = [
    "/lib/udev/scsi_id -gu --sg-version 3 -d /dev/%s 2>/dev/null",
    "/sbin/scsi_id -gu -s /class/scsi_generic/%s 2>/dev/null"
]

def _vscsi_get_devname_by(name, scsi_devices):
    """A device name is gotten by the HCTL.
    (e.g., '0:0:0:0' to '/dev/sda')
    """

    try:
        search = re.compile(r'' + name + '$', re.DOTALL)
    except Exception, e:
        raise VmError("vscsi: invalid expression. " + str(e))

    for hctl, devname, sg, scsi_id in scsi_devices:
        if search.match(hctl):
            return (hctl, devname)

    return (None, None)


def _vscsi_get_hctl_by(phyname, scsi_devices):
    """An HCTL is gotten by the device name or the scsi_id.
    (e.g., '/dev/sda' to '0:0:0:0')
    """
    
    if re.match('/dev/sd[a-z]+([1-9]|1[0-5])?$', phyname):
        # sd driver
        name = re.sub('(^/dev/)|([1-9]|1[0-5])?$', '', phyname)
    elif re.match('/dev/sg[0-9]+$', phyname):
        # sg driver
        name = re.sub('^/dev/', '', phyname)
    elif re.match('/dev/st[0-9]+$', phyname):
        # st driver
        name = re.sub('^/dev/', '', phyname)
    else:
        # scsi_id -gu
        name = phyname

    for hctl, devname, sg, scsi_id in scsi_devices:
        if name in [devname, sg, scsi_id]:
            return (hctl, devname)

    return (None, None)


def _vscsi_get_scsiid(sg):
    for scsi_id_command in SCSI_ID_COMMANDS:
        scsi_id = os.popen(scsi_id_command % sg).read().split()
        if len(scsi_id):
            return scsi_id[0]
    return None


def _vscsi_get_scsidevices_by_lsscsi(option = ""):
    """ get all scsi devices information by lsscsi """

    devices = []

    for scsiinfo in os.popen('{ lsscsi -g %s; } 2>/dev/null' % option).readlines():
        s = scsiinfo.split()
        hctl = s[0][1:-1]
        try:
            devname = s[-2].split('/dev/')[1]
        except IndexError:
            devname = None
        try:
            sg = s[-1].split('/dev/')[1]
            scsi_id = _vscsi_get_scsiid(sg)
        except IndexError:
            sg = None
            scsi_id = None
        devices.append([hctl, devname, sg, scsi_id])

    return devices


def _vscsi_get_scsidevices_by_sysfs():
    """ get all scsi devices information by sysfs """

    devices = []
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
    except:
        return devices

    if sysfs_mnt is None:
        return devices

    for dirpath, dirnames, files in os.walk(sysfs_mnt + SYSFS_SCSI_PATH):
        for hctl in dirnames:
            paths = os.path.join(dirpath, hctl)
            devname = None
            sg = None
            scsi_id = None
            for f in os.listdir(paths):
                realpath = os.path.realpath(os.path.join(paths, f))
                if  re.match('^block', f) or \
                    re.match('^tape', f) or \
                    re.match('^scsi_changer', f) or \
                    re.match('^onstream_tape', f):
                    devname = os.path.basename(realpath)

                if re.match('^scsi_generic', f):
                    sg = os.path.basename(realpath)
                    scsi_id = _vscsi_get_scsiid(sg)
            devices.append([hctl, devname, sg, scsi_id])

    return devices


def vscsi_get_scsidevices():
    """ get all scsi devices information """

    devices = _vscsi_get_scsidevices_by_lsscsi("")
    if devices:
        return devices
    return _vscsi_get_scsidevices_by_sysfs()


def vscsi_get_hctl_and_devname_by(target, scsi_devices = None):
    if scsi_devices is None:
        if len(target.split(':')) == 4:
            scsi_devices = _vscsi_get_scsidevices_by_lsscsi(target)
        elif target.startswith('/dev/'): 
            scsi_devices = _vscsi_get_scsidevices_by_lsscsi("| grep %s" % target)
        else:
            scsi_devices = _vscsi_get_scsidevices_by_lsscsi("")
        if not scsi_devices:
            scsi_devices = _vscsi_get_scsidevices_by_sysfs()

    if len(target.split(':')) == 4:
        return _vscsi_get_devname_by(target, scsi_devices)
    else:
        return _vscsi_get_hctl_by(target, scsi_devices)


def get_scsi_vendor(pHCTL):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_scsi_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_SCSI_PATH, pHCTL)
        scsi_vendor = \
            os.popen('cat ' + sysfs_scsi_dev_path + \
                              SYSFS_SCSI_DEV_VENDOR_PATH).read()
        return scsi_vendor.splitlines()[0]
    except:
        return None

def get_scsi_model(pHCTL):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_scsi_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_SCSI_PATH, pHCTL)
        scsi_model = \
            os.popen('cat ' + sysfs_scsi_dev_path + \
                              SYSFS_SCSI_DEV_MODEL_PATH).read()
        return scsi_model.splitlines()[0]
    except:
        return None

def get_scsi_typeid(pHCTL):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_scsi_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_SCSI_PATH, pHCTL)
        scsi_typeid = \
            os.popen('cat ' + sysfs_scsi_dev_path + \
                              SYSFS_SCSI_DEV_TYPEID_PATH).read()
        return int(scsi_typeid.splitlines()[0])
    except:
        return None

def get_scsi_revision(pHCTL):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_scsi_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_SCSI_PATH, pHCTL)
        scsi_revision = \
            os.popen('cat ' + sysfs_scsi_dev_path + \
                              SYSFS_SCSI_DEV_REVISION_PATH).read()
        return scsi_revision.splitlines()[0]
    except:
        return None

def get_scsi_scsilevel(pHCTL):
    try:
        sysfs_mnt = utils.find_sysfs_mount() 
        sysfs_scsi_dev_path = \
            os.path.join(sysfs_mnt + SYSFS_SCSI_PATH, pHCTL)
        scsi_scsilevel = \
            os.popen('cat ' + sysfs_scsi_dev_path + \
                              SYSFS_SCSI_DEV_SCSILEVEL_PATH).read()
        return int(scsi_scsilevel.splitlines()[0])
    except:
        return None

def _make_scsi_record(scsi_info):
    scsi_rec = {
        'physical_HCTL': scsi_info[0],
        'dev_name': None,
        'sg_name': scsi_info[2],
        'scsi_id': None
    }
    if scsi_info[1] is not None:
        scsi_rec['dev_name'] = scsi_info[1] 
    if scsi_info[3] is not None:
        scsi_rec['scsi_id'] = scsi_info[3] 

    scsi_rec['vendor_name'] = \
        get_scsi_vendor(scsi_rec['physical_HCTL'])
    scsi_rec['model'] = \
        get_scsi_model(scsi_rec['physical_HCTL'])
    scsi_rec['type_id'] = \
        get_scsi_typeid(scsi_rec['physical_HCTL'])
    scsi_rec['revision'] = \
        get_scsi_revision(scsi_rec['physical_HCTL'])
    scsi_rec['scsi_level'] = \
        get_scsi_scsilevel(scsi_rec['physical_HCTL'])

    try:
        lsscsi_info = os.popen('lsscsi %s 2>/dev/null' % scsi_rec['physical_HCTL']).read().split()
        scsi_rec['type'] = lsscsi_info[1]
    except:
        scsi_rec['type'] = None

    return scsi_rec

def get_scsi_device(pHCTL):
    scsis_info = _vscsi_get_scsidevices_by_lsscsi(pHCTL)
    if not scsis_info:
        scsis_info = _vscsi_get_scsidevices_by_sysfs()
    for scsi_info in scsis_info:
        if scsi_info[0] == pHCTL:
            return _make_scsi_record(scsi_info)
    return None

def get_all_scsi_devices():
    scsi_records = []
    for scsi_info in vscsi_get_scsidevices():
        scsi_record = _make_scsi_record(scsi_info)
        scsi_records.append(scsi_record)
    return scsi_records

