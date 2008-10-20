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

def _vscsi_hctl_block(name, scsi_devices):
    """ block-device name is convert into hctl. (e.g., '/dev/sda',
    '0:0:0:0')"""
    try:
        search = re.compile(r'' + name + '$', re.DOTALL)
    except Exception, e:
        raise VmError("vscsi: invalid expression. " + str(e))
    chk = 0
    for hctl, block, sg, scsi_id in scsi_devices:
        if search.match(hctl):
            chk = 1
            break

    if chk:
        return (hctl, block)
    else:
        return (None, None)


def _vscsi_block_scsiid_to_hctl(phyname, scsi_devices):
    """ block-device name is convert into hctl. (e.g., '/dev/sda',
    '0:0:0:0')"""
    
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

    chk = 0
    for hctl, block, sg, scsi_id in scsi_devices:
        if block == name:
            chk = 1
            break
        elif sg == name:
            chk = 1
            break
        elif scsi_id == name:
            chk = 1
            break

    if chk:
        return (hctl, block)
    else:
        return (None, None)


def vscsi_get_scsidevices():
    """ get all scsi devices"""

    # KAF: Stubbed out for now due to bogus use of os.chdir() and because
    # the devices.append() line can fail due to sg and scsi_id not defined.
    return []

    devices = []
    sysfs_mnt = utils.find_sysfs_mount() 

    for dirpath, dirnames, files in os.walk(sysfs_mnt + SYSFS_SCSI_PATH):
        for hctl in dirnames:
            paths = os.path.join(dirpath, hctl)
            block = "-"
            for f in os.listdir(paths):
                if re.match('^block', f):
                    os.chdir(os.path.join(paths, f))
                    block = os.path.basename(os.getcwd())
                elif re.match('^tape', f):
                    os.chdir(os.path.join(paths, f))
                    block = os.path.basename(os.getcwd())
                elif re.match('^scsi_changer', f):
                    os.chdir(os.path.join(paths, f))
                    block = os.path.basename(os.getcwd())
                elif re.match('^onstream_tape', f):
                    os.chdir(os.path.join(paths, f))
                    block = os.path.basename(os.getcwd())

                if re.match('^scsi_generic', f):
                    os.chdir(os.path.join(paths, f))
                    sg = os.path.basename(os.getcwd())
                    lines = os.popen('/sbin/scsi_id -gu -s /class/scsi_generic/' + sg).read().split()
                    if len(lines) == 0:
                        scsi_id = '-'
                    else:
                        scsi_id = lines[0]

            devices.append([hctl, block, sg, scsi_id])

    return devices


def vscsi_search_hctl_and_block(device):

    scsi_devices = vscsi_get_scsidevices()

    tmp = device.split(':')
    if len(tmp) == 4:
        (hctl, block) = _vscsi_hctl_block(device, scsi_devices)
    else:
        (hctl, block) = _vscsi_block_scsiid_to_hctl(device, scsi_devices)

    return (hctl, block)


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

def get_all_scsi_devices():

    scsi_devs = []

    for scsi_info in vscsi_get_scsidevices():
        scsi_dev = {
            'physical_HCTL': scsi_info[0],
            'dev_name': None,
            'sg_name': scsi_info[2],
            'scsi_id': None
        }
        if scsi_info[1] != '-':
            scsi_dev['dev_name'] = scsi_info[1] 
        if scsi_info[3] != '-':
            scsi_dev['scsi_id'] = scsi_info[3] 

        scsi_dev['vendor_name'] = \
            get_scsi_vendor(scsi_dev['physical_HCTL'])
        scsi_dev['model'] = \
            get_scsi_model(scsi_dev['physical_HCTL'])
        scsi_dev['type_id'] = \
            get_scsi_typeid(scsi_dev['physical_HCTL'])
        scsi_dev['revision'] = \
            get_scsi_revision(scsi_dev['physical_HCTL'])
        scsi_dev['scsi_level'] = \
            get_scsi_scsilevel(scsi_dev['physical_HCTL'])

        try:
            lsscsi_info = os.popen('lsscsi ' + scsi_dev['physical_HCTL']).read().split()
            scsi_dev['type'] = lsscsi_info[1]
        except:
            scsi_dev['type'] = None

        scsi_devs.append(scsi_dev)

    return scsi_devs

