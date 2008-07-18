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
import sys
import re
import string

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

    SERCH_SCSI_PATH = "/sys/bus/scsi/devices"
    devices = []

    for dirpath, dirnames, files in os.walk(SERCH_SCSI_PATH):
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

