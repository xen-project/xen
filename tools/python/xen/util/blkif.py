import os
import re
import string

from xen.xend.XendLogging import log

def expand_dev_name(name):
    if not name:
        return name
    if re.match( '^/', name ):
        return name
    else:
        return '/dev/' + name

def blkdev_name_to_number(name):
    """Take the given textual block-device name (e.g., '/dev/sda1',
    'hda') and return the device number used by the OS. """

    n = expand_dev_name(name)

    try:
        return os.stat(n).st_rdev
    except Exception, ex:
        pass

    scsi_major = [ 8, 65, 66, 67, 68, 69, 70, 71, 128, 129, 130, 131, 132, 133, 134, 135 ]
    if re.match( '/dev/sd[a-z]([1-9]|1[0-5])?$', n):
        major = scsi_major[(ord(n[7:8]) - ord('a')) / 16]
        minor = ((ord(n[7:8]) - ord('a')) % 16) * 16 + int(n[8:] or 0)
        return major * 256 + minor
    if re.match( '/dev/sd[a-i][a-z]([1-9]|1[0-5])?$', n):
        major = scsi_major[((ord(n[7:8]) - ord('a') + 1) * 26 + (ord(n[8:9]) - ord('a'))) / 16 ]
        minor = (((ord(n[7:8]) - ord('a') + 1 ) * 26 + (ord(n[8:9]) - ord('a'))) % 16) * 16 + int(n[9:] or 0)
        return major * 256 + minor

    if re.match( '/dev/hd[a-t]([1-9]|[1-5][0-9]|6[0-3])?', n):
        ide_majors = [ 3, 22, 33, 34, 56, 57, 88, 89, 90, 91 ]
        major = ide_majors[(ord(n[7:8]) - ord('a')) / 2]
        minor = ((ord(n[7:8]) - ord('a')) % 2) * 64 + int(n[8:] or 0)
        return major * 256 + minor

    if re.match( '/dev/xvd[a-p]([1-9]|1[0-5])?', n):
        return 202 * 256 + 16 * (ord(n[8:9]) - ord('a')) + int(n[9:] or 0)

    # see if this is a hex device number
    if re.match( '^(0x)?[0-9a-fA-F]+$', name ):
        return string.atoi(name,16)
        
    return None

def blkdev_segment(name):
    """Take the given block-device name (e.g. '/dev/sda1', 'hda')
    and return a dictionary { device, start_sector,
    nr_sectors, type }
        device:       Device number of the given partition
        start_sector: Index of first sector of the partition
        nr_sectors:   Number of sectors comprising this partition
        type:         'Disk' or identifying name for partition type
    """
    val = None
    n = blkdev_name_to_number(name)
    if not n is None:
        val = { 'device'       : n,
                'start_sector' : long(0),
                'nr_sectors'   : long(1L<<63),
                'type'         : 'Disk' }
    return val

def _parse_uname(uname):
    fn = taptype = None
    if uname.find(":") != -1:
        (typ, fn) = uname.split(":", 1)
        if typ == "phy" and not fn.startswith("/"):
            fn = "/dev/%s" %(fn,)
        if typ == "tap":
            (taptype, fn) = fn.split(":", 1)
    return (fn, taptype)

def blkdev_uname_to_file(uname):
    """Take a blkdev uname and return the corresponding filename."""
    return _parse_uname(uname)[0]

def blkdev_uname_to_taptype(uname):
    """Take a blkdev uname and return the blktap type."""
    return _parse_uname(uname)[1]

def mount_mode(name):
    mode = None
    name = expand_dev_name(name)
    lines = os.popen('mount 2>/dev/null').readlines()
    exp = re.compile('^' + name + ' .*[\(,]r(?P<mode>[ow])[,\)]')
    for line in lines:
        pm = exp.match(line)
        if not pm: continue
        mode = pm.group('mode')
        break
    if mode == 'w':
        return mode
    if mode == 'o':
        mode = 'r'
    return mode
    
