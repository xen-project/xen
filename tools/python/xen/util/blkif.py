import os
import re
import string

from xen.util.ip import _readline, _readlines

def expand_dev_name(name):
    if not name:
        return name
    if re.match( '^/dev/', name ):
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
        log.debug("exception looking up device number for %s: %s", name, ex)
        pass

    if re.match( '/dev/sd[a-p]([0-9]|1[0-5])', n):
        return 8 * 256 + 16 * (ord(n[7:8]) - ord('a')) + int(n[8:])

    if re.match( '/dev/hd[a-t]([1-9]|[1-5][0-9]|6[0-3])?', n):
        ide_majors = [ 3, 22, 33, 34, 56, 57, 88, 89, 90, 91 ]
        major = ide_majors[(ord(n[7:8]) - ord('a')) / 2]
        minor = ((ord(n[7:8]) - ord('a')) % 2) * 64 + int(n[8:] or 0)
        return major * 256 + minor

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
    if n:
        val = { 'device'       : n,
                'start_sector' : long(0),
                'nr_sectors'   : long(1L<<63),
                'type'         : 'Disk' }
    return val

def blkdev_uname_to_file(uname):
    """Take a blkdev uname and return the corresponding filename."""
    fn = None
    if uname.find(":") != -1:
        (typ, fn) = uname.split(":")
        if typ == "phy" and not fn.startswith("/dev/"):
            fn = "/dev/%s" %(fn,)
    return fn

def mount_mode(name):
    mode = None
    name = expand_dev_name(name)
    lines = _readlines(os.popen('mount 2>/dev/null'))
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
    
