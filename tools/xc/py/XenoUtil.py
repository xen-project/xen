
import string, re, os

def blkdev_name_to_number(name):
    """Take the given textual block-device name (e.g., '/dev/sda1',
    'hda') and return the device number used by the OS. """

    if not re.match( '/dev/', name ):
        name = '/dev/' + name
        
    fd = os.popen( '/bin/ls -lL ' + name + ' 2>/dev/null' )
    line = fd.readline()

    #brw-rw----    1 root     mail       8,   3 Aug 30  2001 /dev/sda3
    m = re.search( '^b\S+\s+\d+\s+\S+\s+\S+\s+(\d+),\s+(\d+)\s+\S+\s+\d+' +
                   '\s+\d+\s+' + name + '$', line )

    if m:
        # hack -- we just assume device minors are 8 bits
        return (string.atol(m.group(1)) << 8) + string.atol(m.group(2))
    return None


# lookup_blkdev_partn_info( '/dev/sda3' )
def lookup_blkdev_partn_info(partition):
    """Take the given block-device name (e.g., '/dev/sda1', 'hda')
    and return a information tuple ( partn-dev, disc-dev, start-sect,
    nr-sects, type )
        partn-dev:  Device number of the given partition
        disc-dev:   Device number of the disc containing the partition
        start-sect: Index of first sector of the partition
        nr-sects:   Number of sectors comprising this partition
        type:       'Disk' or identifying name for partition type
    """

    if not re.match( '/dev/', partition ):
        partition = '/dev/' + partition

    drive = re.split( '[0-9]', partition )[0]

    if drive == partition:
        fd = os.popen( '/sbin/sfdisk -s ' + drive + ' 2>/dev/null' )
        line = fd.readline()
        if line:
            return ( blkdev_name_to_number(drive),
                     blkdev_name_to_number(drive),
                     0,
                     string.atol(line) * 2,
                     'Disk' )
        return None

    # determine position on disk
    fd = os.popen( '/sbin/sfdisk -d ' + drive + ' 2>/dev/null' )

    #['/dev/sda3 : start= 16948575, size=16836120, Id=83, bootable\012']
    lines = fd.readlines()
    for line in lines:
        m = re.search( '^' + partition + '\s*: start=\s*([0-9]+), ' +
                       'size=\s*([0-9]+), Id=\s*(\S+).*$', line)
        if m:
            return ( blkdev_name_to_number(partition),
                     blkdev_name_to_number(drive),
                     string.atol(m.group(1)),
                     string.atol(m.group(2)),
                     m.group(3) )
    return None
