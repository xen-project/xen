import os, re, socket, string, sys, tempfile

##### Module variables

"""Location of the Virtual Disk management database.
   defaults to /var/db/xen_vdisks.sqlite
"""
VD_DB_FILE = "/var/db/xen_vdisks.sqlite"

"""VBD expertise level - determines the strictness of the sanity checking.
  This mode determines the level of complaints when disk sharing occurs
  through the current VBD mappings.
   0 - only allow shared mappings if both domains have r/o access (always OK)
   1 - also allow sharing with one dom r/w and the other r/o
   2 - allow sharing with both doms r/w
"""
VBD_EXPERT_MODE = 0

##### Module initialisation

try:
    # try to import sqlite (not everyone will have it installed)
    import sqlite
except ImportError:
    # on failure, just catch the error, don't do anything
    pass


##### Networking-related functions

def get_current_ipaddr(dev='eth0'):
    """Return a string containing the primary IP address for the given
    network interface (default 'eth0').
    """
    fd = os.popen( '/sbin/ifconfig ' + dev + ' 2>/dev/null' )
    lines = fd.readlines()
    for line in lines:
        m = re.search( '^\s+inet addr:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*',
                       line )
        if m:
            return m.group(1)
    return None

def get_current_ipmask(dev='eth0'):
    """Return a string containing the primary IP netmask for the given
    network interface (default 'eth0').
    """
    fd = os.popen( '/sbin/ifconfig ' + dev + ' 2>/dev/null' )
    lines = fd.readlines()
    for line in lines:
        m = re.search( '^.+Mask:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*',
                       line )
        if m:
            return m.group(1)
    return None

def get_current_ipgw():
    """Return a string containing the default IP gateway."""
    fd = os.popen( '/sbin/route -n' )
    lines = fd.readlines()
    for line in lines:
        m = re.search( '^0.0.0.0+\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)' +
                       '\s+0.0.0.0+\s+\S*G.*', line )
        if m:
            return m.group(1)
    return None

def setup_vfr_rules_for_vif(dom,vif,addr):
    """Takes a tuple ( domain-id, vif-id, ip-addr ), where the ip-addr
    is expressed as a textual dotted quad, and set up appropriate routing
    rules in Xen. No return value.
    """
    fd = os.open( '/proc/xen/vfr', os.O_WRONLY )
    if ( re.search( '169\.254', addr) ):
        os.write( fd, 'ADD ACCEPT srcaddr=' + addr +
                  ' srcaddrmask=255.255.255.255' +
                  ' srcdom=' + str(dom) + ' srcidx=' + str(vif) +
                  ' dstdom=0 dstidx=0 proto=any\n' )
    else:
        os.write( fd, 'ADD ACCEPT srcaddr=' + addr +
                  ' srcaddrmask=255.255.255.255' +
                  ' srcdom=' + str(dom) + ' srcidx=' + str(vif) +
                  ' dst=PHYS proto=any\n' )
    os.write( fd, 'ADD ACCEPT dstaddr=' + addr +
              ' dstaddrmask=255.255.255.255' +
              ' src=ANY' +
              ' dstdom=' + str(dom) + ' dstidx=' + str(vif) +
              ' proto=any\n' )
    os.close( fd )
    return None

def add_offset_to_ip( ip, off ):
    l = string.split(ip,'.')
    a = ( (string.atoi(l[0])<<24) | (string.atoi(l[1])<<16) | 
	  (string.atoi(l[2])<<8)  | string.atoi(l[3]) ) + off
    
    return '%d.%d.%d.%d' % ( ((a>>24)&0xff), ((a>>16)&0xff),
			     ((a>>8)&0xff), (a&0xff) )

def check_subnet( ip, network, netmask ):
    l = string.split(ip,'.')
    n_ip = ( (string.atoi(l[0])<<24) | (string.atoi(l[1])<<16) | 
	   (string.atoi(l[2])<<8)  | string.atoi(l[3]) ) 

    l = string.split(network,'.')
    n_net = ( (string.atoi(l[0])<<24) | (string.atoi(l[1])<<16) | 
	   (string.atoi(l[2])<<8)  | string.atoi(l[3]) )

    l = string.split(netmask,'.')
    n_mask = ( (string.atoi(l[0])<<24) | (string.atoi(l[1])<<16) | 
	   (string.atoi(l[2])<<8)  | string.atoi(l[3]) )
    
    return (n_ip&n_mask)==(n_net&n_mask)


##### VBD-related Functions

def blkdev_name_to_number(name):
    """Take the given textual block-device name (e.g., '/dev/sda1',
    'hda') and return the device number used by the OS. """

    if not re.match( '/dev/', name ):
        name = '/dev/' + name
        
    return os.stat(name).st_rdev

# lookup_blkdev_partn_info( '/dev/sda3' )
def lookup_raw_partn(partition):
    """Take the given block-device name (e.g., '/dev/sda1', 'hda')
    and return a dictionary { device, start_sector,
    nr_sectors, type }
        device:       Device number of the given partition
        start_sector: Index of first sector of the partition
        nr_sectors:   Number of sectors comprising this partition
        type:         'Disk' or identifying name for partition type
    """

    if not re.match( '/dev/', partition ):
        partition = '/dev/' + partition

    drive = re.split( '[0-9]', partition )[0]

    if drive == partition:
        fd = os.popen( '/sbin/sfdisk -s ' + drive + ' 2>/dev/null' )
        line = fd.readline()
        if line:
            return [ { 'device' : blkdev_name_to_number(drive),
                       'start_sector' : long(0),
                       'nr_sectors' : long(line) * 2,
                       'type' : 'Disk' } ]
        return None

    # determine position on disk
    fd = os.popen( '/sbin/sfdisk -d ' + drive + ' 2>/dev/null' )

    #['/dev/sda3 : start= 16948575, size=16836120, Id=83, bootable\012']
    lines = fd.readlines()
    for line in lines:
        m = re.search( '^' + partition + '\s*: start=\s*([0-9]+), ' +
                       'size=\s*([0-9]+), Id=\s*(\S+).*$', line)
        if m:
            return [ { 'device' : blkdev_name_to_number(drive),
                       'start_sector' : long(m.group(1)),
                       'nr_sectors' : long(m.group(2)),
                       'type' : m.group(3) } ]
    
    return None

def lookup_disk_uname( uname ):
    """Lookup a list of segments for either a physical or a virtual device.
    uname [string]:  name of the device in the format \'vd:id\' for a virtual
                     disk, or \'phy:dev\' for a physical device
    returns [list of dicts]: list of extents that make up the named device
    """
    ( type, d_name ) = string.split( uname, ':' )

    if type == "phy":
        segments = lookup_raw_partn( d_name )
    elif type == "vd":
	segments = vd_lookup( d_name )

    return segments


##### Management of the Xen control daemon
##### (c) Keir Fraser, University of Cambridge

def xend_control_message( message ):
    """Takes a textual control message and sends it to the 'xend' Xen
    control daemon. Returns a dictionary containing the daemon's multi-part
    response."""
    tmpdir = tempfile.mkdtemp()
    try:
        ctl = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        ctl.bind(tmpdir+'/sock')
        ctl.sendto(message, '/var/run/xend/management_sock')
        data, addr = ctl.recvfrom(2048)
        ctl.close()
    finally:
        if os.path.exists(tmpdir+'/sock'):
            os.unlink(tmpdir+'/sock')
        if os.path.exists(tmpdir):
            os.rmdir(tmpdir)    
    return eval(data)


##### VD Management-related functions

##### By Mark Williamson, <mark.a.williamson@intel.com>
##### (C) Intel Research Cambridge

# TODO:
#
# Plenty of room for enhancement to this functionality (contributions
# welcome - and then you get to have your name in the source ;-)...
#
# vd_unformat() : want facilities to unallocate virtual disk
# partitions, possibly migrating virtual disks of them, with checks to see if
# it's safe and options to force it anyway
#
# vd_create() : should have an optional argument specifying a physical
# disk preference - useful to allocate for guest doms to do RAID
#
# vd_undelete() : add ability to "best effort" undelete as much of a
# vdisk as is left in the case that some of it has already been
# reallocated.  Some people might still be able to recover some of
# their data this way, even if some of the disk has disappeared.
#
# It'd be nice if we could wipe virtual disks for security purposes -
# should be easy to do this using dev if=/dev/{zero,random} on each
# extent in turn.  There could be another optional flag to vd_create
# in order to allow this.
#
# Error codes could be more expressive - i.e. actually tell why the
# error occurred rather than "it broke".  Currently the code avoids
# using exceptions to make control scripting simpler and more
# accessible to beginners - therefore probably should just use more
# return codes.
#
# Enhancements / additions to the example scripts are also welcome:
# some people will interact with this code mostly through those
# scripts.
#
# More documentation of how this stuff should be used is always nice -
# if you have a novel configuration that you feel isn't discussed
# enough in the HOWTO (which is currently a work in progress), feel
# free to contribute a walkthrough, or something more substantial.
#


def __vd_no_database():
    """Called when no database found - exits with an error
    """
    print >> sys.stderr, "ERROR: Could not locate the database file at " + VD_DB_FILE
    sys.exit(1)


def vd_format(partition, extent_size_mb):
    """Format a partition or drive for use a virtual disk storage.
    partition [string]: device file representing the partition
    extent_size_mb [string]: extent size in megabytes to use on this disk
    """

    if not os.path.isfile(VD_DB_FILE):
        vd_init_db(VD_DB_FILE)
    
    if not re.match( '/dev/', partition ):
        partition = '/dev/' + partition

    cx = sqlite.connect(VD_DB_FILE)
    cu = cx.cursor()

    cu.execute("select * from vdisk_part where partition = \'"
               + partition + "\'")
    row = cu.fetchone()

    extent_size = extent_size_mb * 2048 # convert megabytes to sectors
    
    if not row:
        part_info = lookup_raw_partn(partition)[0]
        
        cu.execute("INSERT INTO vdisk_part(partition, part_id, extent_size) " +
                   "VALUES ( \'" + partition + "\', "
                   + str(blkdev_name_to_number(partition))
                   + ", " + str(extent_size) + ")")


        cu.execute("SELECT max(vdisk_extent_no) FROM vdisk_extents "
                   + "WHERE vdisk_id = 0")
        
        max_id, = cu.fetchone()

        if max_id != None:
            new_id = max_id + 1
        else:
            new_id = 0

        num_extents = part_info['nr_sectors'] / extent_size

        for i in range(num_extents):
            sql ="""INSERT INTO vdisk_extents(vdisk_extent_no, vdisk_id,
                                              part_id, part_extent_no)
                    VALUES ("""+ str(new_id + i) + ", 0, "\
                               + str(blkdev_name_to_number(partition))\
                               + ", " + str(num_extents - (i + 1)) + ")"
            cu.execute(sql)

    cx.commit()
    cx.close()
    return 0


def vd_create(size_mb, expiry):
    """Create a new virtual disk.
    size_mb [int]: size in megabytes for the new virtual disk
    expiry [int]: expiry time in seconds from now
    """

    if not os.path.isfile(VD_DB_FILE):
        __vd_no_database()

    cx = sqlite.connect(VD_DB_FILE)
    cu = cx.cursor()

    size = size_mb * 2048

    cu.execute("SELECT max(vdisk_id) FROM vdisks")
    max_id, = cu.fetchone()
    new_id = int(max_id) + 1

    # fetch a list of extents from the expired disks, along with information
    # about their size
    cu.execute("""SELECT vdisks.vdisk_id, vdisk_extent_no, part_extent_no,
                         vdisk_extents.part_id, extent_size
                  FROM vdisks NATURAL JOIN vdisk_extents
                                                  NATURAL JOIN vdisk_part
                  WHERE expires AND expiry_time <= datetime('now')
                  ORDER BY expiry_time ASC, vdisk_extent_no DESC
               """)  # aims to reuse the last extents
                     # from the longest-expired disks first

    allocated = 0

    if expiry:
        expiry_ts = "datetime('now', '" + str(expiry) + " seconds')"
        expires = 1
    else:
        expiry_ts = "NULL"
        expires = 0

    # we'll use this to build the SQL statement we want
    building_sql = "INSERT INTO vdisks(vdisk_id, size, expires, expiry_time)" \
                   +" VALUES ("+str(new_id)+", "+str(size)+ ", "              \
                   + str(expires) + ", " + expiry_ts + "); "

    counter = 0

    while allocated < size:
        row = cu.fetchone()
        if not row:
            print "ran out of space, having allocated %d meg of %d" % (allocated, size)
            cx.close()
            return -1
        

        (vdisk_id, vdisk_extent_no, part_extent_no, part_id, extent_size) = row
        allocated += extent_size
        building_sql += "UPDATE vdisk_extents SET vdisk_id = " + str(new_id) \
                        + ", " + "vdisk_extent_no = " + str(counter)         \
                        + " WHERE vdisk_extent_no = " + str(vdisk_extent_no) \
                        + " AND vdisk_id = " + str(vdisk_id) + "; "

        counter += 1
        

    # this will execute the SQL query we build to store details of the new
    # virtual disk and allocate space to it print building_sql
    cu.execute(building_sql)
    
    cx.commit()
    cx.close()
    return str(new_id)


def vd_lookup(id):
    """Lookup a Virtual Disk by ID.
    id [string]: a virtual disk identifier
    Returns [list of dicts]: a list of extents as dicts, containing fields:
                             device : Linux device number of host disk
                             start_sector : within the device
                             nr_sectors : size of this extent
                             type : set to \'VD Extent\'
                             
                             part_device : Linux device no of host partition
                             part_start_sector : within the partition
    """

    if not os.path.isfile(VD_DB_FILE):
        __vd_no_database()

    cx = sqlite.connect(VD_DB_FILE)
    cu = cx.cursor()

    cu.execute("-- types int")
    cu.execute("""SELECT COUNT(*)
                  FROM vdisks
                  WHERE (expiry_time > datetime('now') OR NOT expires)
                              AND vdisk_id = """ + id)
    count, = cu.fetchone()

    if not count:
        cx.close()
        return None

    cu.execute("SELECT size from vdisks WHERE vdisk_id = " + id)
    real_size, = cu.fetchone()
  
    # This query tells PySQLite how to convert the data returned from the
    # following query - the use of the multiplication confuses it otherwise ;-)
    # This row is significant to PySQLite but is syntactically an SQL comment.

    cu.execute("-- types str, int, int, int")

    # This SQL statement is designed so that when the results are fetched they
    # will be in the right format to return immediately.
    cu.execute("""SELECT partition, vdisk_part.part_id,
                         round(part_extent_no * extent_size) as start,
                         extent_size
                         
                  FROM vdisks NATURAL JOIN vdisk_extents
                                             NATURAL JOIN vdisk_part
                                                
                  WHERE vdisk_extents.vdisk_id = """ + id
               + " ORDER BY vdisk_extents.vdisk_extent_no ASC"
               )

    extent_tuples = cu.fetchall()

    # use this function to map the results from the database into a dict
    # list of extents, for consistency with the rest of the code
    def transform ((partition, part_device, part_offset, nr_sectors)):
        return {
                 # the disk device this extent is on - for passing to Xen
                 'device' : lookup_raw_partn(partition)[0]['device'],
                 # the offset of this extent within the disk - for passing to Xen
                 'start_sector' : long(part_offset + lookup_raw_partn(partition)[0]['start_sector']),
                 # extent size, in sectors
                 'nr_sectors' : nr_sectors,
                 # partition device this extent is on (useful to know for xenctl.utils fns)
                 'part_device' : part_device,
                 # start sector within this partition (useful to know for xenctl.utils fns)
                 'part_start_sector' : part_offset,
                 # type of this extent - handy to know
                 'type' : 'VD Extent' }

    cx.commit()
    cx.close()

    extent_dicts = map(transform, extent_tuples)

    # calculate the over-allocation in sectors (happens because
    # we allocate whole extents)
    allocated_size = 0
    for i in extent_dicts:
        allocated_size += i['nr_sectors']

    over_allocation = allocated_size - real_size

    # trim down the last extent's length so the resulting VBD will be the
    # size requested, rather than being rounded up to the nearest extent
    extent_dicts[len(extent_dicts) - 1]['nr_sectors'] -= over_allocation

    return extent_dicts


def vd_enlarge(vdisk_id, extra_size_mb):
    """Create a new virtual disk.
    vdisk_id [string]   :    ID of the virtual disk to enlarge
    extra_size_mb  [int]:    size in megabytes to increase the allocation by
    returns  [int]      :    0 on success, otherwise non-zero
    """

    if not os.path.isfile(VD_DB_FILE):
        __vd_no_database()

    cx = sqlite.connect(VD_DB_FILE)
    cu = cx.cursor()

    extra_size = extra_size_mb * 2048

    cu.execute("-- types int")
    cu.execute("SELECT COUNT(*) FROM vdisks WHERE vdisk_id = " + vdisk_id
               + " AND (expiry_time > datetime('now') OR NOT expires)")
    count, = cu.fetchone()

    if not count: # no such vdisk
        cx.close()
        return -1

    cu.execute("-- types int")
    cu.execute("""SELECT SUM(extent_size)
                  FROM vdisks NATURAL JOIN vdisk_extents
                                         NATURAL JOIN vdisk_part
                  WHERE vdisks.vdisk_id = """ + vdisk_id)

    real_size, = cu.fetchone() # get the true allocated size

    cu.execute("-- types int")
    cu.execute("SELECT size FROM vdisks WHERE vdisk_id = " + vdisk_id)

    old_size, = cu.fetchone()


    cu.execute("--- types int")
    cu.execute("""SELECT MAX(vdisk_extent_no)
                  FROM vdisk_extents
                  WHERE vdisk_id = """ + vdisk_id)

    counter = cu.fetchone()[0] + 1 # this stores the extent numbers


    # because of the extent-based allocation, the VD may already have more
    # allocated space than they asked for.  Find out how much we really
    # need to add.
    add_size = extra_size + old_size - real_size

    # fetch a list of extents from the expired disks, along with information
    # about their size
    cu.execute("""SELECT vdisks.vdisk_id, vdisk_extent_no, part_extent_no,
                         vdisk_extents.part_id, extent_size
                  FROM vdisks NATURAL JOIN vdisk_extents
                                                  NATURAL JOIN vdisk_part
                  WHERE expires AND expiry_time <= datetime('now')
                  ORDER BY expiry_time ASC, vdisk_extent_no DESC
               """)  # aims to reuse the last extents
                     # from the longest-expired disks first

    allocated = 0

    building_sql = "UPDATE vdisks SET size = " + str(old_size + extra_size)\
                   + " WHERE vdisk_id = " + vdisk_id + "; "

    while allocated < add_size:
        row = cu.fetchone()
        if not row:
            cx.close()
            return -1

        (dead_vd_id, vdisk_extent_no, part_extent_no, part_id, extent_size) = row
        allocated += extent_size
        building_sql += "UPDATE vdisk_extents SET vdisk_id = " + vdisk_id    \
                        + ", " + "vdisk_extent_no = " + str(counter)         \
                        + " WHERE vdisk_extent_no = " + str(vdisk_extent_no) \
                        + " AND vdisk_id = " + str(dead_vd_id) + "; "

        counter += 1
        

    # this will execute the SQL query we build to store details of the new
    # virtual disk and allocate space to it print building_sql
    cu.execute(building_sql)
    
    cx.commit()
    cx.close()
    return 0


def vd_undelete(vdisk_id, expiry_time):
    """Create a new virtual disk.
    vdisk_id      [int]: size in megabytes for the new virtual disk
    expiry_time   [int]: expiry time, in seconds from now
    returns       [int]: zero on success, non-zero on failure
    """

    if not os.path.isfile(VD_DB_FILE):
        __vd_no_database()

    if vdisk_id == '0': #  undeleting vdisk 0 isn't sane!
        return -1

    cx = sqlite.connect(VD_DB_FILE)
    cu = cx.cursor()

    cu.execute("-- types int")
    cu.execute("SELECT COUNT(*) FROM vdisks WHERE vdisk_id = " + vdisk_id)
    count, = cu.fetchone()

    if not count:
        cx.close()
        return -1

    cu.execute("-- types int")
    cu.execute("""SELECT SUM(extent_size)
                  FROM vdisks NATURAL JOIN vdisk_extents
                                         NATURAL JOIN vdisk_part
                  WHERE vdisks.vdisk_id = """ + vdisk_id)

    real_size, = cu.fetchone() # get the true allocated size


    cu.execute("-- types int")
    cu.execute("SELECT size FROM vdisks WHERE vdisk_id = " + vdisk_id)

    old_size, = cu.fetchone()

    if real_size < old_size:
        cx.close()
        return -1

    if expiry_time == 0:
        expires = '0'
    else:
        expires = '1'

    # this will execute the SQL query we build to store details of the new
    # virtual disk and allocate space to it print building_sql
    cu.execute("UPDATE vdisks SET expiry_time = datetime('now','"
               + str(expiry_time) + " seconds'), expires = " + expires
               + " WHERE vdisk_id = " + vdisk_id)
    
    cx.commit()
    cx.close()
    return 0




def vd_list():
    """Lists all the virtual disks registered in the system.
    returns [list of dicts]
    """
    
    if not os.path.isfile(VD_DB_FILE):
        __vd_no_database()

    cx = sqlite.connect(VD_DB_FILE)
    cu = cx.cursor()

    cu.execute("""SELECT vdisk_id, size, expires, expiry_time
                  FROM vdisks
                  WHERE (NOT expires) OR expiry_time > datetime('now')
               """)

    ret = cu.fetchall()

    cx.close()

    def makedicts((vdisk_id, size, expires, expiry_time)):
        return { 'vdisk_id' : str(vdisk_id), 'size': size,
                 'expires' : expires, 'expiry_time' : expiry_time }

    return map(makedicts, ret)


def vd_refresh(id, expiry):
    """Change the expiry time of a virtual disk.
    id [string]  : a virtual disk identifier
    expiry [int] : expiry time in seconds from now (0 = never expire)
    returns [int]: zero on success, non-zero on failure
    """

    if not os.path.isfile(VD_DB_FILE):
        __vd_no_database()
    
    cx = sqlite.connect(VD_DB_FILE)
    cu = cx.cursor()

    cu.execute("-- types int")
    cu.execute("SELECT COUNT(*) FROM vdisks WHERE vdisk_id = " + id
               + " AND (expiry_time > datetime('now') OR NOT expires)")
    count, = cu.fetchone()

    if not count:
        cx.close()
        return -1

    if expiry:
        expires = 1
        expiry_ts = "datetime('now', '" + str(expiry) + " seconds')"
    else:
        expires = 0
        expiry_ts = "NULL"

    cu.execute("UPDATE vdisks SET expires = " + str(expires)
               + ", expiry_time = " + expiry_ts
               + " WHERE (expiry_time > datetime('now') OR NOT expires)"
               + " AND vdisk_id = " + id)

    cx.commit()
    cx.close()
    
    return 0


def vd_delete(id):
    """Deletes a Virtual Disk, making its extents available for future VDs.
       id [string]   : identifier for the virtual disk to delete
       returns [int] : 0 on success, -1 on failure (VD not found
                       or already deleted)
    """

    if not os.path.isfile(VD_DB_FILE):
        __vd_no_database()
    
    cx = sqlite.connect(VD_DB_FILE)
    cu = cx.cursor()

    cu.execute("-- types int")
    cu.execute("SELECT COUNT(*) FROM vdisks WHERE vdisk_id = " + id
               + " AND (expiry_time > datetime('now') OR NOT expires)")
    count, = cu.fetchone()

    if not count:
        cx.close()
        return -1

    cu.execute("UPDATE vdisks SET expires = 1, expiry_time = datetime('now')"
               + " WHERE vdisk_id = " + id)

    cx.commit()
    cx.close()
    
    return 0


def vd_freespace():
    """Returns the amount of free space available for new virtual disks, in MB
    returns [int] : free space for VDs in MB
    """

    if not os.path.isfile(VD_DB_FILE):
        __vd_no_database()
 
    cx = sqlite.connect(VD_DB_FILE)
    cu = cx.cursor()

    cu.execute("-- types int")

    cu.execute("""SELECT SUM(extent_size)
                  FROM vdisks NATURAL JOIN vdisk_extents
                                           NATURAL JOIN vdisk_part
                  WHERE expiry_time <= datetime('now') AND expires""")

    sum, = cu.fetchone()

    cx.close()

    return sum / 2048


def vd_init_db(path):
    """Initialise the VD SQLite database
    path [string]: path to the SQLite database file
    """

    cx = sqlite.connect(path)
    cu = cx.cursor()

    cu.execute(
        """CREATE TABLE vdisk_extents
                           ( vdisk_extent_no INT,
                             vdisk_id INT,
                             part_id INT,
                             part_extent_no INT )
        """)

    cu.execute(
        """CREATE TABLE vdisk_part
                           ( part_id INT,
                             partition VARCHAR,
                             extent_size INT )
        """)

    cu.execute(
        """CREATE TABLE vdisks
                           ( vdisk_id INT,
                             size INT,
                             expires BOOLEAN,
                             expiry_time TIMESTAMP )
        """)


    cu.execute(
        """INSERT INTO vdisks ( vdisk_id, size, expires, expiry_time )
                       VALUES ( 0,        0,    1,       datetime('now') )
        """)

    cx.commit()
    cx.close()

    VD_DB_FILE = path



def vd_cp_to_file(vdisk_id,filename):
    """Writes the contents of a specified vdisk out into a disk file, leaving
    the original copy in the virtual disk pool."""

    cx = sqlite.connect(VD_DB_FILE)
    cu = cx.cursor()

    extents = vd_lookup(vdisk_id)

    if not extents:
        return -1
    
    file_idx = 0 # index into source file, in sectors

    for i in extents:
        cu.execute("""SELECT partition, extent_size FROM vdisk_part
                      WHERE part_id =  """ + str(i['part_device']))

        (partition, extent_size) = cu.fetchone()

        os.system("dd bs=1b if=" + partition + " of=" + filename
                  + " skip=" + str(i['part_start_sector'])
                  + " seek=" + str(file_idx)
                  + " count=" + str(i['nr_sectors'])
                  + " > /dev/null")

        file_idx += i['nr_sectors']

    cx.close()

    return 0 # should return -1 if something breaks
    

def vd_mv_to_file(vdisk_id,filename):
    """Writes a vdisk out into a disk file and frees the space originally
    taken within the virtual disk pool.
    vdisk_id [string]: ID of the vdisk to write out
    filename [string]: file to write vdisk contents out to
    returns [int]: zero on success, nonzero on failure
    """

    if vd_cp_to_file(vdisk_id,filename):
        return -1

    if vd_delete(vdisk_id):
        return -1

    return 0


def vd_read_from_file(filename,expiry):
    """Reads the contents of a file directly into a vdisk, which is
    automatically allocated to fit.
    filename [string]: file to read disk contents from
    returns [string] : vdisk ID for the destination vdisk
    """

    size_bytes = os.stat(filename).st_size

    (size_mb,leftover) =  divmod(size_bytes,1048580) # size in megabytes
    if leftover > 0: size_mb += 1 # round up if not an exact number of MB

    vdisk_id = vd_create(size_mb, expiry)

    if vdisk_id < 0:
        return -1

    cx = sqlite.connect(VD_DB_FILE)
    cu = cx.cursor()

    cu.execute("""SELECT partition, extent_size, part_extent_no
                  FROM vdisk_part NATURAL JOIN vdisk_extents
                  WHERE vdisk_id =  """ + vdisk_id + """
                  ORDER BY vdisk_extent_no ASC""")

    extents = cu.fetchall()

    size_sectors = size_mb * 2048 # for feeding to dd

    file_idx = 0 # index into source file, in sectors

    def write_extent_to_vd((partition, extent_size, part_extent_no),
                           file_idx, filename):
        """Write an extent out to disk and update file_idx"""

        os.system("dd bs=512 if=" + filename + " of=" + partition
                  + " skip=" + str(file_idx)
                  + " seek=" + str(part_extent_no * extent_size)
                  + " count=" + str(min(extent_size, size_sectors - file_idx))
                  + " > /dev/null")

        return extent_size

    for i in extents:
        file_idx += write_extent_to_vd(i, file_idx, filename)

    cx.close()

    return vdisk_id
    



def vd_extents_validate(new_extents,new_writeable):
    """Validate the extents against the existing extents.
    Complains if the list supplied clashes against the extents that
    are already in use in the system.
    new_extents [list of dicts]: list of new extents, as dicts
    new_writeable [int]: 1 if they are to be writeable, 0 otherwise
    returns [int]: either the expertise level of the mapping if it doesn't
                   exceed VBD_EXPERT_MODE or -1 if it does (error)
    """

    import Xc # this is only needed in this function

    xc = Xc.new()

    ##### Probe for explicitly created virtual disks and build a list
    ##### of extents for comparison with the ones that are being added

    probe = xc.vbd_probe()

    old_extents = [] # this will hold a list of all existing extents and
                     # their writeable status, as a list of (device,
                     # start, size, writeable?) tuples

    for vbd in probe:
        this_vbd_extents = xc.vbd_getextents(vbd['dom'],vbd['vbd'])
        for vbd_ext in this_vbd_extents:
            vbd_ext['writeable'] = vbd['writeable']
            old_extents.append(vbd_ext)
            
    ##### Now scan /proc/mounts for compile a list of extents corresponding to
    ##### any devices mounted in DOM0.  This list is added on to old_extents

    regexp = re.compile("/dev/(\S*) \S* \S* (..).*")
    fd = open('/proc/mounts', "r")

    while True:
        line = fd.readline()
        if not line: # if we've run out of lines then stop reading
            break
        
        m = regexp.match(line)

        # if the regexp didn't match then it's probably a line we don't
        # care about - skip to next line
        if not m:
            continue

        # lookup the device
        ext_list = lookup_raw_partn(m.group(1))

        # if lookup failed, skip to next mounted device
        if not ext_list:
            continue

        # set a writeable flag as appropriate
        for ext in ext_list:
            ext['writeable'] = m.group(2) == 'rw'

        # now we've got here, the contents of ext_list are in a
        # suitable format to be added onto the old_extents list, ready
        # for checking against the new extents

        old_extents.extend(ext_list)

    fd.close() # close /proc/mounts

    ##### By this point, old_extents contains a list of extents, in
    ##### dictionary format corresponding to every extent of physical
    ##### disk that's either part of an explicitly created VBD, or is
    ##### mounted under DOM0.  We now check these extents against the
    ##### proposed additions in new_extents, to see if a conflict will
    ##### happen if they are added with write status new_writeable

    level = 0 # this'll accumulate the max warning level

    # Search for clashes between the new extents and the old ones
    # Takes time O(len(new_extents) * len(old_extents))
    for new_ext in new_extents:
        for old_ext in old_extents:
            if(new_ext['device'] == old_ext['device']):

                new_ext_start = new_ext['start_sector']
                new_ext_end = new_ext_start + new_ext['nr_sectors'] - 1
                
                old_ext_start = old_ext['start_sector']
                old_ext_end = old_ext_start + old_ext['nr_sectors'] - 1
                
                if((old_ext_start <= new_ext_start <= old_ext_end) or
                   (old_ext_start <= new_ext_end <= old_ext_end)):
                    if (not old_ext['writeable']) and new_writeable:
                        level = max(1,level)
                    elif old_ext['writeable'] and (not new_writeable):
                        level = max(1,level)
                    elif old_ext['writeable'] and new_writeable:
                        level = max(2,level)


    ##### level now holds the warning level incurred by the current
    ##### VBD setup and we complain appropriately to the user


    if level == 1:
        print >> sys.stderr, """Warning: one or more hard disk extents
         writeable by one domain are also readable by another."""
    elif level == 2:
        print >> sys.stderr, """Warning: one or more hard disk extents are
         writeable by two or more domains simultaneously."""

    if level > VBD_EXPERT_MODE:
        print >> sys.stderr, """ERROR: This kind of disk sharing is not allowed
        at the current safety level (%d).""" % VBD_EXPERT_MODE
        level = -1

    return level

