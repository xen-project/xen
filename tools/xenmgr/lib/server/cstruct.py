import struct

class Struct:

    maxDepth = 10

    base = ['x', 'B', 'H', 'I', 'L', 'Q', 'c', 'h', 'i', 'l', 'q', ]

    sizes = {'B': 1,
            'H': 2,
            'I': 4,
            'L': 4,
            'Q': 8,
            'c': 1,
            'h': 2,
            'i': 4,
            'l': 4,
            'q': 8,
            'x': 1,
            }

    formats = {
        'int8'          : 'B',
        'int16'         : 'H',
        'int32'         : 'I',
        'int64'         : 'Q',
        'u8'            : 'B',
        'u16'           : 'H',
        'u32'           : 'I',
        'u64'           : 'Q'
        }

    def typedef(self, name, val):
        self.formats[name] = val

    def struct(self, name, *f):
        self.typedef(name, StructInfo(self, f))
        
    def getType(self, name):
        return self.formats[name]

    def format(self, ty):
        d = 0
        f = ty
        while d < self.maxDepth:
            d += 1
            f = self.formats[f]
            if isinstance(f, StructInfo):
                return f.format()
            if f in self.base:
                return f
        return -1

    def alignedformat(self, ty):
        fmt = self.format(ty)
        #print 'alignedformat> %s |%s|' %(ty, fmt)
        afmt = self.align(fmt)
        #print 'alignedformat< %s |%s| |%s|' % (ty, fmt, afmt)
        return afmt

    def align(self, fmt):
        n1 = 0
        afmt = ''
        for a in fmt:
            n2 = self.getSize(a)
            m = n1 % n2
            if m:
                d = (n2 - m)
                afmt += 'x' * d
                n1 += d
            afmt += a
            n1 += n2
        return afmt

    def fmtsize(self, fmt):
        s = 0
        for f in fmt:
            s += self.getSize(f)
        return s

    def getSize(self, f):
        return self.sizes[f]

    def pack(self, ty, data):
        return self.getType(ty).pack(data)

    def unpack(self, ty, data):
        return self.getType(ty).unpack(data)

    def show(self):
        l = self.formats.keys()
        l.sort()
        for v in l:
            print "%-35s %-10s %s" % (v, self.format(v), self.alignedformat(v))


class StructInfo:

    def __init__(self, s, f):
        self.fmt = None
        self.structs = s
        self.fields = f

    def alignedformat(self):
        if self.afmt: return self.afmt
        self.afmt = self.structs.align(self.format())
        return self.afmt
    
    def format(self):
        if self.fmt: return self.fmt
        fmt = ""
        for (ty, name) in self.fields:
            fmt += self.formatString(ty)
        self.fmt = fmt
        return fmt

    def formatString(self, ty):
        if ty in self.fields:
            ty = self.fields[ty]
        return self.structs.format(ty)

    def pack(self, *args):
        return struct.pack(self.alignedformat(), *args)

    def unpack(self, data):
        return struct.unpack(self.alignedformat(), data)

types = Struct()

types.typedef('short'         , 'h')
types.typedef('int'           , 'i')
types.typedef('long'          , 'l')
types.typedef('unsigned short', 'H')
types.typedef('unsigned int'  , 'I')
types.typedef('unsigned long' , 'L')
types.typedef('domid_t'       , 'u64')
types.typedef('blkif_vdev_t'  , 'u16')
types.typedef('blkif_pdev_t'  , 'u16')
types.typedef('blkif_sector_t', 'u64')

types.struct('u8[6]',
             ('u8', 'a1'),
             ('u8', 'a2'),
             ('u8', 'a3'),
             ('u8', 'a4'),
             ('u8', 'a5'),
             ('u8', 'a6'))
             
types.struct('blkif_fe_interface_status_changed_t',
    ('unsigned int',    'handle'),
    ('unsigned int',    'status'),
    ('unsigned int',    'evtchn'))

types.struct('blkif_fe_driver_status_changed_t',
    ('unsigned int',    'status'),
    ('unsigned int',    'nr_interfaces'))

types.struct('blkif_fe_interface_connect_t',
    ('unsigned int' ,   'handle'),
    ('unsigned long',   'shmem_frame'))

types.struct('blkif_fe_interface_disconnect_t',
    ('unsigned int',   'handle'))

types.struct('blkif_extent_t',
    ('blkif_pdev_t'  , 'device'),
    ('blkif_sector_t', 'sector_start'),
    ('blkif_sector_t', 'sector_length'))

types.struct('blkif_be_create_t', 
    ('domid_t'     ,   'domid'),
    ('unsigned int',   'blkif_handle'),
    ('unsigned int',   'status'))
             
types.struct('blkif_be_destroy_t',
    ('domid_t'     ,   'domid'),
    ('unsigned int',   'blkif_handle'),
    ('unsigned int',   'status'))

types.struct('blkif_be_connect_t',
    ('domid_t'      ,  'domid'),
    ('unsigned int' ,  'blkif_handle'),
    ('unsigned int' ,  'evtchn'),
    ('unsigned long',  'shmem_frame'),
    ('unsigned int' ,  'status'))

types.struct('blkif_be_disconnect_t',
    ('domid_t'     ,   'domid'),
    ('unsigned int',   'blkif_handle'),
    ('unsigned int',   'status'))

types.struct('blkif_be_vbd_create_t', 
    ('domid_t'     ,   'domid'),         #Q
    ('unsigned int',   'blkif_handle'),  #I
    ('blkif_vdev_t',   'vdevice'),       #H
    ('int'         ,   'readonly'),      #i
    ('unsigned int',   'status'))        #I

types.struct('blkif_be_vbd_destroy_t', 
    ('domid_t'     ,   'domid'),
    ('unsigned int',   'blkif_handle'),
    ('blkif_vdev_t',   'vdevice'),
    ('unsigned int',   'status'))

types.struct('blkif_be_vbd_grow_t', 
    ('domid_t'       , 'domid'),         #Q
    ('unsigned int'  , 'blkif_handle'),  #I
    ('blkif_vdev_t'  , 'vdevice'),       #H   
    ('blkif_extent_t', 'extent'),        #HQQ
    ('unsigned int'  , 'status'))        #I

types.struct('blkif_be_vbd_shrink_t', 
    ('domid_t'     ,   'domid'),
    ('unsigned int',   'blkif_handle'),
    ('blkif_vdev_t',   'vdevice'),
    ('unsigned int',   'status'))

types.struct('blkif_be_driver_status_changed_t',
    ('unsigned int',   'status'),
    ('unsigned int',   'nr_interfaces'))

types.struct('netif_fe_interface_status_changed_t',
    ('unsigned int',   'handle'),
    ('unsigned int',   'status'),
    ('unsigned int',   'evtchn'),
    ('u8[6]',          'mac'))

types.struct('netif_fe_driver_status_changed_t',
    ('unsigned int',   'status'),
    ('unsigned int',   'nr_interfaces'))

types.struct('netif_fe_interface_connect_t',
    ('unsigned int',   'handle'),
    ('unsigned long',  'tx_shmem_frame'),
    ('unsigned long',  'rx_shmem_frame'))

types.struct('netif_fe_interface_disconnect_t',
    ('unsigned int',   'handle'))

types.struct('netif_be_create_t', 
    ('domid_t'     ,   'domid'),
    ('unsigned int',   'netif_handle'),
    ('u8[6]'       ,   'mac'),
    ('unsigned int',   'status'))

types.struct('netif_be_destroy_t',
    ('domid_t'     ,   'domid'),
    ('unsigned int',   'netif_handle'),
    ('unsigned int',   'status'))

types.struct('netif_be_connect_t', 
    ('domid_t'      ,  'domid'),
    ('unsigned int' ,  'netif_handle'),
    ('unsigned int' ,  'evtchn'),
    ('unsigned long',  'tx_shmem_frame'),
    ('unsigned long',  'rx_shmem_frame'),
    ('unsigned int' ,  'status'))

types.struct('netif_be_disconnect_t',
    ('domid_t'     ,   'domid'),
    ('unsigned int',   'netif_handle'),
    ('unsigned int',   'status'))

types.struct('netif_be_driver_status_changed_t',
    ('unsigned int',   'status'),
    ('unsigned int',   'nr_interfaces'))

if 1 or __name__ == "__main__":
    types.show()
