
# XDR-style packer/unpacker for sxpr.
#
# string -> [STRING] [len:u16] <len bytes>
# atom   -> [ATOM]   [len:u16] <len bytes>
# int    -> [UINT]   [value]
# list   -> [LIST]   {1 elt}* 0
# null   -> [NULL]
# none   -> [NONE]
# bool   -> [BOOL]   { 0:u8 | 1:u8 }
#
# types packed as u16.
#
# So (a b c) -> [LIST] 1 a 1 b 1 c 0
#    ()      -> [LIST] 0

import struct

try:
    from cStringIO import StringIO as _StringIO
except ImportError:
    from StringIO import StringIO as _StringIO

import types

class Error(Exception):
    
    def __init__(self, msg):
        self.msg = msg
        
    def __repr__(self):
        return repr(self.msg)
    
    def __str__(self):
        return str(self.msg)


class ConversionError(Error):
    pass

BOOL_SIZE   = 1
BOOL_FMT    = '>B'

BYTE_SIZE   = 1
BYTE_FMT    = '>b'
UBYTE_FMT   = '>B'

SHORT_SIZE  = 2
SHORT_FMT   = '>h'
USHORT_FMT  = '>H'

INT_SIZE   =  4
INT_FMT    = '>l'
UINT_FMT   = '>L'

NONE_CODE   = 0
NULL_CODE   = 1
INT_CODE    = 2
STRING_CODE = 3
ATOM_CODE   = 4
BOOL_CODE   = 5
LIST_CODE   = 10

class Packer:
    
    def __init__(self, io=None):
        self.reset(io=io)

    def reset(self, io=None):
        if io is None:
            io = _StringIO()
        self.io = io

    def get_buffer(self):
        return self.io.getvalue()

    def get_io(self):
        return self.io

    def struct_pack(self, fmt, x):
        try:
            self.io.write(struct.pack(fmt, x))
        except struct.error, msg:
            raise ConversionError, msg

    def pack_none(self):
        pass
    
    def pack_bool(self, x):
        # { '1' | '0' }
        print 'bool>', x
        if x:
            self.io.write('\1')
        else:
            self.io.write('\0')

    def pack_byte(self, x):
        self.struct_pack(BYTE_FMT, x & 0xff)

    def pack_char(self, x):
        print 'char>', x
        self.io.write(x)
        
    def pack_ubyte(self, x):
        print 'ubyte>', x
        self.struct_pack(UBYTE_FMT, x & 0xff)

    def pack_ushort(self, x):
        print 'ushort>', x
        self.struct_pack(USHORT_FMT, x & 0xffff)
        
    def pack_short(self, x):
        print 'short>', x
        self.struct_pack(SHORT_FMT, x & 0xffff)

    def pack_uint(self, x):
        print 'uint>', x
        self.struct_pack(UINT_FMT, x)
        
    def pack_int(self, x):
        print 'int>', x
        self.struct_pack(INT_FMT, x)

    def pack_uhyper(self, x):
        print 'uhyper>', x
        self.pack_uint(x>>32 & 0xffffffffL)
        self.pack_uint(x & 0xffffffffL)

    pack_hyper = pack_uhyper

    def pack_fstring(self, n, x):
        print 'fstring>', x
        self.io.write(x)

    pack_fopaque = pack_fstring

    def pack_string(self, x):
        print 'string>', x
        n = len(x)
        self.pack_ushort(n)
        self.pack_fstring(n, x)

    pack_opaque = pack_string
    pack_bytes = pack_string

    def pack_list(self, x, pack_item):
        print 'list>', x
        # { '1' <item> }* '0'
        for item in x:
            self.pack_bool(1)
            pack_item(item)
        self.pack_bool(0)

    def pack_farray(self, x, pack_item):
        # <item>*
        # Can pass n and check length - but is it worth it?
        print 'farray>', list
        for item in x:
            pack_item(item)

    def pack_array(self, x, pack_item):
        # n <item>*n
        print 'array>', x
        self.pack_uint(len(x))
        self.pack_farray(x, pack_item)

class Unpacker:

    def __init__(self, data):
        self.reset(data)

    def reset(self, data):
        if isinstance(data, types.StringType):
            data = _StringIO(data)
        self.io = data

    def get_bytes(self, n):
        if n < 0:
            raise ConversionError('negative byte count')
        data = self.io.read(n)
        return data

    def struct_unpack(self, fmt, n):
        data = self.get_bytes(n)
        try:
            return struct.unpack(fmt, data)[0]
        except struct.error, msg:
            raise ConversionError, msg
       
    def unpack_none(self):
        return None

    def unpack_bool(self):
        return self.struct_unpack(BOOL_FMT, BOOL_SIZE)

    def unpack_char(self):
        return self.get_bytes(1)[0]

    def unpack_byte(self):
        return self.struct_unpack(BYTE_FMT, BYTE_SIZE)
    
    def unpack_ubyte(self):
        return self.struct_unpack(UBYTE_FMT, BYTE_SIZE)
    
    def unpack_ushort(self):
        return self.struct_unpack(USHORT_FMT, SHORT_SIZE)

    def unpack_short(self):
        return self.struct_unpack(SHORT_FMT, SHORT_SIZE)
        
    def unpack_uint(self):
        x = self.struct_unpack(UINT_FMT, UINT_SIZE)
        try:
            return int(x)
        except OverflowError:
            return x

    def unpack_int(self):
        return self.struct_unpack(INT_FMT, INT_SIZE)

    def unpack_uhyper(self):
        hi = self.unpack_uint()
        lo = self.unpack_uint()
        return long(hi)<<32 | lo

    def unpack_hyper(self):
        x = self.unpack_uhyper()
        if x >= 0x8000000000000000L:
            x = x - 0x10000000000000000L
        return x

    def unpack_fstring(self, n):
        return self.get_bytes(n)

    unpack_fopaque = unpack_fstring

    def unpack_string(self):
        n = self.unpack_ushort()
        return self.unpack_fstring(n)

    unpack_opaque = unpack_string
    unpack_bytes = unpack_string

    def unpack_list(self, unpack_item):
        list = []
        while self.unpack_bool():
            list.append(unpack_item())
        return list

    def unpack_farray(self, n, unpack_item):
        list = []
        for i in range(n):
            list.append(unpack_item())
        return list

    def unpack_array(self, unpack_item):
        n = self.unpack_ushort()
        return self.unpack_farray(n, unpack_item)

class SxpPacker(Packer):

    pack_code = Packer.pack_ushort

    def pack(self, x):
        if isinstance(x, types.NoneType):
            self.pack_code(NONE_CODE)
            self.pack_none()
        elif isinstance(x, types.IntType):
            self.pack_code(INT_CODE)
            self.pack_int(x)
        elif isinstance(x, types.StringType):
            self.pack_code(STRING_CODE)
            self.pack_string(x)
        elif isinstance(x, types.ListType):
            self.pack_code(LIST_CODE)
            self.pack_list(x, self.pack)
        else:
           raise Error('invalid type ' + str(type(x)))

class SxpUnpacker(Unpacker):

    unpack_code = Unpacker.unpack_ushort

    def unpack(self):
        code = self.unpack_code()
        if code == NONE_CODE:
            val = self.unpack_none()
        elif code == INT_CODE:
            val = self.unpack_int()
        elif code == BOOL_CODE:
            val = self.unpack_bool()
        elif code == STRING_CODE:
            val = self.unpack_string()
        elif code == ATOM_CODE:
            val = self.unpack_string()
        elif code == LIST_CODE:
            val = self.unpack_list(self.unpack)
        else:
            raise Error('invalid code ' + str(code))
        return val

def main():
    d = "['vfarm', ['@', ['name', 'vfarm1']], ['memory', 1024], ['image', 'splinux'], ['args', 'root=/dev/nfs ip=dhcp'], [ 1, -1, 1000000]]"
    print"> len=", len(d), "d=", d
    obj = ['vfarm', ['@', ['name', 'vfarm1']],
           ['memory', 1024],
           ['image', 'splinux'],
           ['args', 'root=/dev/nfs ip=dhcp'],
           [ 1, -1, 1000000] ]
    print "> obj=", obj
    pack = SxpPacker()
    pack.pack(obj)
    data = pack.get_buffer()
    print "> len=", len(data), "data=", data
    unpack = SxpUnpacker(data)
    obj_unpack = unpack.unpack()
    print "> obj=", obj_unpack
    #obj = [100,101,102, 999.00234, { 'a': 1, 'b': 2 } ]
    #pack.reset()
    #pack.pack_item(obj)
    #data = pack.get_buffer()
    #print "> obj=", obj
    #print "> len=", len(data), "data=", data
    #unpack.reset(data)
    #obj_unpack = unpack.unpack_item()
    #print "> obj=", obj_unpack
    
if __name__ == "__main__":
    main()
