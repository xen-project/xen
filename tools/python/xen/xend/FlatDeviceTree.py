#!/usr/bin/env python
#
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
#
# Copyright (C) IBM Corp. 2006
#
# Authors: Hollis Blanchard <hollisb@us.ibm.com>

import os
import sys
import struct
import stat
import re
import glob
import math

_host_devtree_root = '/proc/device-tree'

_OF_DT_HEADER = int("d00dfeed", 16) # avoid signed/unsigned FutureWarning
_OF_DT_BEGIN_NODE = 0x1
_OF_DT_END_NODE = 0x2
_OF_DT_PROP = 0x3
_OF_DT_END = 0x9

def _bincat(seq, separator=''):
    '''Concatenate the contents of seq into a bytestream.'''
    strs = []
    for item in seq:
        if isinstance(item, int):
            strs.append(struct.pack(">I", item))
        elif isinstance(item, long):
            strs.append(struct.pack(">Q", item))
        else:
            try:
                strs.append(item.to_bin())
            except AttributeError, e:
                strs.append(item)
    return separator.join(strs)

def _alignup(val, alignment):
    return (val + alignment - 1) & ~(alignment - 1)

def _pad(buf, alignment):
    '''Pad bytestream with NULLs to specified alignment.'''
    padlen = _alignup(len(buf), alignment)
    return buf + '\0' * (padlen - len(buf))
    # not present in Python 2.3:
    #return buf.ljust(_padlen, '\0')

def _indent(item):
    indented = []
    for line in str(item).splitlines(True):
        indented.append('    ' + line)
    return ''.join(indented)

class _Property:
    _nonprint = re.compile('[\000-\037\200-\377]')
    def __init__(self, node, name, value):
        self.node = node
        self.value = value
        self.name = name
        self.node.tree.stradd(name)

    def __str__(self):
        result = self.name
        if self.value:
            searchtext = self.value
            # it's ok for a string to end in NULL
            if searchtext.find('\000') == len(searchtext)-1:
                searchtext = searchtext[:-1]
            m = self._nonprint.search(searchtext)
            if m:
                bytes = struct.unpack("B" * len(self.value), self.value)
                hexbytes = [ '%02x' % b for b in bytes ]
                words = []
                for i in range(0, len(self.value), 4):
                    words.append(''.join(hexbytes[i:i+4]))
                v = '<' + ' '.join(words) + '>'
            else:
                v = '"%s"' % self.value
            result += ': ' + v
        return result

    def to_bin(self):
        offset = self.node.tree.stroffset(self.name)
        return struct.pack('>III', _OF_DT_PROP, len(self.value), offset) \
            + _pad(self.value, 4)

class _Node:
    def __init__(self, tree, name):
        self.tree = tree
        self.name = name
        self.props = {}
        self.children = {}
        self.phandle = 0

    def __str__(self):
        propstrs = [ _indent(prop) for prop in self.props.values() ]
        childstrs = [ _indent(child) for child in self.children.values() ]
        return '%s:\n%s\n%s' % (self.name, '\n'.join(propstrs),
            '\n'.join(childstrs))

    def to_bin(self):
        name = _pad(self.name + '\0', 4)
        return struct.pack('>I', _OF_DT_BEGIN_NODE) + \
                name + \
                _bincat(self.props.values()) + \
                _bincat(self.children.values()) + \
                struct.pack('>I', _OF_DT_END_NODE)

    def addprop(self, propname, *cells):
        '''setprop with duplicate error-checking.'''
        if propname in self.props:
            raise AttributeError('%s/%s already exists' % (self.name, propname))
        self.setprop(propname, *cells)

    def setprop(self, propname, *cells):
        self.props[propname] = _Property(self, propname, _bincat(cells))

    def addnode(self, nodename):
        '''newnode with duplicate error-checking.'''
        if nodename in self.children:
            raise AttributeError('%s/%s already exists' % (self.name, nodename))
        return self.newnode(nodename)

    def newnode(self, nodename):
        node = _Node(self.tree, nodename)
        self.children[nodename] = node
        return node

    def getprop(self, propname):
        return self.props[propname]

    def getchild(self, nodename):
        return self.children[nodename]

    def get_phandle(self):
        if self.phandle:
            return self.phandle
        self.phandle = self.tree.alloc_phandle()
        self.addprop('linux,phandle', self.phandle)
        return self.phandle

class _Header:
    def __init__(self):
        self.magic = 0
        self.totalsize = 0
        self.off_dt_struct = 0
        self.off_dt_strings = 0
        self.off_mem_rsvmap = 0
        self.version = 0
        self.last_comp_version = 0
        self.boot_cpuid_phys = 0
        self.size_dt_strings = 0
    def to_bin(self):
        return struct.pack('>9I',
            self.magic,
            self.totalsize,
            self.off_dt_struct,
            self.off_dt_strings,
            self.off_mem_rsvmap,
            self.version,
            self.last_comp_version,
            self.boot_cpuid_phys,
            self.size_dt_strings)

class _StringBlock:
    def __init__(self):
        self.table = []
    def to_bin(self):
        return _bincat(self.table, '\0') + '\0'
    def add(self, str):
        self.table.append(str)
    def getoffset(self, str):
        return self.to_bin().index(str + '\0')

class Tree(_Node):
    def __init__(self):
        self.last_phandle = 0
        self.strings = _StringBlock()
        self.reserved = [(0, 0)]
        _Node.__init__(self, self, '\0')

    def alloc_phandle(self):
        self.last_phandle += 1
        return self.last_phandle

    def stradd(self, str):
        return self.strings.add(str)

    def stroffset(self, str):
        return self.strings.getoffset(str)

    def reserve(self, start, len):
        self.reserved.insert(0, (start, len))

    def to_bin(self):
        # layout:
        #   header
        #   reservation map
        #   string block
        #   data block

        datablock = _Node.to_bin(self)

        r = [ struct.pack('>QQ', rsrv[0], rsrv[1]) for rsrv in self.reserved ]
        reserved = _bincat(r)

        strblock = _pad(self.strings.to_bin(), 4)
        strblocklen = len(strblock)

        header = _Header()
        header.magic = _OF_DT_HEADER
        header.off_mem_rsvmap = _alignup(len(header.to_bin()), 8)
        header.off_dt_strings = header.off_mem_rsvmap + len(reserved)
        header.off_dt_struct = header.off_dt_strings + strblocklen
        header.version = 0x10
        header.last_comp_version = 0x10
        header.boot_cpuid_phys = 0
        header.size_dt_strings = strblocklen

        payload = reserved + \
                strblock + \
                datablock + \
                struct.pack('>I', _OF_DT_END)
        header.totalsize = len(payload) + _alignup(len(header.to_bin()), 8)
        return _pad(header.to_bin(), 8) + payload

def _readfile(fullpath):
    '''Return full contents of a file.'''
    f = file(fullpath, 'r')
    data = f.read()
    f.close()
    return data

def _find_first_cpu(dirpath):
    '''Find the first node of type 'cpu' in a directory tree.'''
    cpulist = glob.glob(os.path.join(dirpath, 'cpus', '*'))
    for node in cpulist:
        try:
            data = _readfile(os.path.join(node, 'device_type'))
        except IOError:
            continue
        if 'cpu' in data:
            return node
    raise IOError("couldn't find any CPU nodes under " + dirpath)

def _copynode(node, dirpath, propfilter):
    '''Copy all properties and children nodes from a directory tree.'''
    dirents = os.listdir(dirpath)
    for dirent in dirents:
        fullpath = os.path.join(dirpath, dirent)
        st = os.lstat(fullpath)
        if stat.S_ISDIR(st.st_mode):
            child = node.addnode(dirent)
            _copynode(child, fullpath, propfilter)
        elif stat.S_ISREG(st.st_mode) and propfilter(fullpath):
            node.addprop(dirent, _readfile(fullpath))

def build(imghandler):
    '''Construct a device tree by combining the domain's configuration and
    the host's device tree.'''
    root = Tree()

    # 1st reseravtion entry used for start_info, console, store, shared_info
    root.reserve(0x3ffc000, 0x4000)

    # 2nd reservation enrty used for initrd, later on when we load the
    # initrd we may fill this in with zeroes which signifies the end
    # of the reservation map.  So as to avoid adding a zero map now we
    # put some bogus yet sensible numbers here.
    root.reserve(0x1000000, 0x1000)

    root.addprop('device_type', 'chrp-but-not-really\0')
    root.addprop('#size-cells', 2)
    root.addprop('#address-cells', 2)
    root.addprop('model', 'Momentum,Maple-D\0')
    root.addprop('compatible', 'Momentum,Maple\0')

    xen = root.addnode('xen')
    xen.addprop('start-info', long(0x3ffc000), long(0x1000))
    xen.addprop('version', 'Xen-3.0-unstable\0')
    xen.addprop('reg', long(imghandler.vm.domid), long(0))
    xen.addprop('domain-name', imghandler.vm.getName() + '\0')
    xencons = xen.addnode('console')
    xencons.addprop('interrupts', 1, 0)

    # add memory nodes
    totalmem = imghandler.vm.getMemoryTarget() * 1024
    rma_log = 26 ### imghandler.vm.info.get('powerpc_rma_log')
    rma_bytes = 1 << rma_log

    # RMA node
    rma = root.addnode('memory@0')
    rma.addprop('reg', long(0), long(rma_bytes))
    rma.addprop('device_type', 'memory\0')

    # all the rest in a single node
    remaining = totalmem - rma_bytes
    if remaining > 0:
        mem = root.addnode('memory@1')
        mem.addprop('reg', long(rma_bytes), long(remaining))
        mem.addprop('device_type', 'memory\0')

    # add CPU nodes
    cpus = root.addnode('cpus')
    cpus.addprop('smp-enabled')
    cpus.addprop('#size-cells', 0)
    cpus.addprop('#address-cells', 1)

    # Copy all properties the system firmware gave us, except for 'linux,'
    # properties, from the first CPU node in the device tree. Do this once for
    # every vcpu. Hopefully all cpus are identical...
    cpu0 = None
    cpu0path = _find_first_cpu(_host_devtree_root)
    def _nolinuxprops(fullpath):
        return not os.path.basename(fullpath).startswith('linux,')
    for i in range(imghandler.vm.getVCpuCount()):
        # create new node and copy all properties
        cpu = cpus.addnode('PowerPC,970@%d' % i)
        _copynode(cpu, cpu0path, _nolinuxprops)

        # overwrite what we need to
        shadow_mb = imghandler.vm.info.get('shadow_memory', 1)
        shadow_mb_log = int(math.log(shadow_mb, 2))
        pft_size = shadow_mb_log + 20
        cpu.setprop('ibm,pft-size', 0, pft_size)

        # set default CPU
        if cpu0 == None:
            cpu0 = cpu

    chosen = root.addnode('chosen')
    chosen.addprop('cpu', cpu0.get_phandle())
    chosen.addprop('memory', rma.get_phandle())
    chosen.addprop('linux,stdout-path', '/xen/console\0')
    chosen.addprop('interrupt-controller', xen.get_phandle())
    chosen.addprop('bootargs', imghandler.cmdline + '\0')
    # xc_linux_load.c will overwrite these 64-bit properties later
    chosen.addprop('linux,initrd-start', long(0))
    chosen.addprop('linux,initrd-end', long(0))

    if 1:
        f = file('/tmp/domU.dtb', 'w')
        f.write(root.to_bin())
        f.close()

    return root
