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

_OF_DT_HEADER = int("d00dfeed", 16) # avoid signed/unsigned FutureWarning
_OF_DT_BEGIN_NODE = 0x1
_OF_DT_END_NODE = 0x2
_OF_DT_PROP = 0x3
_OF_DT_END = 0x9

def _bincat(seq, separator=''):
    '''Concatenate the contents of seq into a bytestream.'''
    strs = []
    for item in seq:
        if type(item) == type(0):
            strs.append(struct.pack(">I", item))
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

_host_devtree_root = '/proc/device-tree'
def _getprop(propname):
    '''Extract a property from the system's device tree.'''
    f = file(os.path.join(_host_devtree_root, propname), 'r')
    data = f.read()
    f.close()
    return data

def _copynode(node, dirpath, propfilter):
    '''Extract all properties from a node in the system's device tree.'''
    dirents = os.listdir(dirpath)
    for dirent in dirents:
        fullpath = os.path.join(dirpath, dirent)
        st = os.lstat(fullpath)
        if stat.S_ISDIR(st.st_mode):
            child = node.addnode(dirent)
            _copytree(child, fullpath, propfilter)
        elif stat.S_ISREG(st.st_mode) and propfilter(fullpath):
            node.addprop(dirent, _getprop(fullpath))

def _copytree(node, dirpath, propfilter):
    path = os.path.join(_host_devtree_root, dirpath)
    _copynode(node, path, propfilter)

def build(imghandler):
    '''Construct a device tree by combining the domain's configuration and
    the host's device tree.'''
    root = Tree()

    # 4 pages: start_info, console, store, shared_info
    root.reserve(0x3ffc000, 0x4000)

    root.addprop('device_type', 'chrp-but-not-really\0')
    root.addprop('#size-cells', 2)
    root.addprop('#address-cells', 2)
    root.addprop('model', 'Momentum,Maple-D\0')
    root.addprop('compatible', 'Momentum,Maple\0')

    xen = root.addnode('xen')
    xen.addprop('start-info', 0, 0x3ffc000, 0, 0x1000)
    xen.addprop('version', 'Xen-3.0-unstable\0')
    xen.addprop('reg', 0, imghandler.vm.domid, 0, 0)
    xen.addprop('domain-name', imghandler.vm.getName() + '\0')
    xencons = xen.addnode('console')
    xencons.addprop('interrupts', 1, 0)

    # XXX split out RMA node
    mem = root.addnode('memory@0')
    totalmem = imghandler.vm.getMemoryTarget() * 1024
    mem.addprop('reg', 0, 0, 0, totalmem)
    mem.addprop('device_type', 'memory\0')

    cpus = root.addnode('cpus')
    cpus.addprop('smp-enabled')
    cpus.addprop('#size-cells', 0)
    cpus.addprop('#address-cells', 1)

    # Copy all properties the system firmware gave us, except for 'linux,'
    # properties, from 'cpus/@0', once for every vcpu. Hopefully all cpus are
    # identical...
    cpu0 = None
    def _nolinuxprops(fullpath):
        return not os.path.basename(fullpath).startswith('linux,')
    for i in range(imghandler.vm.getVCpuCount()):
        cpu = cpus.addnode('PowerPC,970@0')
        _copytree(cpu, 'cpus/PowerPC,970@0', _nolinuxprops)
        # and then overwrite what we need to
        pft_size = imghandler.vm.info.get('pft-size', 0x14)
        cpu.setprop('ibm,pft-size', 0, pft_size)

        # set default CPU
        if cpu0 == None:
            cpu0 = cpu

    chosen = root.addnode('chosen')
    chosen.addprop('cpu', cpu0.get_phandle())
    chosen.addprop('memory', mem.get_phandle())
    chosen.addprop('linux,stdout-path', '/xen/console\0')
    chosen.addprop('interrupt-controller', xen.get_phandle())
    chosen.addprop('bootargs', imghandler.cmdline + '\0')
    # xc_linux_load.c will overwrite these 64-bit properties later
    chosen.addprop('linux,initrd-start', 0, 0)
    chosen.addprop('linux,initrd-end', 0, 0)

    if 1:
        f = file('/tmp/domU.dtb', 'w')
        f.write(root.to_bin())
        f.close()

    return root
