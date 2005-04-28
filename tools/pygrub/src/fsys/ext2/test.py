#!/usr/bin/python


import _pyext2
import struct, os, sys

fs = _pyext2.Ext2Fs("test.img")

f = fs.open_file("/boot/vmlinuz-2.6.11-1.1177_FC4")
buf = f.read()
o = open("vmlinuz", "wb+")
o.write(buf)
o.close()

f.close()
