 # Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Get dmesg output for this node.
"""

import os
import xen.lowlevel.xc

class XendDmesg:
    def __init__(self):
        self.xc = xen.lowlevel.xc.new()

    def info(self):
        return self.xc.readconsolering()

    def clear(self):
        self.xc.readconsolering(True)

def instance():
    global inst
    try:
        inst
    except:
        inst = XendDmesg()
    return inst

