# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Handler for node operations.
 Has some persistent state:
 - logs
 - notification urls

"""

import Xc

class XendNodeInfo:
    """Node information record.
    """

    def __init__(self):
        pass

class XendNode:

    def __init__(self):
        self.xc = Xc.new()

    def shutdown(self):
        return 0

    def reboot(self):
        return 0

    def notify(self, uri):
        return 0
    
    def cpu_bvt_slice_set(self, slice):
        ret = 0
        #ret = self.xc.bvtsched_global_set(ctx_allow=slice)
        return ret

    def cpu_bvt_slice_get(self, slice):
        ret = 0
        #ret = self.xc.bvtsched_global_get()
        return ret
    
    def cpu_rrobin_slice_set(self, slice):
        ret = 0
        #ret = self.xc.rrobin_global_set(slice)
        return ret

def instance():
    global inst
    try:
        inst
    except:
        inst = XendNode()
    return inst

