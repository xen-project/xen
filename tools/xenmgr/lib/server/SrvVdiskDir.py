# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from xenmgr import XendVdisk
from SrvDir import SrvDir

class SrvVdiskDir(SrvDir):
    """Virtual disk directory.
    """

    def __init__(self):
        SrvDir.__init__(self)
        #self.xvdisk = XendVdisk.instance()

    def vdisk(self, x):
        val = None
        try:
            dom = self.xvdisk.vdisk_get(x)
            val = SrvVdisk(dom)
        except KeyError:
            pass
        return val

    def get(self, x):
        v = SrvDir.get(self, x)
        if v is not None:
            return v
        v = self.vdisk(x)
        return v
