# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from xenmgr import XendVdisk
from SrvVdiskDir import SrvVdiskDir

class SrvVdisk(SrvDir):
    """A virtual disk.
    """

    def __init__(self):
        SrvDir.__init__(self)
        self.xvdisk = XendVdisk.instance()
