# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from xenmgr import XendRoot
xroot = XendRoot.instance()
from SrvDir import SrvDir

class SrvRoot(SrvDir):
    """The root of the xend server.
    """

    """Server sub-components. Each entry is (name, class), where
    'name' is the entry name and  'class' is the name of its class.
    """
    #todo Get this list from the XendRoot config.
    subdirs = [
        ('node',    'SrvNode'       ),
        ('domain',  'SrvDomainDir'  ),
        ('console', 'SrvConsoleDir' ),
        ('event',   'SrvEventDir'   ),
        ('vdisk',   'SrvVdiskDir'   ),
        ('device',  'SrvDeviceDir'  ),
        ('vnet',    'SrvVnetDir'    ),
        ]

    def __init__(self):
        SrvDir.__init__(self)
        for (name, klass) in self.subdirs:
            self.add(name, klass)
        for (name, klass) in self.subdirs:
            self.get(name)
        xroot.start()
