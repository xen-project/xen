# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import os

from xen.xend import sxp
from xen.xend import XendDmesg

from SrvDir import SrvDir

class SrvDmesg(SrvDir):
    """Xen Dmesg output.
    """

    def __init__(self):
        SrvDir.__init__(self)
        self.xd = XendDmesg.instance()

    def render_POST(self, req):
        self.perform(req)

    def render_GET(self, req):
        if self.use_sxp(req):
            req.setHeader("Content-Type", "text/plain")
            req.write(self.info())
        else:
            req.write('<html><head></head><body>')
            self.print_path(req)
            req.write('<pre>')
            req.write(self.info())
            req.write('</pre></body></html>')
            
    def info(self):
        return self.xd.info()

    def op_clear(self, op, req):
        self.xd.clear()
        return 0
