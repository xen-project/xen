# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import os
from SrvDir import SrvDir
from xen.xend import sxp
from xen.xend import XendDmesg

class SrvDmesg(SrvDir):
    """Xen Dmesg output.
    """

    def __init__(self):
        SrvDir.__init__(self)
        self.xd = XendDmesg.instance()

    def render_GET(self, req):
        try:
            if self.use_sxp(req):
                req.setHeader("Content-Type", sxp.mime_type)
                sxp.show(['dmesg'] + self.info(), out=req)
            else:
                req.write('<html><head></head><body>')
                req.write('<pre>')
                self.print_path(req)
                req.write(self.info()[0])
                req.write('</pre></body></html>')
            return ''
        except Exception, ex:
            self._perform_err(ex, req)
            
    def info(self):
        return self.xd.info()
