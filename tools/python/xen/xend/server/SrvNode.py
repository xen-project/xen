# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import os

from SrvDir import SrvDir
from xen.xend import sxp
from xen.xend import XendNode
from xen.xend.Args import FormFn

class SrvNode(SrvDir):
    """Information about the node.
    """

    def __init__(self):
        SrvDir.__init__(self)
        self.xn = XendNode.instance()
        self.add('dmesg', 'SrvDmesg')
        self.add('log', 'SrvXendLog')

    def op_shutdown(self, op, req):
        val = self.xn.shutdown()
        return val

    def op_reboot(self, op, req):
        val = self.xn.reboot()
        return val

    def op_cpu_rrobin_slice_set(self, op, req):
        fn = FormFn(self.xn.cpu_rrobin_slice_set,
                    [['slice', 'int']])
        val = fn(req.args, {})
        return val

    def op_cpu_bvt_slice_set(self, op, req):
        fn = FormFn(self.xn.cpu_bvt_slice_set,
                    [['ctx_allow', 'int']])
        val = fn(req.args, {})
        return val
    
    def render_POST(self, req):
        return self.perform(req)

    def render_GET(self, req):
        try:
            if self.use_sxp(req):
                req.setHeader("Content-Type", sxp.mime_type)
                sxp.show(['node'] + self.info(), out=req)
            else:
                url = req.prePathURL()
                if not url.endswith('/'):
                    url += '/'
                req.write('<html><head></head><body>')
                self.print_path(req)
                req.write('<ul>')
                for d in self.info():
                    req.write('<li> %10s: %s' % (d[0], str(d[1])))
                req.write('<li><a href="%sdmesg">Xen dmesg output</a>' % url)
                req.write('<li><a href="%slog>Xend log</a>' % url)
                req.write('</ul>')
                req.write('</body></html>')
            return ''
        except Exception, ex:
            self._perform_err(ex, req)
            
    def info(self):
        return self.xn.info()
