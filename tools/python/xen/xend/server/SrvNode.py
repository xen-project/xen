#============================================================================
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
#============================================================================
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
#============================================================================


from xen.web.SrvDir import SrvDir
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

    def op_shutdown(self, _1, _2):
        val = self.xn.shutdown()
        return val

    def op_reboot(self, _1, _2):
        val = self.xn.reboot()
        return val

    def render_POST(self, req):
        return self.perform(req)

    def render_GET(self, req):
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
            req.write('<li><a href="%slog">Xend log</a>' % url)
            req.write('</ul>')
            req.write('</body></html>')
            
    def info(self):
        return self.xn.info()
