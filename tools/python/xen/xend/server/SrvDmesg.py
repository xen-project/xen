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
# Copyright (C) 2005 XenSource Ltd
#============================================================================


from xen.xend import XendDmesg

from xen.web.SrvDir import SrvDir


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

    def op_clear(self, _1, _2):
        self.xd.clear()
        return 0
