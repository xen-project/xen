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

from xen.web import static

from xen.xend import XendLogging

from xen.web.SrvDir import SrvDir

class SrvXendLog(SrvDir):
    """Xend log.
    """

    def __init__(self):
        SrvDir.__init__(self)
        self.logfile = static.File(XendLogging.getLogFilename(),
                                   defaultType="text/plain")
        self.logfile.type = "text/plain"
        self.logfile.encoding = None

    def render_GET(self, req):
        return self.logfile.render(req)
