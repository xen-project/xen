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

import types

from xen.xend import sxp
from xen.xend import PrettyPrint
from xen.xend.Args import ArgError
from xen.xend.XendError import XendError, XendInvalidDomain
#from xen.xend.XendLogging import log

import resource
import http

from xen.web.SrvBase import SrvBase

class SrvConstructor:
    """Delayed constructor for sub-servers.
    Does not import the sub-server class or create the object until needed.
    """

    def __init__(self, klass):
        """Create a constructor. It is assumed that the class
        should be imported as 'from xen.xend.server.klass import klass'.

        klass name of its class
        """
        self.klass = klass
        self.obj = None

    def getobj(self):
        """Get the sub-server object, importing its class and instantiating it if
        necessary.
        """
        if not self.obj:
            exec 'from xen.xend.server.%s import %s' % (self.klass, self.klass)
            klassobj = eval(self.klass)
            self.obj = klassobj()
        return self.obj

class SrvDir(SrvBase):
    """Base class for directory servlets.
    """
    isLeaf = False
    
    def __init__(self):
        SrvBase.__init__(self)
        self.table = {}
        self.order = []

    def noChild(self, msg):
        return resource.ErrorPage(http.NOT_FOUND, msg=msg)

    def getChild(self, x, req):
        if x == '': return self
        try:
            val = self.get(x)
        except XendError, ex:
            return self.noChild(str(ex))
        except XendInvalidDomain, ex:
            return self.noChild(str(ex))
        if val is None:
            return self.noChild('Not found: ' + str(x))
        else:
            return val

    def get(self, x):
        val = self.table.get(x)
        if isinstance(val, SrvConstructor):
            val = val.getobj()
        return val

    def add(self, x, v=None):
        if v is None:
            v = 'SrvDir'
        if isinstance(v, types.StringType):
            v = SrvConstructor(v)
        self.table[x] = v
        self.order.append(x)
        return v

    def render_GET(self, req):
        if self.use_sxp(req):
            req.setHeader("Content-type", sxp.mime_type)
            self.ls(req, 1)
        else:
            req.write('<html><head></head><body>')
            self.print_path(req)
            self.ls(req)
            self.form(req)
            req.write('</body></html>')
        return ''
            
    def ls(self, req, use_sxp=0):
        url = req.prePathURL()
        if not url.endswith('/'):
            url += '/'
        if use_sxp:
           req.write('(ls ')
           for k in self.order:
               req.write(' ' + k)
           req.write(')')
        else:
            req.write('<ul>')
            for k in self.order:
                v = self.get(k)
                req.write('<li><a href="%s%s">%s</a></li>'
                          % (url, k, k))
            req.write('</ul>')

    def form(self, req):
        pass
