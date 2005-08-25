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
# Copyright (C) 2005 Mike Wray <mike.wray@hp.com>
#============================================================================
# HTTP interface onto xenstore (read-only).
# Mainly intended for testing.

import os
import os.path

from xen.web.httpserver import HttpServer, UnixHttpServer
from xen.web.SrvBase import SrvBase
from xen.web.SrvDir import SrvDir
from xen.xend.Args import FormFn
from xen.xend.xenstore import XenNode

def pathurl(req):
    url = req.prePathURL()
    if not url.endswith('/'):
        url += '/'
    return url
    
def writelist(req, l):
    req.write('(')
    for k in l:
       req.write(' ' + k)
    req.write(')')

def lsData(dbnode, req, url):
    v = dbnode.getData()
    if v is None:
        req.write('<p>No data')
    else:
        req.write('<p>Data: <pre>')
        req.write(str(v))
        req.write('</pre>')
    v = dbnode.getLock()
    if v is None:
        req.write("<p>Unlocked")
    else:
        req.write("<p>Lock = %s" % v)

def lsChildren(dbnode, req, url):
    l = dbnode.ls()
    if l:
        req.write('<p>Children: <ul>')
        for key in l:
            child = dbnode.getChild(key)
            data = child.getData()
            if data is None: data = ""
            req.write('<li><a href="%(url)s%(key)s">%(key)s</a> %(data)s</li>'
                      % { "url": url, "key": key, "data": data })
        req.write('</ul>')
    else:
        req.write('<p>No children')
        

class DBDataResource(SrvBase):
    """Resource for the node data.
    """

    def __init__(self, dbnode):
        SrvBase.__init__(self)
        self.dbnode = dbnode

    def render_GET(self, req):
        req.write('<html><head></head><body>')
        self.print_path(req)
        req.write("<pre>")
        req.write(self.getData() or self.getNoData())
        req.write("</pre>")
        req.write('</body></html>')

    def getContentType(self):
        # Use content-type from metadata.
        return "text/plain"

    def getData(self):
        v = self.dbnode.getData()
        if v is None: return v
        return str(v)

    def getNoData(self):
        return ""

class DBNodeResource(SrvDir):
    """Resource for a DB node.
    """

    def __init__(self, dbnode):
        SrvDir.__init__(self)
        self.dbnode = dbnode

    def get(self, x):
        val = None
        if x == "__data__":
            val = DBDataResource(self.dbnode)
        else:
            if self.dbnode.exists(x):
                child = self.dbnode.getChild(x, create=False)
            else:
                child = None
            if child is not None:
                val = DBNodeResource(child)
        return val

    def render_POST(self, req):
        return self.perform(req)

    def ls(self, req, use_sxp=0):
        if use_sxp:
            writelist(req, self.dbnode.getChildren())
        else:
            url = pathurl(req)
            req.write("<fieldset>")
            lsData(self.dbnode, req, url)
            lsChildren(self.dbnode, req, url)
            req.write("</fieldset>")

    def form(self, req):
        url = req.prePathURL()
        pass
        
class DBRootResource(DBNodeResource):
    """Resource for the root of a DB.
    """

    def __init__(self):
        DBNodeResource.__init__(self, XenNode())

def main(argv):
    root = SrvDir()
    root.putChild('xenstore', DBRootResource())
    interface = ''
    port = 8003
    server = HttpServer(root=root, interface=interface, port=port)
    server.run()
