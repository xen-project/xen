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

import http

def findResource(resource, request):
    """Traverse resource tree to find who will handle the request."""
    while request.postpath and not resource.isLeaf:
        #print 'findResource:', resource, request.postpath
        pathElement = request.postpath.pop(0)
        request.prepath.append(pathElement)
        next = resource.getPathResource(pathElement, request)
        if not next: break
        resource = next
    return resource

class Resource:

    isLeaf = False

    def __init__(self):
        self.children = {}

    def getRequestResource(self, req):
        return findResource(self, req)

    def getChild(self, path, request):
        return None

    def getPathResource(self, path, request):
        #print 'getPathResource>', self, path
        if self.children.has_key(path):
            val =  self.children[path]
        else:
            val = self.getChild(path, request)
        #print 'getPathResource<', val
        return val

    def putChild(self, path, child):
        self.children[path] = child
        #child.server = self.server

    def render(self, req):
        meth = getattr(self, 'render_' + req.getRequestMethod(), self.unsupported)
        return meth(req)

    def supportedMethods(self):
        l = []
        s = 'render_'
        for x in dir(self):
            if x.startswith(s):
                l.append(x[len(s):])
        return l

    def render_HEAD(self, req):
        return self.render_GET(req)

    def render_GET(self, req):
        req.setContentType("text/plain")
        req.write("GET")

    def render_POST(self, req):
        req.setContentType("text/plain")
        req.write("POST")

    def unsupported(self, req):
        req.setHeader("Accept", ",".join(self.supportedMethods()))
        req.setResponseCode(http.NOT_IMPLEMENTED)
        req.setContentType("text/plain")
        req.write("Request method not supported (%s)" % req.getRequestMethod())

class ErrorPage(Resource):

    isLeaf = True
    
    def __init__(self, code, status=None, msg=None):
        Resource.__init__(self)
        if status is None:
            status = http.getStatus(code)
        if msg is None:
            msg = status
        self.code = code
        self.status = status
        self.msg = msg

    def render(self, req):
        req.setResponseCode(self.code, self.status)
        req.setContentType("text/plain")
        req.write(self.msg)
        

    
    

