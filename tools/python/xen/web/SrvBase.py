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
from xen.xend.XendError import XendError
from xen.xend.XendLogging import log

import resource
import http
import httpserver

def uri_pathlist(p):
    """Split a path into a list.
    p path
    return list of path elements
    """
    l = []
    for x in p.split('/'):
        if x == '': continue
        l.append(x)
    return l

class SrvBase(resource.Resource):
    """Base class for services.
    """

    
    def use_sxp(self, req):
        return req.useSxp()
    
    def get_op_method(self, op):
        """Get the method for an operation.
        For operation 'foo' looks for 'op_foo'.

        op operation name
        returns method or None
        """
        op_method_name = 'op_' + op
        return getattr(self, op_method_name, None)
        
    def perform(self, req):
        """General operation handler for posted operations.
        For operation 'foo' looks for a method op_foo and calls
        it with op_foo(op, req). Replies with code 500 if op_foo
        is not found.

        The method must return a list when req.use_sxp is true
        and an HTML string otherwise (or list).
        Methods may also return a ThreadRequest (for incomplete processing).

        req request
        """
        op = req.args.get('op')
        if op is None or len(op) != 1:
            req.setResponseCode(http.NOT_ACCEPTABLE, "Invalid request")
            return ''
        op = op[0]
        op_method = self.get_op_method(op)
        if op_method is None:
            req.setResponseCode(http.NOT_IMPLEMENTED, "Operation not implemented: " + op)
            req.setHeader("Content-Type", "text/plain")
            req.write("Operation not implemented: " + op)
            return ''
        else:
            try:
                return op_method(op, req)
            except Exception, exn:
                req.setResponseCode(http.INTERNAL_SERVER_ERROR, "Request failed: " + op)
                log.exception("Request %s failed.", op)
                if req.useSxp():
                    return ['xend.err', str(exn)]
                else:
                    return "<p>%s</p>" % str(exn)

    def print_path(self, req):
        """Print the path with hyperlinks.
        """
        req.printPath()

