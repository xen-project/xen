# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import types


from xen.xend import sxp
from xen.xend import PrettyPrint
from xen.xend.Args import ArgError
from xen.xend.XendError import XendError
from xen.xend.XendLogging import log

import resource
import http
import httpserver
import defer

def uri_pathlist(p):
    """Split a path into a list.
    p		path
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

        op	operation name
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

        req	request
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
            return op_method(op, req)

    def print_path(self, req):
        """Print the path with hyperlinks.
        """
        req.printPath()

