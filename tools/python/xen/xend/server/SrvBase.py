# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

import cgi

import os
import sys
import types
import StringIO

from twisted.internet import defer
from twisted.internet import reactor
from twisted.web import error
from twisted.web import resource
from twisted.web import server

from xen.xend import sxp
from xen.xend import PrettyPrint

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

    def parse_form(self, req, method):
        """Parse the data for a request, GET using the URL, POST using encoded data.
        Posts should use enctype='multipart/form-data' in the <form> tag,
        rather than 'application/x-www-form-urlencoded'. Only 'multipart/form-data'
        handles file upload.

        req		request
        returns a cgi.FieldStorage instance
        """
        env = {}
        env['REQUEST_METHOD'] = method
        if self.query:
            env['QUERY_STRING'] = self.query
        val = cgi.FieldStorage(fp=req.rfile, headers=req.headers, environ=env)
        return val
    
    def use_sxp(self, req):
        """Determine whether to send an SXP response to a request.
        Uses SXP if there is no User-Agent, no Accept, or application/sxp is in Accept.

        req		request
        returns 1 for SXP, 0 otherwise
        """
        ok = 0
        user_agent = req.getHeader('User-Agent')
        accept = req.getHeader('Accept')
        if (not user_agent) or (not accept) or (accept.find(sxp.mime_type) >= 0):
            ok = 1
        return ok

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
        Methods may also return a Deferred (for incomplete processing).

        req	request
        """
        op = req.args.get('op')
        if op is None or len(op) != 1:
            req.setResponseCode(404, "Invalid")
            return ''
        op = op[0]
        op_method = self.get_op_method(op)
        if op_method is None:
            req.setResponseCode(501, "Not implemented")
            req.setHeader("Content-Type", "text/plain")
            req.write("Not implemented: " + op)
            return ''
        else:
            val = op_method(op, req)
            if isinstance(val, defer.Deferred):
                val.addCallback(self._cb_perform, req, 1)
                return server.NOT_DONE_YET
            else:
                self._cb_perform(val, req, 0)
                return ''

    def _cb_perform(self, val, req, dfr):
        """Callback to complete the request.
        May be called from a Deferred.
        """
        if isinstance(val, error.ErrorPage):
            req.write(val.render(req))
        elif self.use_sxp(req):
            req.setHeader("Content-Type", sxp.mime_type)
            sxp.show(val, req)
        else:
            req.write('<html><head></head><body>')
            self.print_path(req)
            if isinstance(val, types.ListType):
                req.write('<code><pre>')
                PrettyPrint.prettyprint(val, out=req)
                req.write('</pre></code>')
            else:
                req.write(str(val))
            req.write('</body></html>')
        if dfr:
            req.finish()

    def print_path(self, req):
        """Print the path with hyperlinks.
        """
        pathlist = [x for x in req.prepath if x != '' ]
        s = "/"
        req.write('<h1><a href="/">/</a>')
        for x in pathlist:
            s += x + "/"
            req.write(' <a href="%s">%s</a>/' % (s, x))
        req.write("</h1>")
