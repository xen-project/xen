from twisted.web.resource import Resource
from xen.sv.util import *

class HTMLBase( Resource ):

    isLeaf = True
 
    def __init__( self ):
        Resource.__init__(self)

    def render_POST( self, request ):
        self.perform( request )
        return self.render_GET( request )
        
    def render_GET( self, request ):
        self.write_TOP( request )
        self.write_BODY( request )
        self.write_BOTTOM( request )
        return ''
                
    def write_BODY( self, request ):
        request.write( "BODY" )
        
    def write_TOP( self, request ):
        request.write( '<html><head><title>Xen</title><link rel="stylesheet" type="text/css" href="inc/style.css" />' )
        request.write( '<script src="inc/script.js"></script>' )
        request.write( '</head><body>' )
        request.write('<form method="post" action="%s">' % request.uri)

    def write_BOTTOM( self, request ):
        request.write('<input type="hidden" name="op" value="">')
        request.write('<input type="hidden" name="args" value="">')
        request.write('</form>')
        request.write( "</body></html>" )

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
        it with op_foo(req). Replies with code 500 if op_foo
        is not found.

        The method must return a list when req.use_sxp is true
        and an HTML string otherwise (or list).
        Methods may also return a Deferred (for incomplete processing).

        req	request
        """
        op = req.args.get('op')
        if not op is None and len(op) == 1:
            op = op[0]
            op_method = self.get_op_method(op)
            if op_method:
                op_method( req )   
