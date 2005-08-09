from xen.sv.util import *

class HTMLBase:

    isLeaf = True
 
    def __init__( self ):
        pass

    def render_POST( self, request ):
        self.perform( request )
        return self.render_GET( request )
        
    def render_GET( self, request ):
        pass
    
    def write_BODY( self, request ):
        pass
        
    def write_TOP( self, request ):
        pass
    
    def write_BOTTOM( self, request ):
        pass
    
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
