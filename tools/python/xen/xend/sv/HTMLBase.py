from twisted.web import server, resource
from twisted.internet import reactor

class HTMLBase( resource.Resource ):
	
    isLeaf = True
		
    def __init__( self ):
        resource.Resource.__init__(self)
		
    def render_GET( self, request ):
        self.write_TOP( request )
        return self.write_BODY( request, self.finish_render_GET )

    def finish_render_GET( self, request ):
        self.write_BOTTOM( request )
        request.finish()
                
    def write_BODY( self, request ):
		request.write( "BODY" )
        
    def write_TOP( self, request ):
        request.write( '<html><head><title>Xen</title><link rel="stylesheet" type="text/css" href="inc/style.css" />' )
        request.write( '</head><body>' )

    def write_BOTTOM( self, request ):
        request.write( "</body></html>" )