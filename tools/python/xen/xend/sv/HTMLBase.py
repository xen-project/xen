from twisted.web import server, resource
from twisted.internet import reactor

class HTMLBase( resource.Resource ):
	
    isLeaf = True
    
    defaultPath = "/usr/lib/python2.2/site-packages/xen/xend/sv/"
		
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
        f = open( self.defaultPath + 'inc/top.htm', 'r' )
        request.write( f.read() )

    def write_BOTTOM( self, request ):
        f = open( self.defaultPath + 'inc/bottom.htm', 'r' )
        request.write( f.read() )