from twisted.web.resource import Resource

class HTMLBase( Resource ):

    isLeaf = True
 
    def __init__( self ):
        Resource.__init__(self)

    def render_GET( self, request ):
        self.write_TOP( request )
        self.write_BODY( request )
        self.write_BOTTOM( request )
        request.finish()
        return ''
                
    def write_BODY( self, request ):
        request.write( "BODY" )
        
    def write_TOP( self, request ):
        request.write( '<html><head><title>Xen</title><link rel="stylesheet" type="text/css" href="inc/style.css" />' )
        request.write( '</head><body>' )

    def write_BOTTOM( self, request ):
        request.write( "</body></html>" )
