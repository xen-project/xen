from xen.xend.sv.HTMLBase import HTMLBase

class TabView( HTMLBase ):

    def __init__( self, tab, tabs, urlWriter ):
        HTMLBase.__init__(self)
        self.tab = tab # interger - tab id
        self.tabs = tabs
        self.urlWriter = urlWriter

    def write_BODY( self, request ):
        request.write( "<table style='' border='0' cellspacing='0' cellpadding='0' align='center'>" )
        request.write( "<tr height='22'>" )
        
        if self.tab == 0:
            image = "left-end-highlight.jpg"
        else:
            image = "left-end-no-highlight.jpg"
            
        request.write( "<td height='22' width='14'><image src='images/%s' width='14' height='22'></td>" % image )  
                  
        count = len( self.tabs )

        for i in range( count ):
        
            if i == self.tab:
                image = "middle-highlight.jpg" 
            else:
                image = "middle-no-highlight.jpg"
            
            request.write( "<td style='background: url(images/%s)'><p align='center'><a href='%s'>%s</a></p></td>" % ( image, self.urlWriter( "&tab=%s" % i ), self.tabs[ i ] ) )

            if i < count-1:
                if i == self.tab:
                    image = "seperator-left-highlight.jpg"
                elif self.tab == i+1:
                    image = "seperator-right-highlight.jpg"                 
                else:
                    image = "seperator.jpg"
                    
                request.write( "<td height='22' width='23'><image src='images/%s' width='23' height='22'></td>" % image )
                    
        if self.tab == count - 1:
            image = "right-end-highlight.jpg"
        else:
            image = "right-end-no-highlight.jpg"
        
        request.write( "<td height='22' width='14'><image src='images/%s' width='14' height='22'></td>" % image )  
        request.write( "</tr></table>" )
