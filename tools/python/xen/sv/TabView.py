from xen.sv.HTMLBase import HTMLBase

class TabView( HTMLBase ):

    # tab - int, id into tabs of selected tab
    # tabs - list of strings, tab names
    # urlWriter - 
    def __init__( self, tab, tabs, urlWriter ):
        HTMLBase.__init__(self)
        self.tab = tab
        self.tabs = tabs
        self.urlWriter = urlWriter

    def write_BODY( self, request ):
        request.write( "<table style='' border='0' cellspacing='3' cellpadding='2' align='center'>" )
        request.write( "<tr height='22'>" )                  
    
        for i in range( len( self.tabs ) ):
            if self.tab == i:
                backgroundColor = "white"
            else:
                backgroundColor = "grey"
        
            request.write( "<td style='border:1px solid black; background-color: %s'><p align='center'><a href='%s'>%s</a></p></td>" % ( backgroundColor, self.urlWriter( "&tab=%s" % i ), self.tabs[ i ] ) )
  
        request.write( "</tr></table>" )
