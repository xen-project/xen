from xen.sv.util import *
from xen.sv.HTMLBase import HTMLBase
from xen.xend import sxp

class Wizzard( HTMLBase ):

    def __init__( self, urlWriter, title, sheets ):
        HTMLBase.__init__( self )
        self.title = title
        self.sheets = sheets
        self.currSheet = 0
        self.urlWriter = urlWriter
        
    def write_MENU( self, request ):
    	request.write( "<p class='small'><a href='%s'>%s</a></p>" % (self.urlWriter( '' ), self.title) ) 
    
    def write_BODY( self, request ):
        
   	request.write( "<table width='100%' border='0' cellspacing='0' cellpadding='0'><tr><td>" )
        request.write( "<p align='center'><u>%s</u></p></td></tr><tr><td>" % self.title )
        
        currSheet = getVar( 'sheet', request )
    
        if not currSheet is None:
        
            self.currSheet = int( currSheet )
            
        self.sheets[ self.currSheet ]( self.urlWriter ).write_BODY( request )
        
        request.write( "</td></tr><tr><td><table width='100%' border='0' cellspacing='0' cellpadding='0'><tr>" )
        request.write( "<td width='80%'></td><td width='20%' align='center'>" )
        request.write( "<p align='center'><img src='images/previous.png' onclick='doOp( \"prev\" )' onmouseover='update( \"wizText\", \"Previous\" )' onmouseout='update( \"wizText\", \"&nbsp;\" )'>&nbsp;" )
        request.write( "<img src='images/next.png' onclick='doOp( \"next\" )' onmouseover='update( \"wizText\", \"Next\" )' onmouseout='update( \"wizText\", \"&nbsp;\" )'></p>" )
        request.write( "<p align='center'><span id='wizText'></span></p></td></tr></table>" )
        request.write( "</td></tr></table>" )
        
class Sheet( HTMLBase ):

    def __init__( self, urlWriter, feilds, title ):
        HTMLBase.__init__( self )
        self.urlWriter = urlWriter
        self.feilds = feilds
        self.title = title
        
    def parseForm( self, request ):
    	return sxp.toString( request.args )
        
    def write_BODY( self, request ):
   	request.write( "<p>%s</p>" % self.title )
    
    	previous_values = request.args
        
    	for (feild, name) in self.feilds:
            value = sxp.child_value( previous_values, feild )
            if value is None:
            	value = ''
            request.write( "<p>%s<input type='text' name='%s' value='%s'></p>" % (name, feild, value) )
            
    def op_next( self, request ):
    	pass
        
    def op_prev( self, request ):
    	pass        
            
    
      
