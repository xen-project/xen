from xen.sv.util import *
from xen.sv.HTMLBase import HTMLBase
from xen.xend import sxp

DEBUG = 1

class Wizard( HTMLBase ):

    def __init__( self, urlWriter, title, sheets ):
        HTMLBase.__init__( self )
        self.title = title
        self.sheets = sheets
        self.urlWriter = urlWriter
        
    def write_MENU( self, request ):
    	request.write( "<p class='small'><a href='%s'>%s</a></p>" % (self.urlWriter( '' ), self.title) ) 
    
    def write_BODY( self, request ):
        
   	request.write( "<table width='100%' border='0' cellspacing='0' cellpadding='0'><tr><td>" )
        request.write( "<p align='center'><u>%s</u></p></td></tr><tr><td>" % self.title )
        
        currSheet = getVar( 'sheet', request )
    
        if not currSheet is None:
            currSheet = int( currSheet )
        else:
            currSheet = 0
            
        op = getVar( 'op', request )
        
        if op == 'next':
            currSheet += 1
        elif op == 'prev':
            currSheet -= 1    
            
        self.sheets[ currSheet ]( self.urlWriter ).write_BODY( request )
        
        request.write( "</td></tr><tr><td><table width='100%' border='0' cellspacing='0' cellpadding='0'><tr>" )
        request.write( "<td width='80%'></td><td width='20%' align='center'><p align='center'>" )
	if currSheet > 0:
       		request.write( "<img src='images/previous.png' onclick='doOp( \"prev\" )' onmouseover='update( \"wizText\", \"Previous\" )' onmouseout='update( \"wizText\", \"&nbsp;\" )'>&nbsp;" )
        if currSheet < ( len( self.sheets ) - 1 ):        
        	request.write( "<img src='images/next.png' onclick='doOp( \"next\" )' onmouseover='update( \"wizText\", \"Next\" )' onmouseout='update( \"wizText\", \"&nbsp;\" )'>" )
        request.write( "</p><p align='center'><span id='wizText'></span></p></td></tr></table>" )
        request.write( "</td></tr></table>" )
        
    def op_next( self, request ):
    	pass
        
    def op_prev( self, request ):
    	pass  
        
class Sheet( HTMLBase ):

    def __init__( self, urlWriter, feilds, title, location ):
        HTMLBase.__init__( self )
        self.urlWriter = urlWriter
        self.feilds = feilds
        self.title = title
        self.location = location
        self.passback = "()"
        
    def parseForm( self, request ):
    	do_not_parse = [ 'mod', 'op', 'sheet' ] 
    
    	passed_back = request.args
        
        temp_passback = passed_back.get( "passback" )
        
        if temp_passback is not None and len( temp_passback ) > 0:
            temp_passback = temp_passback[ len( temp_passback )-1 ]
        else:
            temp_passback = "(passback )"        
        
        last_passback = ssxp2hash( string2sxp( temp_passback ) )
        
        if DEBUG: print last_passback
        
        try: 
            del passed_back[ 'passback' ]
        except:
            pass
        
        for (key, value) in passed_back.items():
            if key not in do_not_parse:
                last_passback[ key ] = value[ len( value ) - 1 ]
                
        self.passback = sxp2string( hash2sxp( last_passback ) ) #store the sxp
        
        if DEBUG: print self.passback
        
        return last_passback #return the hash
        
    def write_BODY( self, request ):
        
   	request.write( "<p>%s</p>" % self.title )
    
    	previous_values = self.parseForm( request ) #get the hash for quick reference
        
    	for (feild, name) in self.feilds:
            value = previous_values.get( feild )
            if value is None:
            	value = ''
            request.write( "<p>%s<input type='text' name='%s' value='%s'></p>" % (name, feild, value) )
        
        request.write( "<input type='hidden' name='passback' value=\"%s\"></p>" % self.passback )
        request.write( "<input type='hidden' name='sheet' value='%s'></p>" % self.location )        
                 
            
    
      
