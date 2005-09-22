from xen.sv.util import *
from xen.sv.HTMLBase import HTMLBase
from xen.sv.GenTabbed import GenTabbed, ActionTab
from xen.xend import sxp

import re

DEBUG = 0

class Wizard( GenTabbed ):

    def __init__( self, urlWriter, title, sheets ):
        self.title = title
        self.sheets = sheets
        self.urlWriter = urlWriter
        self.offset = 0
        GenTabbed.__init__( self, title, urlWriter, map( lambda x: x.title, sheets ), sheets ) 
        
    def write_MENU( self, request ):
    	request.write( "<p class='small'><a href='%s'>%s</a></p>" % (self.urlWriter( '' ), self.title) ) 
    
    def write_BODY( self, request ):
        GenTabbed.write_BODY( self, request )
        actionTab = ActionTab( { ("tab", str(self.tab-1)) : "< Prev", ("tab", str(self.tab+1)) : "Next >", "finish" : "Finish" } )
        actionTab.write_BODY( request )

    def perform( self, request ):
        try:
            action = getVar( 'op', request, 0 )
            if action == "tab":
                self.tab = int( getVar( 'args', request ) )
                oldtab = int( getVar( 'tab', request ) )
                if not self.tabObjects[ oldtab ]( self.urlWriter ).validate( request ):
                    self.tab = oldtab
            else:
                self.tab = int( getVar( 'tab', request, 0 ) )
                self.tabObjects[ self.tab ]( self.urlWriter ).perform( request )
                getattr( self, "op_" +  getVar( "op", request ), None )( request )
        except:
            pass
            
    def op_finish( self, request ):
    	pass  
        
class Sheet( HTMLBase ):

    def __init__( self, urlWriter, title, location ):
        HTMLBase.__init__( self )
        self.urlWriter = urlWriter
        self.fields = []
        self.title = title
        self.location = location
        self.passback = None
        
    def parseForm( self, request ):
    	do_not_parse = [ 'mod', 'op', 'passback' ] 
    
    	passed_back = request.args
        
        temp_passback = passed_back.get( "passback" )
        
        if temp_passback is not None and len( temp_passback ) > 0:
            temp_passback = temp_passback[ len( temp_passback )-1 ]
        else:
            temp_passback = "( )"        
        
        last_passback = ssxp2hash( string2sxp( temp_passback ) ) #use special function - will work with no head on sxp
        
        if DEBUG: print last_passback
        
        for (key, value) in passed_back.items():
            if key not in do_not_parse:
                last_passback[ key ] = value[ len( value ) - 1 ]
                
        self.passback = sxp2string( hash2sxp( last_passback ) ) #store the sxp
        
        if DEBUG: print self.passback
        
    def write_BODY( self, request ):
    
    	if not self.passback: self.parseForm( request )
        
   	request.write( "<p>%s</p>" % self.title )
    
    	previous_values = ssxp2hash( string2sxp( self.passback ) ) #get the hash for quick reference
        
        request.write( "<table width='100%' cellpadding='0' cellspacing='1' border='0'>" )
        
    	for (field, control) in self.fields:
            control.write_Control( request, previous_values.get( field ) )
            if previous_values.get( field ) is not None and not control.validate( previous_values.get( field ) ):
            	control.write_Help( request )
            
        request.write( "</table>" )
            
        request.write( "<input type='hidden' name='passback' value=\"%s\"></p>" % self.passback )
        #request.write( "<input type='hidden' name='visited-sheet%s' value='True'></p>" % self.location )
                
    def addControl( self, control ):
    	self.fields.append( [ control.getName(), control ] )
        
    def validate( self, request ):
    
        if not self.passback: self.parseForm( request )
            
    	check = True
        
        previous_values = ssxp2hash( string2sxp( self.passback ) ) #get the map for quick reference
    	if DEBUG: print previous_values
      
      	for (field, control) in self.fields:
            if not control.validate( previous_values.get( field ) ):
                check = False
                if DEBUG: print "> %s = %s" % (field, previous_values.get( field ))

        return check
        
class SheetControl( HTMLBase ):

    def __init__( self, reg_exp = ".*" ):
        HTMLBase.__init__( self )
        self.name = ""
        self.reg_exp = reg_exp 
        
    def write_Control( self, request, persistedValue ):
        request.write( "<tr colspan='2'><td>%s</td></tr>" % persistedValue )
        
    def write_Help( self, request ):
        request.write( "<tr><td align='right' colspan='2'><p class='small'>Text must match pattern:" )
        request.write( " %s</p></td></tr>" % self.reg_exp )
        
    def validate( self, persistedValue ):
    	if persistedValue is None:
            persistedValue = ""
            
        return not re.compile( self.reg_exp ).match( persistedValue ) is None

    def getName( self ):
    	return self.name
        
    def setName( self, name ):
    	self.name = name
        
class InputControl( SheetControl ):

    def __init__( self, name, defaultValue, humanText,  reg_exp = ".*", help_text = "You must enter the appropriate details in this field." ):
        SheetControl.__init__( self, reg_exp )
        self.setName( name )
        
        self.defaultValue = defaultValue
        self.humanText = humanText
        self.help_text = help_text
        
    def write_Control( self, request, persistedValue ):
    	if persistedValue is None:
            persistedValue = self.defaultValue
        
        request.write( "<tr><td width='50%%'><p>%s</p></td><td width='50%%'><input size='40'type='text' name='%s' value=\"%s\"></td></tr>" % (self.humanText, self.getName(), persistedValue) )

    def write_Help( self, request ):
        request.write( "<tr><td align='right' colspan='2'><p class='small'>" )
        request.write( " %s</p></td></tr>" % self.help_text )         
        
class TextControl( SheetControl ):

    def __init__( self, text ):
    	SheetControl.__init__( self )
        self.text = text
        
    def write_Control( self, request, persistedValue ):
    	request.write( "<tr><td colspan='2'><p>%s</p></td></tr>" % self.text )

class SmallTextControl( SheetControl ):

    def __init__( self, text ):
    	SheetControl.__init__( self )
        self.text = text
        
    def write_Control( self, request, persistedValue ):
    	request.write( "<tr><td colspan='2'><p class='small'>%s</p></tr></td>" % self.text )
        
class ListControl( SheetControl ):

    def __init__( self, name, options, humanText ):
    	SheetControl.__init__( self )
        self.setName( name )
        self.options = options
        self.humanText = humanText
        
    def write_Control( self, request, persistedValue ):
        request.write( "<tr><td width='50%%'><p>%s</p></td><td width='50%%'>" % self.humanText )
    	request.write( "<select name='%s'>" % self.getName() )
        for (value, text) in self.options:
            if value == persistedValue:
            	request.write( "<option value='%s' selected>%s\n" % (value, text) )
            else:
                request.write( "<option value='%s'>%s\n" % (value, text) )
        request.write( "</select></td></tr>" )

    def validate( self, persistedValue ):
        for (value, text) in self.options:
            if value == persistedValue:
                return True
                
        return False
        
class FileControl( InputControl ):

    def __init__( self, name, defaultValue, humanText,  reg_exp = ".*", help_text = "You must enter the appropriate details in this field." ):
	InputControl.__init__( self, name, defaultValue, humanText )
        
    def validate( self, persistedValue ):
        if persistedValue is None: return False
        try:
            open( persistedValue )
            return True
        except IOError, TypeError:
            return False
    
    def write_Help( self, request ):
        request.write( "<tr><td colspan='2' align='right'><p class='small'>File does not exist: you must enter a valid, absolute file path.</p></td></tr>" )

class TickControl( SheetControl ):

    def __init__( self, name, defaultValue, humanText ):
        SheetControl.__init__( self )
        self.setName( name )
        self.defaultValue = defaultValue
        self.humanText = humanText
        
    def write_Control( self, request, persistedValue ):
        request.write( "<tr><td width='50%%'><p>%s</p></td><td width='50%%'>" % self.humanText )

        #request.write( str( persistedValue ) )

        #TODO: Theres a problem with this: it doesn't persist an untick, because the browsers don't pass it back. Need a fix...
        
        if persistedValue == 'True':
    	    request.write( "<input type='checkbox' name='%s' value='True' checked>" % self.getName() )
        else:
    	    request.write( "<input type='checkbox' name='%s' value='True'>" % self.getName() )
            
        request.write( "</td></tr>" )

      
