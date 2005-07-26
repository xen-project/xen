import types

from xen.sv.HTMLBase import HTMLBase
from xen.sv.TabView import TabView
from xen.sv.util import getVar

class GenTabbed( HTMLBase ):

    def __init__( self, title, urlWriter, tabStrings, tabObjects ):
        HTMLBase.__init__(self)
        self.tabStrings = tabStrings
        self.tabObjects = tabObjects
        self.urlWriter = urlWriter
        self.title = title

    def write_BODY( self, request, urlWriter = None ):
        try:
            tab = int( getVar( 'tab', request, 0 ) )
        except:
            tab = 0
            
        request.write( "<table style='' width='100%' border='0' cellspacing='0' cellpadding='0'>" )
        request.write( "<tr><td>" )
        request.write( "<p align='center'><u>%s</u></p>" % self.title )
        
        TabView( tab, self.tabStrings, self.urlWriter ).write_BODY( request )
        
        request.write( "</td></tr><tr><td>" )

        try:
            render_tab = self.tabObjects[ tab ]
            render_tab().write_BODY( request )
        except:
            request.write( "<p>Error Rendering Tab</p>" )
       
        request.write( "</td></tr></table>" )
       
    def perform( self, request ):
        try:
            tab = int( getVar( 'tab', request, 0 ) )
        except:
            tab = 0;
            
        op_tab = self.tabObjects[ tab ]
        
        if op_tab:
            op_tab().perform( request )
        
class PreTab( HTMLBase ):

    def __init__( self, source ):
        HTMLBase.__init__( self )
        self.source = source
    
    def write_BODY( self, request ):
        
        request.write( "<div style='display: block; overflow: auto; border: 0px solid black; width: 540px; padding: 5px; z-index:0; align: center'><pre>" )
        
        request.write( self.source )
        
        request.write( "</pre></div>" )

class GeneralTab( HTMLBase ):
                        
    def __init__( self, dict, titles ):
        HTMLBase.__init__( self )
        self.dict = dict
        self.titles = titles
                        
    def write_BODY( self, request ): 
        
        request.write( "<table width='100%' cellspacing='0' cellpadding='0' border='0'>" )
        
        def writeAttr( niceName, attr, formatter=None ):
            if type( attr ) is types.TupleType:
                ( attr, formatter ) = attr
            
            if attr in self.dict:
                if formatter:
                    temp = formatter( self.dict[ attr ] )
                else:
                    temp = str( self.dict[ attr ] )
                request.write( "<tr><td width='50%%'><p>%s:</p></td><td width='50%%'><p>%s</p></td></tr>" % ( niceName, temp ) )
        
        for niceName, attr in self.titles.items():
            writeAttr( niceName, attr )
                            
        request.write( "</table>" )

class NullTab( HTMLBase ):
    
    def __init__( self ):
        HTMLBase.__init__( self )
        self.title = "Null Tab"

    def __init__( self, title ):
        HTMLBase.__init__( self )
        self.title = title
        
    def write_BODY( self, request ):
        request.write( "<p>%s</p>" % self.title )

class ActionTab( HTMLBase ):

    def __init__( self, actions ):
        self.actions = actions
        HTMLBase.__init__( self )
        
    def write_BODY( self, request ):
        request.write( "<p align='center'><table cellspacing='3' cellpadding='2' border='0'><tr>" )
    
        for ( command, text ) in self.actions.items():
            request.write( "<td style='border: 1px solid black; background-color: grey' onmouseover='buttonMouseOver( this )' onmouseout='buttonMouseOut( this )'>" )
            request.write( "<p><a href='javascript: doOp( \"%s\" );'>%s</a></p></td>" % (command, text) )
 
        request.write("</table></p>")        
        
class CompositeTab( HTMLBase ):

    def __init__( self, tabs ):
    	HTMLBase.__init__( self )
        self.tabs = tabs
        
    def write_BODY( self, request ):
    	for tab in self.tabs:
            request.write( "<br/>" )
            tab().write_BODY( request )
            
    def perform( self, request ):
    	for tab in self.tabs:
            tab().perform( request )
    
    
       
        
