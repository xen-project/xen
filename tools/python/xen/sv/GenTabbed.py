import types

from xen.sv.HTMLBase import HTMLBase
from xen.sv.TabView import TabView

class GenTabbed( HTMLBase ):

    def __init__( self, title, urlWriter, tabStrings, tabObjects ):
        HTMLBase.__init__(self)
        self.tab = 0;
        self.tabStrings = tabStrings
        self.tabObjects = tabObjects
        self.urlWriter = urlWriter
        self.title = title

    def write_BODY( self, request, urlWriter = None ):
        tab = request.args.get('tab')
        
        if tab is None or len( tab) != 1:
            self.tab = 0
        else:
            self.tab = int( tab[0] )
            
        request.write( "<table style='' width='100%' border='0' cellspacing='0' cellpadding='0'>" )
        request.write( "<tr><td>" )
        
        request.write( "<p align='center'><u>%s</u></p>" % self.title )
        
        TabView( self.tab, self.tabStrings, self.urlWriter ).write_BODY( request )
        
        request.write( "</td></tr><tr><td>" )
        
        render_tab = self.tabObjects[ self.tab ]
                
        if render_tab is None:
            request.write( "<p>Bad Tab</p>" )
            self.finish_BODY( request )
        else:
            render_tab().write_BODY( request )

        request.write( "</td></tr></table>" )
       
    def perform( self, request ):
        tab = request.args.get('tab')
        
        if tab is None or len( tab) != 1:
            self.tab = 0
        else:
            self.tab = int( tab[0] )
            
        op_tab = self.tabObjects[ self.tab ]
        
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
        
    def write_BODY( self, request ):
        request.write( "<p>%s</p>" % self.title )

class ActionTab( HTMLBase ):

    def __init__( self, actions ):
        self.actions = actions
        HTMLBase.__init__( self )
        
    def write_BODY( self, request ):
        request.write("<p align='center'>")
         
        for ( command, ( text, image ) ) in self.actions.items():
            request.write("<img src='images/%s' width='54' height='54' onclick='doOp( \"%s\" )' onmouseover='update( \"button_desc\", \"%s\" )' " % ( image, command, text ) )
            request.write("onmouseout='update( \"button_desc\", \"&nbsp;\" )' style='button'>")
            request.write("&nbsp;&nbsp;")
    
        request.write("<p align='center'><span id='button_desc'>&nbsp;</span></p>")   
        request.write("</p>")        
        
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
    
    
       
        
