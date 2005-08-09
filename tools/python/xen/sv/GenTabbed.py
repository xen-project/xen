import types

from xen.sv.HTMLBase import HTMLBase
from xen.sv.util import getVar

class GenTabbed( HTMLBase ):

    def __init__( self, title, urlWriter, tabStrings, tabObjects ):
        HTMLBase.__init__(self)
        self.tabStrings = tabStrings
        self.tabObjects = tabObjects
        self.urlWriter = urlWriter
        self.title = title
        
    def write_BODY( self, request ):
        if not self.__dict__.has_key( "tab" ):
            try:
                self.tab = int( getVar( 'tab', request, 0 ) )
            except:
                self.tab = 0
            
        request.write( "\n<div class='title'>%s</div>" % self.title )
        
        TabView( self.tab, self.tabStrings, self.urlWriter ).write_BODY( request )
        
        try:
            request.write( "\n<div class='tab'>" )
            render_tab = self.tabObjects[ self.tab ]
            render_tab( self.urlWriter ).write_BODY( request )
            request.write( "\n</div>" )
        except Exception, e:
            request.write( "\n<p>Error Rendering Tab</p>" )
            request.write( "\n<p>%s</p>" % str( e ) )

        request.write( "\n<input type=\"hidden\" name=\"tab\" value=\"%d\">" % self.tab )

    def perform( self, request ):
        request.write( "Tab> perform" )
        request.write( "<br/>op: " + str( getVar( 'op', request ) ) )
        request.write( "<br/>args: " + str( getVar( 'args', request ) ) )
        request.write( "<br/>tab: " + str( getVar( 'tab', request ) ) )      

        try:
            action = getVar( 'op', request, 0 )
            if action == "tab":
                self.tab = int( getVar( 'args', request ) )
            else:
                this.tab = int( getVar( 'tab', request, 0 ) )
                self.tabObjects[ self.tab ]( self.urlWriter ).perform( request )
        except:
            pass
        
class PreTab( HTMLBase ):

    def __init__( self, source ):
        HTMLBase.__init__( self )
        self.source = source
    
    def write_BODY( self, request ):
        request.write( "\n<pre>" )
        request.write( self.source )
        request.write( "\n</pre>" )

class GeneralTab( HTMLBase ):
                        
    def __init__( self, dict, titles ):
        HTMLBase.__init__( self )
        self.dict = dict
        self.titles = titles
                        
    def write_BODY( self, request ): 
        
        request.write( "\n<table width='100%' cellspacing='0' cellpadding='0' border='0'>" )
        
        def writeAttr( niceName, attr, formatter=None ):
            if type( attr ) is types.TupleType:
                ( attr, formatter ) = attr
            
            if attr in self.dict:
                if formatter:
                    temp = formatter( self.dict[ attr ] )
                else:
                    temp = str( self.dict[ attr ] )
                request.write( "\n<tr><td width='50%%'><p>%s:</p></td><td width='50%%'><p>%s</p></td></tr>" % ( niceName, temp ) )
        
        for niceName, attr in self.titles.items():
            writeAttr( niceName, attr )
                            
        request.write( "</table>" )

class NullTab( HTMLBase ):
    
    def __init__( self, title="Null Tab" ):
        HTMLBase.__init__( self )
        self.title = title

    def write_BODY( self, request ):
        request.write( "\n<p>%s</p>" % self.title )

class ActionTab( HTMLBase ):

    def __init__( self, actions ):
        self.actions = actions
        HTMLBase.__init__( self )
        
    def write_BODY( self, request ):
        for item in self.actions.items():
            try:
                ((op, attr), title) = item
            except:
                (op, title) = item
                attr = ""
            request.write( "\n<div class='button' onclick=\"doOp2( '%s', '%s' )\">%s</a></div>" % (op, attr, title) )

class CompositeTab( HTMLBase ):

    def __init__( self, tabs, urlWriter ):
    	HTMLBase.__init__( self )
        self.tabs = tabs
        self.urlWriter = urlWriter
        
    def write_BODY( self, request ):
    	for tab in self.tabs:
            tab( self.urlWriter ).write_BODY( request )
            
    def perform( self, request ):
    	for tab in self.tabs:
            tab( self.urlWriter ).perform( request )

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
            for i in range( len( self.tabs ) ):
                if self.tab == i:
                    at = " id='activeTab'"
                else:
                    at = ""
                request.write( "\n<div%s class='tabButton' onclick=\"doOp2( 'tab', '%d' )\">%s</div>" % ( at, i, self.tabs[ i ] ) )
