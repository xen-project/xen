import types

from HTMLBase import HTMLBase
from TabView import TabView

class GenTabbed( HTMLBase ):

    def __init__( self, urlWriter, tabStrings, tabObjects, callback ):
        HTMLBase.__init__(self)
        self.tab = 0;
        self.tabStrings = tabStrings
        self.tabObjects = tabObjects
        self.urlWriter = urlWriter
        self.callback = callback

    def write_BODY( self, request, urlWriter = None ):
        tab = request.args.get('tab')
        
        if tab is None or len( tab) != 1:
            self.tab = 0
        else:
            self.tab = int( tab[0] )
            
        request.write( "<table style='' width='100%' border='0' cellspacing='0' cellpadding='0'>" )
        request.write( "<tr><td>" )
        
        TabView( self.tab, self.tabStrings, self.urlWriter ).write_BODY( request )
        
        request.write( "</td></tr><tr><td>" )
        
        render_tab = self.tabObjects[ self.tab ]()
                
        if render_tab is None:
            request.write( "<p>Bad Tab</p>" )
            self.finish_BODY( request )
        else:
            render_tab.write_BODY( request, self.finish_BODY )

    def finish_BODY( self, request ):
            
        request.write( "</td></tr></table>" )
        
        self.callback( request )
    
class PreTab( HTMLBase ):

    def __init__( self, source ):
        HTMLBase.__init__( self )
        self.source = source
    
    def write_BODY( self, request, callback ):
        
        request.write( "<div style='display: block; overflow: auto; border: 0px solid black; height: 400px; width: 540px; padding: 5px; z-index:0; align: center'><pre>" )
        
        request.write( self.source )
        
        request.write( "</pre></div>" )
        
        callback( request )

class GeneralTab( HTMLBase ):
                        
    def __init__( self, title, dict, titles ):
        HTMLBase.__init__( self )
        self.title = title
        self.dict = dict
        self.titles = titles
                        
    def write_BODY( self, request, callback ): 
        
        request.write( "<p><u>%s</u></p>" % self.title )
        
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
        
        callback( request )
    
class NullTab( HTMLBase ):
    
    def __init__( self ):
        HTMLBase.__init__( self )
        self.title = "Null Tab"
        
    def write_BODY( self, request, callback ):
        request.write( "<p>%s</p>" % self.title )
        callback( request )
         
        