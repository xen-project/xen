from xen.xend.XendClient import aserver as server
from xen.xend import PrettyPrint

from xen.sv.HTMLBase import HTMLBase
from xen.sv.util import *
from xen.sv.GenTabbed import *

class DomInfo( GenTabbed ):

    def __init__( self, urlWriter ):
        
        self.dom = 0;
    
        def tabUrlWriter( tab ):
            return urlWriter( "mod=info&dom=%s%s" % ( self.dom, tab ) )
        
        GenTabbed.__init__( self, tabUrlWriter, [ 'General', 'SXP', 'Devices' ], [ DomGenTab, DomSXPTab, NullTab ]  )

    def write_BODY( self, request ):
        dom = request.args.get('dom')
        
        if dom is None or len(dom) != 1:
            request.write( "<p>Please Select a Domain</p>" )
            return None
        else:
            self.dom = dom[0]
        
        GenTabbed.write_BODY( self, request )

class DomGenTab( GeneralTab ):

    def __init__( self ):
    
        titles = {}
    
        titles[ 'ID' ] = 'dom'      
        titles[ 'Name' ] = 'name'
        titles[ 'CPU' ] = 'cpu'
        titles[ 'Memory' ] = ( 'mem', memoryFormatter )
        titles[ 'State' ] = ( 'state', stateFormatter )
        titles[ 'Total CPU' ] = ( 'cpu_time', smallTimeFormatter )
        titles[ 'Up Time' ] = ( 'up_time', bigTimeFormatter )
    
        GeneralTab.__init__( self, "General Domain Info", {}, titles )
        
    def write_BODY( self, request ):
    
        dom = request.args.get('dom')
        
        if dom is None or len(dom) != 1:
            request.write( "<p>Please Select a Domain</p>" )
            return None
        else:
            self.dom = dom[0]
            
        self.dict = getDomInfoHash( self.dom )
        
        GeneralTab.write_BODY( self, request )
            
class DomSXPTab( PreTab ):

    def __init__( self ):
        self.dom = 0
        PreTab.__init__( self, "" )


    def write_BODY( self, request ):
        dom = request.args.get('dom')
        
        if dom is None or len(dom) != 1:
            request.write( "<p>Please Select a Domain</p>" )
            return None
        else:
            self.dom = dom[0]
            
        domInfo = server.xend_domain( self.dom )
        
        self.source = sxp2string( domInfo )
        
        PreTab.write_BODY( self, request )
        

