from xen.xend.XendClient import aserver as server
from xen.xend import PrettyPrint

from xen.sv.HTMLBase import HTMLBase
from xen.sv.util import *
from xen.sv.GenTabbed import *

class DomInfo( GenTabbed ):

    def __init__( self, urlWriter ):
        
        self.dom = 0;
    
        def tabUrlWriter( tab ):
            return urlWriter( "&dom=%s%s" % ( self.dom, tab ) )
        
        GenTabbed.__init__( self, "Domain Info", tabUrlWriter, [ 'General', 'SXP', 'Devices' ], [ DomGeneralTab, DomSXPTab, NullTab ]  )

    def write_BODY( self, request ):
        dom = request.args.get('dom')
        
        if dom is None or len(dom) != 1:
            request.write( "<p>Please Select a Domain</p>" )
            return None
        else:
            self.dom = dom[0]
        
        GenTabbed.write_BODY( self, request )
        
    def write_MENU( self, request ):
        pass

class DomGeneralTab( CompositeTab ):
    def __init__( self ):
       CompositeTab.__init__( self, [ DomGenTab, DomActionTab ] )        
        
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
    
        GeneralTab.__init__( self, {}, titles )
        
    def write_BODY( self, request ):
    
        self.dom = getVar('dom', request)
        
        if self.dom is None:
            request.write( "<p>Please Select a Domain</p>" )
            return None
            
        self.dict = getDomInfoHash( self.dom )
        
        GeneralTab.write_BODY( self, request )
            
class DomSXPTab( PreTab ):

    def __init__( self ):
        self.dom = 0
        PreTab.__init__( self, "" )


    def write_BODY( self, request ):
        self.dom = getVar('dom', request)
        
        if self.dom is None:
            request.write( "<p>Please Select a Domain</p>" )
            return None

        domInfo = server.xend_domain( self.dom )
        
        self.source = sxp2prettystring( domInfo )
        
        PreTab.write_BODY( self, request )
        
class DomActionTab( ActionTab ):

    def __init__( self ):
    	actions = { "shutdown" : ( "Shutdown the Domain", "shutdown.png" ),
        	    "reboot" : ( "Reboot the Domain", "reboot.png" ),
                    "pause" : ( "Pause the Domain", "pause.png" ),
                    "unpause" : ( "Unpause the Domain", "unpause.png" ) }
        ActionTab.__init__( self, actions )    
        
    def op_shutdown( self, request ):
   	dom = getVar( 'dom', request )
        if not dom is None:
    	   print ">DomShutDown %s" % dom
    	#server.xend_node_shutdown()
    
    def op_reboot( self, request ):
       	dom = getVar( 'dom', request )
        if not dom is None:
    	    print ">DomReboot %s" % dom
        #server.xend_node_reboot()
        
    def op_pause( self, request ):
       	dom = getVar( 'dom', request )
        if not dom is None:
    	    print ">DomPause %s" % dom
            server.xend_domain_pause( int( dom ) )
        
    def op_unpause( self, request ):
       	dom = getVar( 'dom', request )
        if not dom is None:
    	   print ">DomUnpause %s" % dom
           server.xend_domain_unpause( int( dom ) )
        
    
    
        

