from xen.xend.XendClient import getAsynchServer
server = getAsynchServer()
from xen.xend import PrettyPrint

from xen.sv.HTMLBase import HTMLBase
from xen.sv.util import *
from xen.sv.GenTabbed import *

DEBUG=1

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

        try:
            domInfo = server.xend_domain( self.dom )
        except:
            domInfo = [["Error getting domain details."]]
            
        self.source = sxp2prettystring( domInfo )
        
        PreTab.write_BODY( self, request )
        
class DomActionTab( ActionTab ):

    def __init__( self ):
    	actions = { "shutdown" : ( "Shutdown the Domain", "shutdown.png" ),
        	    "reboot" : ( "Reboot the Domain", "reboot.png" ),
                    "pause" : ( "Pause the Domain", "pause.png" ),
                    "unpause" : ( "Unpause the Domain", "unpause.png" ),
                    "destroy" : ( "Destroy the Domain", "destroy.png" ) }
        ActionTab.__init__( self, actions )    
        
    def op_shutdown( self, request ):
   	dom = getVar( 'dom', request )
        if not dom is None and dom != '0':
    	   if DEBUG: print ">DomShutDown %s" % dom
           try:
    	   	server.xend_domain_shutdown( int( dom ), "halt" )
           except:
           	pass
    
    def op_reboot( self, request ):
       	dom = getVar( 'dom', request )
        if not dom is None and dom != '0':
    	    if DEBUG: print ">DomReboot %s" % dom
            try:
            	server.xend_domain_shutdown( int( dom ), "reboot" )
            except:
            	pass
                
    def op_pause( self, request ):
       	dom = getVar( 'dom', request )
        if not dom is None and dom != '0':
    	    if DEBUG: print ">DomPause %s" % dom
            try:
                server.xend_domain_pause( int( dom ) )
            except:
            	pass
               
    def op_unpause( self, request ):
       	dom = getVar( 'dom', request )
        if not dom is None and dom != '0':
    	   if DEBUG: print ">DomUnpause %s" % dom
           try:
               server.xend_domain_unpause( int( dom ) )
    	   except:
               pass
               
    def op_destroy( self, request ):
    	dom = getVar( 'dom', request )
        if not dom is None and dom != '0':
    	   if DEBUG: print ">DomDestroy %s" % dom
           try:
           	server.xend_domain_destroy( int( dom ), "halt" )
           except:
           	pass
        
    
    
        

