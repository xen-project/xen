from xen.xend.XendClient import server

from xen.sv.util import *
from xen.sv.GenTabbed import *

class NodeInfo( GenTabbed ):

    def __init__( self, urlWriter ):
    
        GenTabbed.__init__( self, "Node Details", urlWriter, [ 'General', 'Dmesg', ], [ NodeGeneralTab, NodeDmesgTab ] )
    
    def write_MENU( self, request ):
        request.write( "<p class='small'><a href='%s'>Node details</a></p>" % self.urlWriter( '' ) )

class NodeGeneralTab( CompositeTab ):
    def __init__( self ):
    	CompositeTab.__init__( self, [ NodeInfoTab, NodeActionTab ] )        
        
class NodeInfoTab( GeneralTab ):
                        
    def __init__( self ):
         
    	nodeInfo = {}
        try:
            nodeInfo = sxp2hash( server.xend_node() )
   	except:
            nodeInfo[ 'system' ] = 'Error getting node info'
             
        dictTitles = {}
        dictTitles[ 'System' ] = 'system'
        dictTitles[ 'Hostname' ] = 'host' 
        dictTitles[ 'Release' ] = 'release' 
        dictTitles[ 'Version' ] ='version' 
        dictTitles[ 'Machine' ] = 'machine' 
        dictTitles[ 'Cores' ] = 'cores' 
        dictTitles[ 'Hyperthreading' ] = ( 'hyperthreads_per_core', hyperthreadFormatter )
        dictTitles[ 'CPU Speed' ] = ( 'cpu_mhz', cpuFormatter )
        dictTitles[ 'Memory' ] = ( 'memory', memoryFormatter )
        dictTitles[ 'Free Memory' ] = ( 'free_memory', memoryFormatter )
        
        GeneralTab.__init__( self, dict=nodeInfo, titles=dictTitles )

class NodeDmesgTab( PreTab ):

    def __init__( self ):
    	try:
            dmesg = server.xend_node_get_dmesg()
        except:
            dmesg = "Error getting node information: XenD not running?"
        PreTab.__init__( self, dmesg )
  
class NodeActionTab( ActionTab ):

    def __init__( self ):
        ActionTab.__init__( self, { "shutdown" : ( "Shutdown the Node", "shutdown.png" ),
        	"reboot" : ( "Reboot the Node", "reboot.png" ) } )    
        
    def op_shutdown( self, request ):
    	print ">NodeShutDown"
    	server.xend_node_shutdown()
    
    def op_reboot( self, request ):
    	print ">NodeReboot"
        server.xend_node_reboot()
