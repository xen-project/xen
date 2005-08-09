from xen.xend.XendClient import server

from xen.sv.util import *
from xen.sv.GenTabbed import *

class NodeInfo( GenTabbed ):

    def __init__( self, urlWriter ):  
        GenTabbed.__init__( self, "Node Details", urlWriter, [ 'General', 'Dmesg', 'SXP' ], [ NodeGeneralTab, NodeDmesgTab, NodeSXPTab ] )
    
    def write_MENU( self, request ):
        request.write( "<p class='small'><a href='%s'>Node details</a></p>" % self.urlWriter( '' ) )

class NodeGeneralTab( CompositeTab ):
    def __init__( self, urlWriter ):
    	CompositeTab.__init__( self, [ NodeInfoTab, NodeActionTab ], urlWriter )        
        
class NodeInfoTab( GeneralTab ):
                        
    def __init__( self, urlWriter ):
         
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

    def __init__( self, urlWriter ):
    	try:
            dmesg = server.xend_node_get_dmesg()
        except:
            dmesg = "Error getting node information: XenD not running?"
        PreTab.__init__( self, dmesg )
  
class NodeActionTab( ActionTab ):

    def __init__( self, urlWriter ):
        ActionTab.__init__( self, { "shutdown" : "shutdown",
        	"reboot" : "reboot" } )    
        
    def op_shutdown( self, request ):
        if debug: print ">NodeShutDown"
    	server.xend_node_shutdown()
    
    def op_reboot( self, request ):
        if debug: print ">NodeReboot"
        server.xend_node_reboot()

class NodeSXPTab( PreTab ):

    def __init__( self, urlWriter ):
        try:
            nodeSXP = sxp2string( server.xend_node() )
        except:
            nodeSXP = 'Error getting node sxp'

        PreTab.__init__( self, nodeSXP )
