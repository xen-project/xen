from xen.xend.XendClient import server

from xen.sv.util import *
from xen.sv.GenTabbed import *

class NodeInfo( GenTabbed ):

    def __init__( self, urlWriter ):
    
        def newUrlWriter( url ):
            return urlWriter( "mod=node%s" % url )
    
        GenTabbed.__init__( self, newUrlWriter, [ 'General', 'Dmesg' ], [ NodeGenTab, NodeDmesgTab ] )

class NodeGenTab( PreTab ):
    def __init__( self ):
       text = sxp2string( server.xend_node() )
       PreTab.__init__( self, text )            
    
class NodeGeneralTab( GeneralTab ):
                        
    def __init__( self ):
         
        nodeInfo = server.xend_node()
        
        dictNodeInfo = {}
        
        for l in nodeInfo:
            dictNodeInfo[ l[0] ] = l[1]
            
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
        
        GeneralTab.__init__( self, title="General Node Info", dict=dictNodeInfo, titles=dictTitles )

class NodeDmesgTab( PreTab ):

    def __init__( self ):
        dmesg = server.xend_node_dmesg()
        PreTab.__init__( self, dmesg[ 1 ] )
    
