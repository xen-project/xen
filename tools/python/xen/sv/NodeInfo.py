from xen.xend import XendDmesg
from xen.xend import XendNode

from xen.sv.util import *
from xen.sv.GenTabbed import *
from xen.sv.HTMLBase  import HTMLBase

class NodeInfo( GenTabbed ):

    def __init__( self, urlWriter, callback ):
    
        def newUrlWriter( url ):
            return urlWriter( "mod=node%s" % url )
    
        GenTabbed.__init__( self, newUrlWriter, [ 'General', 'Dmesg' ], [ NodeGeneralTab, NodeDmesgTab ], callback )

class NodeGeneralTab( GeneralTab ):
                        
    def __init__( self ):
         
        nodeInfo = XendNode.instance().info()
        
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
        self.xd = XendDmesg.instance()
        PreTab.__init__( self, self.xd.info()[0] )
    
