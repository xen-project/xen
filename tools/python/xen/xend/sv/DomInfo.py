from HTMLBase import HTMLBase
from XendClientDeferred import server
from xen.xend import PrettyPrint

from xen.xend.sv.util import *
from xen.xend.sv.GenTabbed import *

class DomInfo( GenTabbed ):

    def __init__( self, urlWriter, callback ):
        
        self.dom = 0;
    
        def tabUrlWriter( tab ):
            return urlWriter( "mod=info&dom=%s%s" % ( self.dom, tab ) )
        
        GenTabbed.__init__( self, tabUrlWriter, [ 'General', 'SXP', 'Devices' ], [ DomGenTab, DomSXPTab, NullTab ], callback  )

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
        
    def write_BODY( self, request, callback ):
        dom = request.args.get('dom')
        
        if dom is None or len(dom) != 1:
            request.write( "<p>Please Select a Domain</p>" )
            return None
        else:
            self.dom = dom[0]
            
        deferred = getDomInfoHash( self.dom )
        deferred.addCallback( self.continue_BODY, request, callback )

    def continue_BODY( self, dict, request, callback ):

        self.dict = dict
        
        GeneralTab.write_BODY( self, request, callback )
            
class DomSXPTab( PreTab ):

    def __init__( self ):
        self.dom = 0
        PreTab.__init__( self, "" )

    def fn( self, x, request ):
        class tmp:
            def __init__( self ):
                self.str = ""
            def write( self, str ):
                self.str = self.str + str
        temp = tmp()
        PrettyPrint.prettyprint( x, out=temp )
        self.source = temp.str
        return request
        
    def fn2( self, request, callback ):
        PreTab.write_BODY( self, request, callback )
        
    def write_BODY( self, request, callback ):
        dom = request.args.get('dom')
        
        if dom is None or len(dom) != 1:
            request.write( "<p>Please Select a Domain</p>" )
            return None
        else:
            self.dom = dom[0]
            
        deferred = server.xend_domain( self.dom )
        
        deferred.addCallback( self.fn, request )
        deferred.addCallback( self.fn2, callback )
        def errback( x ):
            print ">err ", x
        deferred.addErrback( errback )