
from xen.sv.NodeInfo import NodeInfo
from xen.sv.DomInfo  import DomInfo
from xen.sv.CreateDomain import CreateDomain
from xen.sv.RestoreDomain import RestoreDomain

from xen.sv.util import getVar

# adapter to make this all work with mod_python
# as opposed to Twisted
# (c) Tom Wilkie 2005

class Args:
    def __init__( self, req ):
        from mod_python.util import FieldStorage
        self.fieldStorage = FieldStorage( req, True )

    # return a list of values for the given key,
    # or None if key not there
    def get( self, var ):
        retVar = self.fieldStorage.getlist( var )
        if len( retVar ) == 0:
            return None
        else:
            return retVar

    # return a list of tuples,
    # (key, value) where value is a list of values
    def items( self ):
        result = [];
        for key in self.fieldStorage.keys():
            result.append( (key, self.fieldStorage.getlist( key ) ) )
        return result
                                                                                                                                                            
# This is the Main class
# It pieces together all the modules

class Main:
    def __init__( self ):
        self.modules = { "node": NodeInfo, 
                         "create": CreateDomain,
                         "restore" : RestoreDomain,
                         "info": DomInfo }

        self.init_done = False

    def init_modules( self, request ):
        for moduleName, module in self.modules.iteritems():
            self.modules[ moduleName ] = module( self.urlWriter( moduleName, request.url ) )             

    def render_menu( self, request ):
        if not self.init_done:
            self.init_modules( request )
            self.init_done = True
            
        for _, module in self.modules.iteritems():
            module.write_MENU( request )
            request.write( "\n" )

    def render_main( self, request ):
        if not self.init_done:
            self.init_modules( request )
            self.init_done = True
                                   
        moduleName = getVar('mod', request)
        if moduleName not in self.modules:
            request.write( '<p>Please select a module</p>' )
        else:
            module = self.modules[ moduleName ]
            module.write_BODY( request )

    def do_POST( self, request ): 
        if not self.init_done:
            self.init_modules( request )
            self.init_done = True                       
        
    	moduleName = getVar( 'mod', request )      
        if moduleName in self.modules:
            self.modules[ moduleName ].perform( request )

    def urlWriter( self, module, url ):
        return lambda x: "%s?mod=%s%s" % ( url, module, x )
