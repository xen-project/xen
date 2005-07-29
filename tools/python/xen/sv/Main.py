from xen.sv.HTMLBase import HTMLBase
from xen.sv.DomList  import DomList
from xen.sv.NodeInfo import NodeInfo
from xen.sv.DomInfo  import DomInfo
from xen.sv.CreateDomain import CreateDomain
from xen.sv.MigrateDomain import MigrateDomain
from xen.sv.SaveDomain import SaveDomain
from xen.sv.RestoreDomain import RestoreDomain

from xen.xend.XendClient import server

from xen.sv.util import getVar

class Main( HTMLBase ):
    
    isLeaf = True

    def __init__( self, urlWriter = None ):
        self.modules = { "node": NodeInfo, 
                         "list": DomList, 
                         "info": DomInfo,
                         "create": CreateDomain,
                         "migrate" : MigrateDomain,
                         "save" : SaveDomain,
                         "restore" : RestoreDomain }

        # ordered list of module menus to display
        self.module_menus = [ "node", "create", "migrate", "save",
                              "restore", "list" ]
        HTMLBase.__init__(self)
        
    def render_POST( self, request ):
    
    	#decide what module post'd the action
                
    	args = getVar( 'args', request )

        mod = getVar( 'mod', request )
                
        if not mod is None and args is None:
            module = self.modules[ mod ]
            #check module exists
            if module:
               module( self.mainUrlWriter ).perform( request )
        else:
            self.perform( request )     
    
        return self.render_GET( request )

    def mainUrlWriter( self, module ):
    	def fun( f ):
            return "Main.rpy?mod=%s%s" % ( module, f )
        return fun    
        
    def write_BODY( self, request ):
    
        request.write( "\n<table style='border:0px solid black; background: url(images/orb_01.jpg) no-repeat' cellspacing='0' cellpadding='0' border='0' width='780px' height='536px'>\n" )
        request.write( "<tr>\n" )
        request.write( " <td width='15px'>&nbsp;</td>" )
        request.write( " <td width='175px' align='center' valign'center'>" )
        request.write( "  <table cellspacing='0' cellpadding='0' border='0' width='100%' height='100%'>" )
        request.write( "   <tr><td height='140px' align='center' valign='bottom'><a href='http://www.cl.cam.ac.uk/Research/SRG/netos/xen/'>" )
        request.write( "   <img src='images/xen.png' width='150' height='75' border='0'/></a><br/></td></tr>" )
        request.write( "   <tr><td height='60px' align='center'><p class='small'>SV Web Interface<br/>(C) <a href='mailto:tw275@cam.ac.uk'>Tom Wilkie</a> 2004</p></td></tr>")
        request.write( "   <tr><td align='center' valign='top'>" )

        for modName in self.module_menus:
            self.modules[modName]( self.mainUrlWriter( modName ) ).write_MENU( request )
        
        request.write( "   </td></tr>" )
        request.write( "  </table>" )
        request.write( " &nbsp;" )
        request.write( " </td>\n" )
        request.write( " <td width='15px'>&nbsp;</td>" )
        request.write( " <td width='558px' align='left' valign='top'>" )
        request.write( "  <table cellspacing='0' cellpadding='0' border='0' width='100%' height='100%'>" )
        request.write( "   <tr><td height='20px'></td></tr>" )
        request.write( "   <tr><td align='center' valign='top'>" )
        
        modName = getVar('mod', request)
        
        if modName is None:
            request.write( '<p>Please select a module</p>' )
        else:
            module = self.modules[ modName ]
            if module:
               module( self.mainUrlWriter( modName ) ).write_BODY( request )  
            else:
               request.write( '<p>Invalid module. Please select another</p>' )
    
        request.write( "   </td></tr>" )
        request.write( "  </table>" )
        request.write( " </td>\n" )
        request.write( " <td width='17px'>&nbsp;</td>" )
        request.write( "</tr>\n" )
        
        request.write( "</table>\n" )
        
                
    def op_destroy( self, request ):
    	dom = getVar( 'dom', request )
        if not dom is None and dom != "0":
            server.xend_domain_destroy( int( dom ), "halt" ) 
                 
    def op_pause( self, request ):
    	dom = getVar( 'dom', request )
        if not dom is None and dom != "0":
            server.xend_domain_pause( int( dom ) )      
    
    def op_unpause( self, request ):
    	dom = getVar( 'dom', request )
        if not dom is None and dom != "0":
            server.xend_domain_unpause( int( dom ) )      
