from xen.sv.HTMLBase import HTMLBase
from xen.sv.DomList  import DomList
from xen.sv.NodeInfo import NodeInfo
from xen.sv.DomInfo  import DomInfo

class Main( HTMLBase ):
    
    isLeaf = True

    def __init__( self, urlWriter = None ):
        self.modules = { "node": ( "Node details", NodeInfo ), 
                         "list": ( "Domain summary", DomList ), 
                         "info": ( "Domain info", DomInfo ) }
        HTMLBase.__init__(self)
        
    def render_POST( self, request ):
    
    	#decide what module post'd the action

        mod = request.args.get('mod')
                
        if not mod is None and len(mod) == 1:
            modTup = self.modules[ mod[0] ]
            #check module exists
            if modTup:
               (modName, module) = modTup
               module( self.mainUrlWriter ).perform( request )     
    
        return self.render_GET( request )

    def mainUrlWriter( self, s ):
        return "Main.rpy?%s" % s

    def write_BODY( self, request ):
    
        request.write( "\n<table style='border:0px solid black; background: url(images/orb_01.jpg) no-repeat' cellspacing='0' cellpadding='0' border='0' width='780px' height='536px'>\n" )
        request.write( "<tr>\n" )
        request.write( " <td width='15px'>&nbsp;</td>" )
        request.write( " <td width='175px' align='center' valign'center'>" )
        request.write( "  <table cellspacing='0' cellpadding='0' border='0' width='100%' height='100%'>" )
        request.write( "   <tr><td height='200px' align='center' valign='center'><a href='http://www.cl.cam.ac.uk/Research/SRG/netos/xen/'>" )
        request.write( "   <img src='images/xen.png' width='150' height='75' border='0'/></a></td></tr>" )
        request.write( "   <tr><td align='center' valign='top'>" )
        
        for (modName, (modTitle, module)) in self.modules.items():
            request.write( "    <p class='small'><a href='Main.rpy?mod=%s'>%s</a></p>" % (modName, modTitle))
    
        DomList( self.mainUrlWriter ).write_BODY( request, True, False )

        request.write( "   </td></tr>" )
        request.write( "  </table>" )
        request.write( " &nbsp;" )
        request.write( " </td>\n" )
        request.write( " <td width='15px'>&nbsp;</td>" )
        request.write( " <td width='558px' align='left' valign='top'>" )
        request.write( "  <table cellspacing='0' cellpadding='0' border='0' width='100%' height='100%'>" )
        request.write( "   <tr><td height='20px'></td></tr>" )
        request.write( "   <tr><td align='center' valign='top'>" )
        
        mod = request.args.get('mod')
        
        if mod is None or len(mod) != 1:
            request.write( '<p>Please select a module</p>' )
        else:
            modTup = self.modules[ mod[0] ]
            if modTup:
               (modName, module) = modTup
               module( self.mainUrlWriter ).write_BODY( request )  
            else:
               request.write( '<p>Invalid module. Please select another</p>' )
    
        request.write( "   </td></tr>" )
        request.write( "  </table>" )
        request.write( " </td>\n" )
        request.write( " <td width='17px'>&nbsp;</td>" )
        request.write( "</tr>\n" )
        
        request.write( "</table>\n" )
        
