from xen.sv.HTMLBase import HTMLBase
from xen.sv import DomList, NodeInfo, DomInfo

class Main( HTMLBase ):
    
    isLeaf = True

    def __init__( self ):
        HTMLBase.__init__(self)
        
    def render_POST( self, request ):
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
        
        request.write( "    <p class='small'><a href='Main.rpy?mod=node'>Node details</a></p>" )
        request.write( "    <p class='small'><a href='Main.rpy?mod=list'>Domains summary</a></p>" )
    
        DomList.DomList( self.mainUrlWriter ).write_BODY( request, True, False )

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
        elif mod[0] == 'info':
            DomInfo.DomInfo( self.mainUrlWriter ).write_BODY( request )
        elif mod[0] == 'list':
            DomList.DomList( self.mainUrlWriter ).write_BODY( request )
        elif mod[0] == 'node':
            NodeInfo.NodeInfo( self.mainUrlWriter ).write_BODY( request )
        else:
            request.write( '<p>Invalid module. Please select another</p>' )
    
        request.write( "   </td></tr>" )
        request.write( "  </table>" )
        request.write( " </td>\n" )
        request.write( " <td width='17px'>&nbsp;</td>" )
        request.write( "</tr>\n" )
        
        request.write( "</table>\n" )
        
