from xen.xend.XendClient import server
from xen.xend import sxp

from xen.sv.HTMLBase import HTMLBase
from xen.sv.util import *

class DomList( HTMLBase ):
    
    isLeaf = True

    def __init__( self, urlWriter ):
        HTMLBase.__init__(self)
        self.urlWriter = urlWriter
        
    def write_MENU( self, request ):
    	return self.write_BODY( request, head=True, long=False ) 

    def write_BODY( self, request, head=True, long=True ):
        
    	domains = None
    
    	try:
        	domains = server.xend_domains()
        	domains.sort()
  	except:
        	pass
                
        request.write( "\n<table style='border:0px solid white' cellspacing='0' cellpadding='0' border='0' width='100%'>\n" )
        
        if head:
            request.write( "<tr class='domainInfoHead'>" )
            self.write_DOMAIN_HEAD( request, long )
            request.write( "</tr>" )
        
        odd = True
        
        if not domains is None:
            for domain in domains:
                if odd:
                    request.write( "<tr class='domainInfoOdd'>\n" )
                    odd = False
                else:
                    request.write( "<tr class='domainInfoEven'>\n" )
                    odd = True
                self.write_DOMAIN( request, getDomInfoHash( domain ), long )
                request.write( "</tr>\n" )
        else:
        	request.write( "<tr colspan='10'><p class='small'>Error getting domain list<br/>Perhaps XenD not running?</p></tr>")
                
        request.write( "</table>\n" )
            
    def write_DOMAIN( self, request, domInfoHash, long=True ):   
        request.write( "<td class='domainInfo' align='center'>%(id)s</td>\n" % domInfoHash )

        url = self.urlWriter( "&mod=info&dom=%(id)s" % domInfoHash )

        request.write( "<td class='domainInfo' align='center'><a href='%s'>%s</a></td>\n" % ( url, domInfoHash['name'] ) )
        if long: 
            request.write( "<td class='domainInfo' align='center'>%(memory)5s</td>\n" % domInfoHash )
            request.write( "<td class='domainInfo' align='center'>%(cpu)2s</td>\n" % domInfoHash )
        request.write( "<td class='domainInfo' align='center'>%(state)5s</td>\n" % domInfoHash )
        if domInfoHash[ 'id' ] != "0":
            request.write( "<td class='domainInfo' align='center'>" )
            
            if domInfoHash[ 'state' ][ 2 ] == "-":
                request.write( "<img src='images/small-pause.png' onclick='doOp2( \"pause\", \"%(dom)-4s\" )'>" % domInfoHash )
            else:
                request.write( "<img src='images/small-unpause.png' onclick='doOp2( \"unpause\", \"%(dom)-4s\" )'>" % domInfoHash )              
            
            request.write( "<img src='images/small-destroy.png' onclick='doOp2( \"destroy\", \"%(dom)-4s\" )'></td>" % domInfoHash)
        else:
            request.write( "<td>&nbsp;</td>" )

    def write_DOMAIN_HEAD( self, request, long=True ):
        request.write( "<td class='domainInfoHead' align='center'>Domain</td>\n" )      
        request.write( "<td class='domainInfoHead' align='center'>Name</td>\n" )      
        if long:
            request.write( "<td class='domainInfoHead' align='center'>Memory / Mb</td>\n" )      
            request.write( "<td class='domainInfoHead' align='center'>CPU</td>\n" )      
        request.write( "<td class='domainInfoHead' align='center'>State</td>\n" )      
        request.write( "<td class='domainInfoHead' align='center'></td>\n" )
