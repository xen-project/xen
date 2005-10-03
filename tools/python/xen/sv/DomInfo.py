from xen.xend.XendClient import server
from xen.xend import PrettyPrint

from xen.sv.HTMLBase import HTMLBase
from xen.sv.util import *
from xen.sv.GenTabbed import *
from xen.sv.Wizard import *

DEBUG=1

class DomInfo( GenTabbed ):

    def __init__( self, urlWriter ):
        
        self.dom = 0;
                   
        GenTabbed.__init__( self, "Domain Info", urlWriter, [ 'General', 'SXP', 'Devices', 'Migrate', 'Save' ], [ DomGeneralTab, DomSXPTab, DomDeviceTab, DomMigrateTab, DomSaveTab ]  )

    def write_BODY( self, request ):
        try:
            dom = int( getVar( 'dom', request ) )
        except:
            request.write( "<p>Please Select a Domain</p>" )
            return None
       
        GenTabbed.write_BODY( self, request )
        
    def write_MENU( self, request ):
       domains = []

       try:
           domains = server.xend_domains()
           domains.sort()
       except:
           pass

       request.write( "\n<table style='border:0px solid white' cellspacing='0' cellpadding='0' border='0' width='100%'>\n" )
       request.write( "<tr class='domainInfoHead'>" )
       request.write( "<td class='domainInfoHead' align='center'>Domain</td>\n" )
       request.write( "<td class='domainInfoHead' align='center'>Name</td>\n" )
       request.write( "<td class='domainInfoHead' align='center'>State</td>\n" )
       request.write( "<td class='domainInfoHead' align='center'></td>\n" )
       request.write( "</tr>" )

       odd = True
       if not domains is None:
           for domain in domains:
               odd = not odd;
               if odd:
                   request.write( "<tr class='domainInfoOdd'>\n" )
               else:
                   request.write( "<tr class='domainInfoEven'>\n" )
               domInfo = getDomInfo( domain )
               request.write( "<td class='domainInfo' align='center'>%(id)s</td>\n" % domInfo )
               url = self.urlWriter( "&dom=%(id)s" % domInfo )
               request.write( "<td class='domainInfo' align='center'><a href='%s'>%s</a></td>\n" % ( url, domInfo['name'] ) )
               request.write( "<td class='domainInfo' align='center'>%(state)5s</td>\n" % domInfo )
               if domInfo[ 'id' ] != "0":
                   request.write( "<td class='domainInfo' align='center'>" )
                   if domInfo[ 'state' ][ 2 ] == "-":
                       request.write( "<img src='images/small-pause.png' onclick='doOp2( \"pause\", \"%(dom)-4s\" )'>" % domInfo )
                   else:
                       request.write( "<img src='images/small-unpause.png' onclick='doOp2( \"unpause\", \"%(dom)-4s\" )'>" % domInfo )
                   request.write( "<img src='images/small-destroy.png' onclick='doOp2( \"destroy\", \"%(dom)-4s\" )'></td>" % domInfo )
               else:
                   request.write( "<td>&nbsp;</td>" )
               request.write( "</tr>\n" )
       else:
           request.write( "<tr colspan='10'><p class='small'>Error getting domain list<br/>Perhaps XenD not running?</p></tr>")
       request.write( "</table>" )
       
class DomGeneralTab( CompositeTab ):
    def __init__( self, urlWriter ):
       CompositeTab.__init__( self, [ DomGenTab, DomActionTab ], urlWriter )        
       
class DomGenTab( GeneralTab ):

    def __init__( self, _ ):
    
        titles = {}
    
        titles[ 'ID' ] = 'dom'      
        titles[ 'Name' ] = 'name'
        titles[ 'CPU' ] = 'cpu'
        titles[ 'Memory' ] = ( 'mem', memoryFormatter )
        titles[ 'State' ] = ( 'state', stateFormatter )
        titles[ 'Total CPU' ] = ( 'cpu_time', smallTimeFormatter )
        titles[ 'Up Time' ] = ( 'up_time', bigTimeFormatter )
    
        GeneralTab.__init__( self, {}, titles )
        
    def write_BODY( self, request ):
    
        self.dom = getVar('dom', request)
        
        if self.dom is None:
            request.write( "<p>Please Select a Domain</p>" )
            return None
            
        self.dict = getDomInfo( self.dom )
        
        GeneralTab.write_BODY( self, request )
            
class DomSXPTab( PreTab ):

    def __init__( self, _ ):
        self.dom = 0
        PreTab.__init__( self, "" )


    def write_BODY( self, request ):
        self.dom = getVar('dom', request)
        
        if self.dom is None:
            request.write( "<p>Please Select a Domain</p>" )
            return None

        try:
            domInfo = server.xend_domain( self.dom )
        except:
            domInfo = [["Error getting domain details."]]
            
        self.source = sxp2prettystring( domInfo )
        
        PreTab.write_BODY( self, request )
       
class DomActionTab( ActionTab ):

    def __init__( self, _ ):
    	actions = { "shutdown" : "Shutdown",
        	    "reboot" : "Reboot",
                    "pause" : "Pause",
                    "unpause" : "Unpause",
                    "destroy" : "Destroy" }
        ActionTab.__init__( self, actions )    
        
    def op_shutdown( self, request ):
   	dom = getVar( 'dom', request )
        if not dom is None and dom != '0':
    	   if DEBUG: print ">DomShutDown %s" % dom
           try:
    	   	server.xend_domain_shutdown( int( dom ), "poweroff" )
           except:
           	pass
    
    def op_reboot( self, request ):
       	dom = getVar( 'dom', request )
        if not dom is None and dom != '0':
    	    if DEBUG: print ">DomReboot %s" % dom
            try:
            	server.xend_domain_shutdown( int( dom ), "reboot" )
            except:
            	pass
                
    def op_pause( self, request ):
       	dom = getVar( 'dom', request )
        if not dom is None and dom != '0':
    	    if DEBUG: print ">DomPause %s" % dom
            try:
                server.xend_domain_pause( int( dom ) )
            except:
            	pass
               
    def op_unpause( self, request ):
       	dom = getVar( 'dom', request )
        if not dom is None and dom != '0':
    	   if DEBUG: print ">DomUnpause %s" % dom
           try:
               server.xend_domain_unpause( int( dom ) )
    	   except:
               pass
               
    def op_destroy( self, request ):
    	dom = getVar( 'dom', request )
        if not dom is None and dom != '0':
    	   if DEBUG: print ">DomDestroy %s" % dom
           try:
           	server.xend_domain_destroy(int( dom ))
           except:
           	pass

class DomDeviceTab( CompositeTab ):

    def __init__( self, urlWriter ):
        CompositeTab.__init__( self, [ DomDeviceListTab, DomDeviceOptionsTab, DomDeviceActionTab ], urlWriter )

class DomDeviceListTab( NullTab ):

    title = "Device List"

    def __init__( self, _ ):
        pass

class DomDeviceOptionsTab( NullTab ):

    title = "Device Options"

    def __init__( self, _ ):
        pass

class DomDeviceActionTab( ActionTab ):

    def __init__( self, _ ):
        ActionTab.__init__( self, { "addvcpu" : "Add VCPU", "addvbd" : "Add VBD", "addvif" : "Add VIF" } )

class DomMigrateTab( CompositeTab ):

    def __init__( self, urlWriter ):
        CompositeTab.__init__( self, [ DomMigrateExtraTab, DomMigrateActionTab ], urlWriter ) 

class DomMigrateExtraTab( Sheet ):

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Configure Migration", 0)
        self.addControl( TickControl('live', 'True', 'Live migrate:') )
        self.addControl( InputControl('rate', '0', 'Rate limit:') )
        self.addControl( InputControl( 'dest', 'host.domain', 'Name or IP address:', ".*") )
                                                                                                            
class DomMigrateActionTab( ActionTab ):

    def __init__( self, _ ):
        actions = { "migrate" : "Migrate" }
        ActionTab.__init__( self, actions )
                
    def op_migrate( self, request ):
        try:
            domid = int( getVar( 'dom', request ) )
            live  = getVar( 'live', request )
            rate  = getVar( 'rate', request )
            dest  = getVar( 'dest', request )
            dom_sxp = server.xend_domain_migrate( domid, dest, live == 'True', rate )
            success = "Your domain was successfully Migrated.\n"
        except Exception, e:
            success = "There was an error migrating your domain\n"
            dom_sxp = str(e)
                                                        
class DomSaveTab( CompositeTab ):

    def __init__( self, urlWriter ):
        CompositeTab.__init__( self, [ DomSaveExtraTab, DomSaveActionTab ], urlWriter ) 

class DomSaveExtraTab( Sheet ):

    title = "Save location"

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Save Domain to file", 0 )
        self.addControl( InputControl( 'file', '', 'Suspend file name:', ".*") )
               
class DomSaveActionTab( ActionTab ):

    def __init__( self, _ ):
        actions = { "save" : "Save" }
        ActionTab.__init__( self, actions )

    def op_save( self, request ):

        try:
            dom_sxp = server.xend_domain_save( config['domid'], config['file'] )
            success = "Your domain was successfully saved.\n"
        except Exception, e:
            success = "There was an error saving your domain\n"
            dom_sxp = str(e)
                                                                                       
        try:
            dom = int( getVar( 'dom', request ) )
        except:
            pass
