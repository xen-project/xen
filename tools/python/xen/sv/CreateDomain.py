from xen.sv.Wizard import *
from xen.sv.util import *
from xen.sv.GenTabbed import PreTab

from xen.xm.create import make_config

from xen.xend.XendClient import server

class CreateDomain( Wizard ):
    def __init__( self, urlWriter ):
    	
    	sheets = [ CreatePage0,
          	   CreatePage1,
          	   CreatePage2,
                   CreatePage3,
                   CreatePage4,
                   CreateFinish ]
    
    	Wizard.__init__( self, urlWriter, "Create Domain Wizard", sheets )
       
class CreatePage0( Sheet ):

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "General", 0 )
        self.addControl( InputControl( 'name', 'VM Name', 'VM Name:' ) )
        self.addControl( InputControl( 'memory', '64', 'Memory (Mb):' ) )
        self.addControl( InputControl( 'cpu', '0', 'CPU:' ) )
                        
class CreatePage1( Sheet ):

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Setup Kernel Image", 1 )
        self.addControl( InputControl( 'builder', 'linux', 'Kernel Type:' ) )
        self.addControl( InputControl( 'kernel', '/boot/vmlinuz-2.4.26-xenU', 'Kernel Image:' ) )
        self.addControl( InputControl( 'extra', '', 'Kernel Command Line Parame:' ) )

class CreatePage2( Sheet ):

    def __init__( self, urlWriter ):
    	Sheet.__init__( self, urlWriter, "Setup Virtual Block Device", 2 )
        self.addControl( InputControl( 'num_vbds', '1', 'Number of VBDs:' ) )

class CreatePage3( Sheet ):

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Setup Virtual Block Device", 3 )
        
    def write_BODY( self, request ):
    	previous_values = sxp2hash( string2sxp( self.passback ) ) #get the hash for quick reference
        num_vbds = previous_values.get( 'num_vbds' )
        
        for i in range( int( num_vbds ) ):
            self.addControl( InputControl( 'vbd%s_dom0' % i, '/dev/sda%i' % i, 'Device %s name:' % i  ) )
            self.addControl( InputControl( 'vbd%s_domU' % i, '/dev/sda%i' % i, 'Virtualized device %s:' % i ) )
            self.addControl( InputControl( 'vbd%s_mode' % i, 'w', 'Device %s mode:' % i ) )
            
        self.addControl( InputControl( 'root', '/dev/sda1', 'Root device (in VM):' ) )
        
        Sheet.write_BODY( self, request )
                
class CreatePage4( Sheet ):

    def __init__( self, urlWriter ):        
        Sheet.__init__( self, urlWriter, "Network settings", 4 )  
        self.addControl( InputControl( 'hostname', 'hostname', 'VM Hostname:' ) )
        self.addControl( InputControl( 'ip_addr', '1.2.3.4', 'VM IP Address:' ) )
        self.addControl( InputControl( 'ip_subnet', '255.255.255.0', 'VM Subnet Mask:' ) ) 
        self.addControl( InputControl( 'ip_gateway', '1.2.3.4', 'VM Gateway:' ) )           
         
class CreateFinish( Sheet ):

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "All Done", 5 )
        
    def write_BODY( self, request ):
    	fin_sxp = string2sxp( self.passback )
    
        xend_sxp = self.translate_sxp( fin_sxp )
        
        pt = PreTab( sxp2prettystring( xend_sxp ) )
        pt.write_BODY( request )
        
        server.xend_domain_create( xend_sxp )
       
        request.write( "<input type='hidden' name='passback' value=\"%s\"></p>" % self.passback )
        request.write( "<input type='hidden' name='sheet' value='%s'></p>" % self.location )
    
    def translate_sxp( self, fin_sxp ):
   	fin_hash = ssxp2hash( fin_sxp )
    
    	vals = OptVals()
        
        setattr(vals, "name", 	fin_hash.get( 'name' ) )
        setattr(vals, "memory", fin_hash.get( 'memory' ) )
        setattr(vals, "cpu", 	fin_hash.get( 'cpu' ) )
        
        setattr(vals, "builder", 	fin_hash.get( 'builder' ) )        
        setattr(vals, "kernel", 	fin_hash.get( 'kernel' ) )
	setattr(vals, "root", 		fin_hash.get( 'root' ) )
        setattr(vals, "extra", 		fin_hash.get( 'extra' ) ) 
        
        vbds = []
        
        for i in range( int( fin_hash.get( 'num_vbds' ) ) ):
            vbds.append( ( fin_hash.get('vbd%s_domU' % i ), fin_hash.get( 'vbd%s_dom0' % i ), fin_hash.get( 'vbd%s_mode' % i ) ) )
        
        vals.disk = vbds    
            
        vals.pci = []
        
        vals.vif = []
        vals.nics = 1
        
        vals.blkif = None
        vals.netif = None
        vals.restart = None
        vals.console = None
        vals.ramdisk = None
        
        #todo: setup ip addr stuff
        
        vals.cmdline_ip = None
        
        return make_config( vals )

        
class OptVals:
    """Class to hold option values.
    """
    pass