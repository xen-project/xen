from xen.sv.Wizard import *
from xen.sv.util import *

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
        self.addControl( InputControl( 'vm_name', 'VM Name', 'VM Name:' ) )
        self.addControl( InputControl( 'memory', '64', 'Memory (Mb):' ) )
                        
class CreatePage1( Sheet ):

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Setup Kernel Image", 1 )
        self.addControl( InputControl( 'kernel_image', '/boot/vmlinuz-2.4.26-xenU', 'Kernel Image:' ) )
        self.addControl( InputControl( 'kernel_params', '', 'Kernel Command Line Parame:' ) )

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
            
        self.addControl( InputControl( 'root_dev', '/dev/sda1', 'Root device (in VM):' ) )
        
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
    	request.write( "<pre>%s</pre>" % sxp2prettystring( string2sxp( self.passback ) ) )
        request.write( "<input type='hidden' name='passback' value=\"%s\"></p>" % self.passback )
        request.write( "<input type='hidden' name='sheet' value='%s'></p>" % self.location )
