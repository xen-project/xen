from xen.sv.Wizard import *
from xen.sv.util import *
from xen.sv.GenTabbed import PreTab

from xen.xm.create import make_config, OptVals

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
        self.addControl( InputControl( 'name', 'VM Name', 'VM Name:', "[\\w|\\S]+", "You must enter a name in this field" ) )
        self.addControl( InputControl( 'memory', '64', 'Memory (Mb):', "[\\d]+", "You must enter a number in this field" ) )
        self.addControl( InputControl( 'cpu', '0', 'CPU:', "[\\d]+", "You must enter a number in this feild" ) )
        self.addControl( InputControl( 'cpu_weight', '1', 'CPU Weight:', "[\\d]+", "You must enter a number in this feild" ) )
                        
class CreatePage1( Sheet ):

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Setup Kernel Image", 1 )
        self.addControl( ListControl( 'builder', [('linux', 'Linux'), ('netbsd', 'NetBSD')], 'Kernel Type:' ) )
        self.addControl( FileControl( 'kernel', '/boot/vmlinuz-2.6.9-xenU', 'Kernel Image:' ) )
        self.addControl( InputControl( 'extra', '', 'Kernel Command Line Parameters:' ) )

class CreatePage2( Sheet ):

    def __init__( self, urlWriter ):
    	Sheet.__init__( self, urlWriter, "Setup Virtual Block Device", 2 )
        self.addControl( InputControl( 'num_vbds', '1', 'Number of VBDs:', '[\\d]+', "You must enter a number in this field" ) )

class CreatePage3( Sheet ):

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Setup Virtual Block Device", 3 )
        
    def write_BODY( self, request, err ):
        if not self.passback: self.parseForm( request )
    
    	previous_values = sxp2hash( string2sxp( self.passback ) ) #get the hash for quick reference
        
        num_vbds = previous_values.get( 'num_vbds' )
        
        for i in range( int( num_vbds ) ):
            self.addControl( InputControl( 'vbd%s_dom0' % i, 'phy:sda%s' % str(i + 1), 'Device %s name:' % i  ) )
            self.addControl( InputControl( 'vbd%s_domU' % i, 'sda%s' % str(i + 1), 'Virtualized device %s:' % i ) )
            self.addControl( ListControl( 'vbd%s_mode' % i, [('w', 'Read + Write'), ('r', 'Read Only')], 'Device %s mode:' % i ) )
            
        self.addControl( InputControl( 'root', '/dev/sda1', 'Root device (in VM):' ) )
        
        Sheet.write_BODY( self, request, err )
                
class CreatePage4( Sheet ):

    def __init__( self, urlWriter ):        
        Sheet.__init__( self, urlWriter, "Network settings", 4 )
        self.addControl( ListControl( 'dhcp', [('off', 'No'), ('dhcp', 'Yes')], 'Use DHCP:' ) )
        self.addControl( InputControl( 'hostname', 'hostname', 'VM Hostname:' ) )
        self.addControl( InputControl( 'ip_addr', '1.2.3.4', 'VM IP Address:' ) )
        self.addControl( InputControl( 'ip_subnet', '255.255.255.0', 'VM Subnet Mask:' ) ) 
        self.addControl( InputControl( 'ip_gateway', '1.2.3.4', 'VM Gateway:' ) )           
        self.addControl( InputControl( 'ip_nfs', '1.2.3.4', 'NFS Server:' ) )  
                 
class CreateFinish( Sheet ):

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "All Done", 5 )
        
    def write_BODY( self, request, err ):
    
        if not self.passback: self.parseForm( request )
        
        xend_sxp = self.translate_sxp( string2sxp( self.passback ) )
        
        try:
            dom_sxp = server.xend_domain_create( xend_sxp )
            success = "Your domain was successfully created.\n"
        except:
            success = "There was an error creating your domain.\nThe configuration used is as follows:\n"
            dom_sxp = xend_sxp
            
            
        
        pt = PreTab( success + sxp2prettystring( dom_sxp ) )
        pt.write_BODY( request )

        request.write( "<input type='hidden' name='passback' value=\"%s\"></p>" % self.passback )
        request.write( "<input type='hidden' name='sheet' value='%s'></p>" % self.location )
    
    def translate_sxp( self, fin_sxp ):
   	fin_hash = ssxp2hash( fin_sxp )
    
        def get( key ):
            ret = fin_hash.get( key )
            if ret:
                return ret
            else:
                return ""
        
    	vals = OptVals()
        
        vals.name = 	get( 'name' )
        vals.memory = 	get( 'memory' )
        vals.maxmem =   get( 'maxmem' )
        vals.cpu =  	get( 'cpu' )
        vals.cpu_weight = get( 'cpu_weight' )
        
        vals.builder =  get( 'builder' )       
        vals.kernel =   get( 'kernel' )
	vals.root = 	get( 'root' )
        vals.extra = 	get( 'extra' )
        
        #setup vbds
        
        vbds = []
        
        for i in range( int( get( 'num_vbds' ) ) ):
            vbds.append( ( get( 'vbd%s_dom0' % i ), get('vbd%s_domU' % i ), get( 'vbd%s_mode' % i ) ) )
        
        vals.disk = vbds    
            
        #misc
        
        vals.pci = []
        
        vals.blkif = None
        vals.netif = None
        vals.restart = None
        vals.console = None
        vals.ramdisk = None
        
        #setup vifs
        
        vals.vif = []
        vals.nics = 1
                
        ip =   get( 'ip_addr' )
        nfs =  get( 'ip_nfs' )
        gate = get( 'ip_gateway' )
        mask = get( 'ip_subnet' )
        host = get( 'hostname' )
        dhcp = get( 'dhcp' )
        
        vals.cmdline_ip = "%s:%s:%s:%s:%s:eth0:%s" % (ip, nfs, gate, mask, host, dhcp)
        
        try:
            return make_config( vals )
        except:
            return [["Error creating domain config."]]    
        
