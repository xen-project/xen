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
    
    	Wizard.__init__( self, urlWriter, "Create Domain", sheets )

    def op_finish( self, request ):
        pass
    
class CreatePage0( Sheet ):

    title = "General"
    
    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "General", 0 )
        self.addControl( InputControl( 'name', 'VM Name', 'VM Name:', "[\\w|\\S]+", "You must enter a name in this field" ) )
        self.addControl( InputControl( 'memory', '64', 'Memory (Mb):', "[\\d]+", "You must enter a number in this field" ) )
        self.addControl( InputControl( 'cpu', '0', 'CPU:', "[\\d]+", "You must enter a number in this feild" ) )
        self.addControl( InputControl( 'cpu_weight', '1', 'CPU Weight:', "[\\d]+", "You must enter a number in this feild" ) )
        self.addControl( InputControl( 'vcpus', '1', 'Virtual CPUs:', '[\\d]+', "You must enter a number in this feild") )
                        
class CreatePage1( Sheet ):

    title = "Setup Kernel Image"

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Setup Kernel Image", 1 )
        self.addControl( ListControl( 'builder', [('linux', 'Linux'), ('netbsd', 'NetBSD')], 'Domain Builder:' ) )
        self.addControl( FileControl( 'kernel', '/boot/vmlinuz-2.6.12-xenU', 'Kernel Image:' ) )
        self.addControl( InputControl( 'extra', '', 'Kernel Command Line Parameters:' ) )
        self.addControl( ListControl( 'use-initrd', [('yes', 'Yes'), ('no', 'No')], 'Use an Initial Ram Disk?:' ) )
        self.addControl( FileControl( 'initrd', '/boot/initrd-2.6.12-xenU.img', 'Initial Ram Disk:' ) )

    def validate( self, request ):
        if not self.passback: self.parseForm( request )
        check = True
        request.write( previous_values.get( '>>>>>use-initrd' ) )
        previous_values = ssxp2hash( string2sxp( self.passback ) ) #get the map for quick reference
        if DEBUG: print previous_values
        for (feild, control) in self.feilds:
            if feild == 'initrd' and previous_values.get( 'use-initrd' ) != 'no':
                request.write( previous_values.get( '>>>>>use-initrd' ) )
                if control.validate( previous_values.get( feild ) ):
                    check = False
            elif not control.validate( previous_values.get( feild ) ):
                check = False

            if DEBUG: print "> %s = %s" % (feild, previous_values.get( feild ))

        return check
                                                 

class CreatePage2( Sheet ):

    title = "Choose number of VBDS"

    def __init__( self, urlWriter ):
    	Sheet.__init__( self, urlWriter, "Setup Virtual Block Device", 2 )
        self.addControl( InputControl( 'num_vbds', '1', 'Number of VBDs:', '[\\d]+', "You must enter a number in this field" ) )

class CreatePage3( Sheet ):

    title = "Setup VBDS"

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Setup Virtual Block Device", 3 )
        
    def write_BODY( self, request ):
        if not self.passback: self.parseForm( request )
    
    	previous_values = sxp2hash( string2sxp( self.passback ) ) #get the hash for quick reference
        
        num_vbds = previous_values.get( 'num_vbds' )
        
        for i in range( int( num_vbds ) ):
            self.addControl( InputControl( 'vbd%s_dom0' % i, 'phy:sda%s' % str(i + 1), 'Device %s name:' % i  ) )
            self.addControl( InputControl( 'vbd%s_domU' % i, 'sda%s' % str(i + 1), 'Virtualized device %s:' % i ) )
            self.addControl( ListControl( 'vbd%s_mode' % i, [('w', 'Read + Write'), ('r', 'Read Only')], 'Device %s mode:' % i ) )
            
        self.addControl( InputControl( 'root', '/dev/sda1', 'Root device (in VM):' ) )
        
        Sheet.write_BODY( self, request )
                
class CreatePage4( Sheet ):

    title = "Network Setting"

    def __init__( self, urlWriter ):        
        Sheet.__init__( self, urlWriter, "Network settings", 4 )
        self.addControl( ListControl( 'dhcp', [('off', 'No'), ('dhcp', 'Yes')], 'Use DHCP:' ) )
        self.addControl( InputControl( 'hostname', 'hostname', 'VM Hostname:' ) )
        self.addControl( InputControl( 'ip_addr', '192.168.1.1', 'VM IP Address:' ) )
        self.addControl( InputControl( 'ip_subnet', '255.255.255.0', 'VM Subnet Mask:' ) ) 
        self.addControl( InputControl( 'ip_gateway', '192.168.1.1', 'VM Gateway:' ) )           
        self.addControl( InputControl( 'ip_nfs', '192.168.1.1', 'NFS Server:' ) )  
                 
class CreateFinish( Sheet ):

    title = "Finish"

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "All Done", 5 )
        
    def write_BODY( self, request ):
    
        if not self.passback: self.parseForm( request )
        
        xend_sxp = self.translate_sxp( string2sxp( self.passback ) )

        request.write( "<pre>%s</pre>" % sxp2prettystring( xend_sxp ) )
        
        try:
            server.xend_domain_create( xend_sxp )
            request.write( "<p>You domain had been successfully created.</p>" )
        except Exception, e:
            request.write( "<p>There was an error creating your domain.<br/>The configuration used is as follows:\n</p>" )
            request.write( "<pre>%s</pre>" % sxp2prettystring( xend_sxp ) )
            request.write( "<p>The error was:</p>" )
            request.write( "<pre>%s</pre>" % str( e ) )

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
        vals.vcpus = get( 'vcpus' )
        
        vals.builder =  get( 'builder' )       
        vals.kernel =   get( 'kernel' )
	vals.root = 	get( 'root' )
        vals.extra = 	get( 'extra' )
        
        #setup vbds
        
        vbds = []
        
        for i in range( int( get( 'num_vbds' ) ) ):
            vbds.append( ( get( 'vbd%s_dom0' % i ), get('vbd%s_domU' % i ), get( 'vbd%s_mode' % i ), None ) )
        
        vals.disk = vbds    
            
        #misc
        
        vals.pci = []
        
        vals.blkif = None
        vals.netif = None
        vals.restart = None
        vals.console = None
        vals.ramdisk = None
        vals.ssidref = -1
        vals.bootloader = None
        vals.usb = []
        vals.acpi = []
        
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

        opts = None
        
        try:
            return make_config( opts, vals )
        except Exception, e:
            return [["There was an error creating the domain config SXP.  This is typically due to an interface change in xm/create.py:make_config", e]]    
        
