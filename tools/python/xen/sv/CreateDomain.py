from xen.sv.Wizzard import Wizzard, Sheet

class CreateDomain( Wizzard ):
    def __init__( self, urlWriter ):
    	
    	sheets = { 0: CreatePage0,
          	   1: CreatePage1,
          	   2: CreatePage2,
                   3: CreatePage3 }
    
    	Wizzard.__init__( self, urlWriter, "Create Domain Wizzard", sheets )
       
class CreatePage0( Sheet ):

    def __init__( self, urlWriter ):
    
    	feilds = [( 'name', 'VM Name:'),
                  ( 'memory', 'RAM (Mb):' )]
    
        Sheet.__init__( self, urlWriter, feilds, "Create New Domain", 0 )
                
class CreatePage1( Sheet ):

    def __init__( self, urlWriter ):
    
    	feilds = [( 'kernel_type', 'Kernel Type:'),
                  ( 'kernel_location', 'Kernel location:')]
        
        Sheet.__init__( self, urlWriter, feilds, "Setup Kernel Image", 1 )
        
class CreatePage2( Sheet ):

    def __init__( self, urlWriter ):
    
    	feilds = [( 'vbd_dom0', 'Location of vbd:'),
        	  ( 'vbd_dom0', 'Vitualised location:')]    
   
        Sheet.__init__( self, urlWriter, feilds, "Setup Virtual Block Devices", 2 )
                
class CreatePage3( Sheet ):

    def __init__( self, urlWriter ):
    
    	feilds = [( 'vifs', 'Number of Vifs:')]
        
        Sheet.__init__( self, urlWriter, feilds, "Create New Domain - 4", 3 )       
