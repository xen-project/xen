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
    
    	feilds = [( 'name', 'Name')]
    
        Sheet.__init__( self, urlWriter, feilds, "Create New Domain - 1" )
                
class CreatePage1( Sheet ):

    def __init__( self, urlWriter ):
    
    	feilds = [( 'name', 'Name')]
        
        Sheet.__init__( self, urlWriter, feilds, "Create New Domain - 2" )
        
class CreatePage2( Sheet ):

    def __init__( self, urlWriter ):
    
    	feilds = [( 'name', 'Name')]    
   
        Sheet.__init__( self, urlWriter, feilds, "Create New Domain - 3" )
                
class CreatePage3( Sheet ):

    def __init__( self, urlWriter ):
    
    	feilds = [( 'name', 'Name')]
        
        Sheet.__init__( self, urlWriter, feilds, "Create New Domain - 4" )       