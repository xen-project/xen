from xen.sv.Wizard import *
from xen.sv.util import *
from xen.sv.GenTabbed import PreTab

from xen.xm.create import make_config, OptVals

from xen.xend.XendClient import server

class RestoreDomain( Wizard ):
    def __init__( self, urlWriter ):

        sheets = [ ChooseRestoreDomain,
                   DoRestore ]

        Wizard.__init__( self, urlWriter, "Restore Domain", sheets )


class ChooseRestoreDomain( Sheet ):
    title = "Configure Restore"

    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Configure Restore", 0)
        
        self.addControl( InputControl( 'file', '',
                                       'Suspend file name:',
                                       ".*") )

class DoRestore( Sheet ):
    title = "Restore Done"
    
    def __init__(self, urlWriter ):
        Sheet.__init__(self, urlWriter, "Restore Done", 1)

    def write_BODY( self, request, err ):

        if not self.passback: self.parseForm( request )
        config = ssxp2hash ( string2sxp( self.passback ) )
      
        try:
            dom_sxp = server.xend_domain_restore( config['file'] )
            success = "Your domain was successfully restored.\n"
        except Exception, e:
            success = "There was an error restoring your domain\n"
            dom_sxp = str(e)
        
        pt = PreTab( success + sxp2prettystring( dom_sxp ) )
        pt.write_BODY( request )

        request.write( "<input type='hidden' name='passback' value=\"%s\"></p>" % self.passback )
        request.write( "<input type='hidden' name='sheet' value='%s'></p>" % self.location )
