from xen.sv.Wizard import *
from xen.sv.util import *
from xen.sv.GenTabbed import PreTab

from xen.xm.create import make_config, OptVals

from xen.xend.XendClient import server

class SaveDomain( Wizard ):
    def __init__( self, urlWriter ):

        sheets = [ ChooseSaveDomain,
                   DoSave ]

        Wizard.__init__( self, urlWriter, "Save Domain", sheets )


class ChooseSaveDomain( Sheet ):
    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Configure Save", 0)
        try:
            domains = server.xend_domains()
            domains.sort()
        except:
            pass

        domnames = []
        for i in domains:
            if i != 'Domain-0': domnames.append((i,i))
        
        self.addControl( ListControl('domid',
                                     domnames,
                                     'Domain ID:') )
        self.addControl( InputControl( 'file', '',
                                       'Suspend file name:',
                                       ".*") )

class DoSave( Sheet ):
    def __init__(self, urlWriter ):
        Sheet.__init__(self, urlWriter, "Save Done", 1)

    def write_BODY( self, request, err ):

        if not self.passback: self.parseForm( request )
        config = ssxp2hash ( string2sxp( self.passback ) )
      
        try:
            dom_sxp = server.xend_domain_save( config['domid'],
                                                  config['file'] )
            success = "Your domain was successfully saved.\n"
        except Exception, e:
            success = "There was an error saving your domain\n"
            dom_sxp = str(e)
        
        pt = PreTab( success + dom_sxp ) # sxp2prettystring( dom_sxp ) )
        pt.write_BODY( request )

        request.write( "<input type='hidden' name='passback' value=\"%s\"></p>" % self.passback )
        request.write( "<input type='hidden' name='sheet' value='%s'></p>" % self.location )
