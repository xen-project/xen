from xen.sv.Wizard import *
from xen.sv.util import *
from xen.sv.GenTabbed import PreTab

from xen.xm.create import make_config, OptVals

from xen.xend.XendClient import server

class MigrateDomain( Wizard ):
    def __init__( self, urlWriter ):

        sheets = [ ChooseMigrateDomain,
                   DoMigrate ]

        Wizard.__init__( self, urlWriter, "Migrate Domain", sheets )


class ChooseMigrateDomain( Sheet ):
    def __init__( self, urlWriter ):
        Sheet.__init__( self, urlWriter, "Configure Migration", 0)
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
        self.addControl( TickControl('live',
                                     'True',
                                     'Live migrate:') )
        self.addControl( InputControl('rate',
                                      '0',
                                      'Rate limit:') )
        self.addControl( InputControl( 'dest', 'myhost.mydomain',
                                       'Name or IP address:',
                                       ".*") )

class DoMigrate( Sheet ):
    def __init__(self, urlWriter ):
        Sheet.__init__(self, urlWriter, "Migration Done", 1)

    def write_BODY( self, request, err ):

        if not self.passback: self.parseForm( request )

#        print string2sxp(self.passback)
        
        config = ssxp2hash ( string2sxp( self.passback ) )
      
        try:
            print config
            print config['domid'], config['dest']
            dom_sxp = server.xend_domain_migrate( config['domid'],
                                                  config['dest'],
                                                  config.get('live') == 'True',
                                                  config['rate'] )
            success = "Your domain was successfully Migrated.\n"
        except Exception, e:
            success = "There was an error migrating your domain\n"
            dom_sxp = str(e)
        
        pt = PreTab( success + dom_sxp ) # sxp2prettystring( dom_sxp ) )
        pt.write_BODY( request )

        request.write( "<input type='hidden' name='passback' value=\"%s\"></p>" % self.passback )
        request.write( "<input type='hidden' name='sheet' value='%s'></p>" % self.location )
