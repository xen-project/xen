
from distutils.core import setup, Extension

PACKAGE = 'xenmgr'
VERSION = '1.0'

setup(name            = PACKAGE,
      version         = VERSION,
      description     = 'Xen Management API',
      author          = 'Mike Wray',
      author_email    = 'mike.wray@hp.com',
      packages        = [ PACKAGE, PACKAGE + '.server' ],
      package_dir     = { PACKAGE: 'lib' },
      )
