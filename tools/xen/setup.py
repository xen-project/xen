
from distutils.core import setup, Extension

setup(name            = 'xen',
      version         = '1.0',
      description     = 'Xen',
      author          = 'Mike Wray',
      author_email    = 'mike.wray@hp.com',
      packages        = ['xen',
                         'xen.ext',
                         'xen.xend',
                         'xen.xend.server',
                         'xen.xm',
                         ],
      package_dir     = { 'xen': 'lib' },
      )
