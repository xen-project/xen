
from distutils.core import setup, Extension

XEN_ROOT = "../.."

extra_compile_args  = [ "-fno-strict-aliasing", "-Wall", "-Werror" ]


include_dirs = [ XEN_ROOT + "/xen/include/hypervisor-ifs",
                 XEN_ROOT + "/linux-xen-sparse/include",
                 XEN_ROOT + "/tools/python/xen/ext/xu",
                 XEN_ROOT + "/tools/libxc",
                 XEN_ROOT + "/tools/libxutil",
                 ]

library_dirs = [ XEN_ROOT + "/tools/libxc",
                 XEN_ROOT + "/tools/libxutil",
                 ]

libraries = [ "xc", "xutil" ]

xc = Extension("xc",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/ext/xc" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "xen/ext/xc/xc.c" ])

xu = Extension("xu",
               extra_compile_args = extra_compile_args,
               include_dirs       = include_dirs + [ "xen/ext/xu" ],
               library_dirs       = library_dirs,
               libraries          = libraries,
               sources            = [ "xen/ext/xu/xu.c" ])
               
setup(name            = 'xen',
      version         = '2.0',
      description     = 'Xen',
      packages        = ['xen',
                         'xen.ext',
                         'xen.util',
                         'xen.xend',
                         'xen.xend.server',
                         'xen.xm',
                         ],
      ext_package = "xen.ext",
      ext_modules = [ xc, xu ]
      )
