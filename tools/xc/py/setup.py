
from distutils.core import setup, Extension

module = Extension("xc",
                   extra_compile_args   = ["-fno-strict-aliasing"],
                   include_dirs         = ["../lib",
                                           "../../../xen/include/hypervisor-ifs",
                                           "../../../linux-xen-sparse/include",
                                           "../../xu/lib",
                                           "../../lib" ],
                   library_dirs         = ["../lib",
                                           "../../lib" ],
                   libraries            = ["xc"],
                   sources              = ["Xc.c"])

setup(name = "xc",
      version = "2.0",
      ext_package = "xen.ext",
      ext_modules = [module])
