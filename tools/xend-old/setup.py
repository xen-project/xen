
from distutils.core import setup, Extension

utils = Extension("utils",
                  extra_compile_args   = ["-fno-strict-aliasing"],
                  include_dirs         = ["../xc/lib",
                                          "../../xen/include/hypervisor-ifs",
                                          "../../linux-xen-sparse/include"],
                  library_dirs         = ["../xc/lib"],
                  libraries            = ["xc"],
                  sources              = ["lib/utils.c"])

setup(name = "xend",
      version = "1.0",
      packages = ["xend"],
      package_dir = { "xend" : "lib" },
      ext_package = "xend",
      ext_modules = [ utils ]
      )
