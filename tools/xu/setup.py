
from distutils.core import setup, Extension

xu = Extension("xu",
                  extra_compile_args   = ["-fno-strict-aliasing"],
                  include_dirs         = ["../xc/lib",
                                          "../../xen/include/hypervisor-ifs",
                                          "../../linux-xen-sparse/include"],
                  library_dirs         = ["../xc/lib"],
                  libraries            = ["xc"],
                  sources              = ["lib/xu.c"])

setup(name = "xu",
      version = "1.0",
      #packages = ["xend"],
      #package_dir = { "xend" : "lib" },
      ext_package = "xen.ext",
      ext_modules = [ xu ]
      )
