
from distutils.core import setup, Extension

module = Extension("xend_utils",
                   include_dirs         = ["../xc/lib",
                                           "../../xenolinux-sparse/include"],
                   library_dirs         = ["../xc/lib"],
                   libraries            = ["xc"],
                   sources              = ["xend_utils.c"])

setup(name = "xend_utils", version = "1.0", ext_modules = [module])
