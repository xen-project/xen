from distutils.core import setup, Extension

extra_compile_args  = [ "-fno-strict-aliasing", "-Werror" ]

setup(name         = 'ptsname',
      version      = '1.0',
      description  = 'POSIX ptsname() function',
      author       = 'Tim Deegan',
      author_email = 'Tim.Deegan@xensource.com',
      license      = 'GPL',
      ext_modules  = [ Extension("ptsname", [ "ptsname.c" ]) ])
