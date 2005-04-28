from distutils.core import setup, Extension
import os

extra_compile_args  = [ "-fno-strict-aliasing", "-Wall", "-Werror" ]

# in a perfect world, we'd figure out the fsys modules dynamically
ext2 = Extension("grub.fsys.ext2._pyext2",
                 extra_compile_args = extra_compile_args,
                 libraries = ["ext2fs"],
                 sources = ["src/fsys/ext2/ext2module.c"])

setup(name='pygrub',
      version='0.1',
      description='Boot loader that looks a lot like grub for Xen',
      author='Jeremy Katz',
      author_email='katzj@redhat.com',
      license='GPL',
      package_dir={'grub': 'src'},
      scripts = ["src/pygrub"],
      packages=['grub',
                'grub.fsys',
                'grub.fsys.ext2'],
      ext_modules = [ext2]
      )
               
