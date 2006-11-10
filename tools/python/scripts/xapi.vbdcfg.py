#
# Virtual Block Device (VBD) Xen API Configuration
# 
# Note: There is a non-API field here called "image" which is a backwards
#       compat addition so you can mount to old images.
# 

VDI =  ''
device = 'sda1'
mode = 'RW'
driver = 'paravirtualised'
image = 'file:/root/gentoo.amd64.img'
