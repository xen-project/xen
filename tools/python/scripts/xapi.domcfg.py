#
# VM Configuration for Xen API
#

name_label =  'GentooAPI'
name_description =  'Gentoo VM via API'
user_version =  1
is_a_template =  False
memory_static_max =  32
memory_dynamic_max =  32
memory_dynamic_min =  32
memory_static_min =  32
VCPUs_policy =  ''
VCPUs_params =  ''
VCPUS_features_required =  ''
VCPUs_features_can_use =  ''
VCPUs_features_force_on =  ''
VCPUs_features_force_off =  ''
actions_after_shutdown =  'destroy'
actions_after_reboot =  'restart'
actions_after_suspend =  'destroy'
actions_after_crash =  'restart'
bios_boot =  ''
platform_std_VGA =  False
platform_serial =  ''
platform_localtime =  False
platform_clock_offset =  False
platform_enable_audio =  False
builder =  'linux'
boot_method =  '' # this will remove the kernel/initrd ??
kernel_kernel =  '/boot/vmlinuz-2.6.16.29-xen'
kernel_initrd =  '/root/initrd-2.6.16.29-xen.img'
kernel_args =  'root=/dev/sda1 ro'
grub_cmdline =  ''
PCI_bus =  ''
other_config =  ''

