# Use GNU tool definitions as the tools we are using are either GNU compatible
# or we only use features which are supported on Mac OS.
include $(XEN_ROOT)/config/StdGNU.mk

# Force cross compile on Mac OS: Only hypervisor build is supported, no tools,
# and in the hypervisor the (plain) SVR4 ABI is in use.
XEN_COMPILE_ARCH = unknown
