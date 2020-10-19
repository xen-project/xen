# Included by Mini-OS stubdom builds to set variables depending on Xen
# internal paths.
#
# Input variables are:
# XEN_ROOT
# MINIOS_TARGET_ARCH

XENSTORE_CPPFLAGS = -isystem $(XEN_ROOT)/tools/include
TOOLCORE_PATH = $(XEN_ROOT)/stubdom/libs-$(MINIOS_TARGET_ARCH)/toolcore
TOOLLOG_PATH = $(XEN_ROOT)/stubdom/libs-$(MINIOS_TARGET_ARCH)/toollog
EVTCHN_PATH = $(XEN_ROOT)/stubdom/libs-$(MINIOS_TARGET_ARCH)/evtchn
GNTTAB_PATH = $(XEN_ROOT)/stubdom/libs-$(MINIOS_TARGET_ARCH)/gnttab
CALL_PATH = $(XEN_ROOT)/stubdom/libs-$(MINIOS_TARGET_ARCH)/call
FOREIGNMEMORY_PATH = $(XEN_ROOT)/stubdom/libs-$(MINIOS_TARGET_ARCH)/foreignmemory
DEVICEMODEL_PATH = $(XEN_ROOT)/stubdom/libs-$(MINIOS_TARGET_ARCH)/devicemodel
CTRL_PATH = $(XEN_ROOT)/stubdom/libs-$(MINIOS_TARGET_ARCH)/ctrl
GUEST_PATH = $(XEN_ROOT)/stubdom/libs-$(MINIOS_TARGET_ARCH)/guest
