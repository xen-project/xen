# Libraries below tools/libs/ and their dependencies

LIBS_LIBS += toolcore
USELIBS_toolcore :=
LIBS_LIBS += toollog
USELIBS_toollog :=
LIBS_LIBS += evtchn
USELIBS_evtchn := toollog toolcore
LIBS_LIBS += gnttab
USELIBS_gnttab := toollog toolcore
LIBS_LIBS += call
USELIBS_call := toollog toolcore
LIBS_LIBS += foreignmemory
USELIBS_foreignmemory := toollog toolcore
LIBS_LIBS += devicemodel
USELIBS_devicemodel := toollog toolcore call
LIBS_LIBS += hypfs
USELIBS_hypfs := toollog toolcore call
LIBS_LIBS += ctrl
USELIBS_ctrl := toollog call evtchn gnttab foreignmemory devicemodel
LIBS_LIBS += guest
USELIBS_guest := evtchn ctrl
LIBS_LIBS += store
USELIBS_store := toolcore
LIBS_LIBS += vchan
USELIBS_vchan := toollog store gnttab evtchn
LIBS_LIBS += stat
USELIBS_stat := ctrl store
LIBS_LIBS += light
USELIBS_light := toollog evtchn toolcore ctrl store hypfs guest
LIBS_LIBS += util
USELIBS_util := light
FILENAME_util := xlutil

# Give the list of Xen library that the libraries in $(1) are linked against,
# directly or indirectly.
define xenlibs-dependencies
    $(sort $(foreach lib,$(1), \
        $(USELIBS_$(lib)) $(call xenlibs-dependencies,$(USELIBS_$(lib)))))
endef
