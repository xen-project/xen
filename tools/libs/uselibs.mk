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
