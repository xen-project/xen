#define parseelfimage parseelfimage_32
#define loadelfimage loadelfimage_32
#define xen_elfnote_string xen_elfnote_string32
#define xen_elfnote_numeric xen_elfnote_numeric32
#define ELFSIZE 32
#include "../../common/elf.c"

