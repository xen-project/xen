/*
 * This supplies .note.* sections to go into the PT_NOTE inside the vDSO text.
 * Here we can supply some information useful to userland.
 * First we get the vanilla i386 note that supplies the kernel version info.
 */

#include "vsyscall-note.S"

/*
 * Now we add a special note telling glibc's dynamic linker a fake hardware
 * flavor that it will use to choose the search path for libraries in the
 * same way it uses real hardware capabilities like "mmx".
 * We supply "nosegneg" as the fake capability, to indicate that we
 * do not like negative offsets in instructions using segment overrides,
 * since we implement those inefficiently.  This makes it possible to
 * install libraries optimized to avoid those access patterns in someplace
 * like /lib/i686/tls/nosegneg.  Note that an /etc/ld.so.conf.d/file
 * corresponding to the bits here is needed to make ldconfig work right.
 * It should contain:
 *	hwcap 0 nosegneg
 * to match the mapping of bit to name that we give here.
 */
#define NOTE_KERNELCAP_BEGIN(ncaps, mask) \
	ASM_ELF_NOTE_BEGIN(".note.kernelcap", "a", "GNU", 2) \
	.long ncaps, mask
#define NOTE_KERNELCAP(bit, name) \
	.byte bit; .asciz name
#define NOTE_KERNELCAP_END ASM_ELF_NOTE_END

NOTE_KERNELCAP_BEGIN(1, 1)
NOTE_KERNELCAP(0, "nosegneg")
NOTE_KERNELCAP_END
