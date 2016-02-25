#include "efi.h"
#include <efi/efiprot.h>
#include <efi/efipciio.h>
#include <public/xen.h>
#include <xen/bitops.h>
#include <xen/compile.h>
#include <xen/ctype.h>
#include <xen/dmi.h>
#include <xen/init.h>
#include <xen/keyhandler.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/multiboot.h>
#include <xen/pci_regs.h>
#include <xen/pfn.h>
#if EFI_PAGE_SIZE != PAGE_SIZE
# error Cannot use xen/pfn.h here!
#endif
#include <xen/string.h>
#include <xen/stringify.h>
#ifdef CONFIG_X86
/*
 * Keep this arch-specific modified include in the common file, as moving
 * it to the arch specific include file would obscure that special care is
 * taken to include it with __ASSEMBLY__ defined.
 */
#define __ASSEMBLY__ /* avoid pulling in ACPI stuff (conflicts with EFI) */
#include <asm/fixmap.h>
#undef __ASSEMBLY__
#endif

/* Using SetVirtualAddressMap() is incompatible with kexec: */
#undef USE_SET_VIRTUAL_ADDRESS_MAP

#define EFI_REVISION(major, minor) (((major) << 16) | (minor))

#define SMBIOS3_TABLE_GUID \
  { 0xf2fd1544, 0x9794, 0x4a2c, {0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94} }
#define SHIM_LOCK_PROTOCOL_GUID \
  { 0x605dab50, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23} }

typedef EFI_STATUS
(/* _not_ EFIAPI */ *EFI_SHIM_LOCK_VERIFY) (
    IN VOID *Buffer,
    IN UINT32 Size);

typedef struct {
    EFI_SHIM_LOCK_VERIFY Verify;
} EFI_SHIM_LOCK_PROTOCOL;

union string {
    CHAR16 *w;
    char *s;
    const char *cs;
};

struct file {
    UINTN size;
    union {
        EFI_PHYSICAL_ADDRESS addr;
        void *ptr;
    };
};

static CHAR16 *FormatDec(UINT64 Val, CHAR16 *Buffer);
static CHAR16 *FormatHex(UINT64 Val, UINTN Width, CHAR16 *Buffer);
static void  DisplayUint(UINT64 Val, INTN Width);
static CHAR16 *wstrcpy(CHAR16 *d, const CHAR16 *s);
static void noreturn blexit(const CHAR16 *str);
static void PrintErrMesg(const CHAR16 *mesg, EFI_STATUS ErrCode);
static char *get_value(const struct file *cfg, const char *section,
                              const char *item);
static char *split_string(char *s);
static CHAR16 *s2w(union string *str);
static char *w2s(const union string *str);
static bool_t read_file(EFI_FILE_HANDLE dir_handle, CHAR16 *name,
                        struct file *file, char *options);
static size_t wstrlen(const CHAR16 * s);
static int set_color(u32 mask, int bpp, u8 *pos, u8 *sz);
static bool_t match_guid(const EFI_GUID *guid1, const EFI_GUID *guid2);

static const EFI_BOOT_SERVICES *__initdata efi_bs;
static UINT32 __initdata efi_bs_revision;
static EFI_HANDLE __initdata efi_ih;

static SIMPLE_TEXT_OUTPUT_INTERFACE *__initdata StdOut;
static SIMPLE_TEXT_OUTPUT_INTERFACE *__initdata StdErr;

static UINT32 __initdata mdesc_ver;
static bool_t __initdata map_bs;

static struct file __initdata cfg;
static struct file __initdata kernel;
static struct file __initdata ramdisk;
static struct file __initdata xsm;
static CHAR16 __initdata newline[] = L"\r\n";

#define PrintStr(s) StdOut->OutputString(StdOut, s)
#define PrintErr(s) StdErr->OutputString(StdErr, s)

/*
 * Include architecture specific implementation here, which references the
 * static globals defined above.
 */
#include "efi-boot.h"

static CHAR16 *__init FormatDec(UINT64 Val, CHAR16 *Buffer)
{
    if ( Val >= 10 )
        Buffer = FormatDec(Val / 10, Buffer);
    *Buffer = (CHAR16)(L'0' + Val % 10);
    return Buffer + 1;
}

static CHAR16 *__init FormatHex(UINT64 Val, UINTN Width, CHAR16 *Buffer)
{
    if ( Width > 1 || Val >= 0x10 )
        Buffer = FormatHex(Val >> 4, Width ? Width - 1 : 0, Buffer);
    *Buffer = (CHAR16)((Val &= 0xf) < 10 ? L'0' + Val : L'a' + Val - 10);
    return Buffer + 1;
}

static void __init DisplayUint(UINT64 Val, INTN Width)
{
    CHAR16 PrintString[32], *end;

    if (Width < 0)
        end = FormatDec(Val, PrintString);
    else
    {
        PrintStr(L"0x");
        end = FormatHex(Val, Width, PrintString);
    }
    *end = 0;
    PrintStr(PrintString);
}

static size_t __init __maybe_unused wstrlen(const CHAR16 *s)
{
    const CHAR16 *sc;

    for ( sc = s; *sc != L'\0'; ++sc )
        /* nothing */;
    return sc - s;
}

static CHAR16 *__init wstrcpy(CHAR16 *d, const CHAR16 *s)
{
    CHAR16 *r = d;

    while ( (*d++ = *s++) != 0 )
        ;
    return r;
}

static int __init wstrcmp(const CHAR16 *s1, const CHAR16 *s2)
{
    while ( *s1 && *s1 == *s2 )
    {
        ++s1;
        ++s2;
    }
    return *s1 - *s2;
}

static int __init wstrncmp(const CHAR16 *s1, const CHAR16 *s2, UINTN n)
{
    while ( n && *s1 && *s1 == *s2 )
    {
        --n;
        ++s1;
        ++s2;
    }
    return n ? *s1 - *s2 : 0;
}

static CHAR16 *__init s2w(union string *str)
{
    const char *s = str->s;
    CHAR16 *w;
    void *ptr;

    if ( efi_bs->AllocatePool(EfiLoaderData, (strlen(s) + 1) * sizeof(*w),
                              &ptr) != EFI_SUCCESS )
        return NULL;

    w = str->w = ptr;
    do {
        *w = *s++;
    } while ( *w++ );

    return str->w;
}

static char *__init w2s(const union string *str)
{
    const CHAR16 *w = str->w;
    char *s = str->s;

    do {
        if ( *w > 0x007f )
            return NULL;
        *s = *w++;
    } while ( *s++ );

    return str->s;
}

static bool_t __init match_guid(const EFI_GUID *guid1, const EFI_GUID *guid2)
{
    return guid1->Data1 == guid2->Data1 &&
           guid1->Data2 == guid2->Data2 &&
           guid1->Data3 == guid2->Data3 &&
           !memcmp(guid1->Data4, guid2->Data4, sizeof(guid1->Data4));
}

static void __init noreturn blexit(const CHAR16 *str)
{
    if ( str )
        PrintStr((CHAR16 *)str);
    PrintStr(newline);

    if ( !efi_bs )
        efi_arch_halt();

    if ( cfg.addr )
        efi_bs->FreePages(cfg.addr, PFN_UP(cfg.size));
    if ( kernel.addr )
        efi_bs->FreePages(kernel.addr, PFN_UP(kernel.size));
    if ( ramdisk.addr )
        efi_bs->FreePages(ramdisk.addr, PFN_UP(ramdisk.size));
    if ( xsm.addr )
        efi_bs->FreePages(xsm.addr, PFN_UP(xsm.size));

    efi_arch_blexit();

    efi_bs->Exit(efi_ih, EFI_SUCCESS, 0, NULL);
    unreachable(); /* not reached */
}

/* generic routine for printing error messages */
static void __init PrintErrMesg(const CHAR16 *mesg, EFI_STATUS ErrCode)
{
    static const CHAR16* const ErrCodeToStr[] __initconstrel = {
        [~EFI_ERROR_MASK & EFI_NOT_FOUND]           = L"Not found",
        [~EFI_ERROR_MASK & EFI_NO_MEDIA]            = L"The device has no media",
        [~EFI_ERROR_MASK & EFI_MEDIA_CHANGED]       = L"Media changed",
        [~EFI_ERROR_MASK & EFI_DEVICE_ERROR]        = L"Device error",
        [~EFI_ERROR_MASK & EFI_VOLUME_CORRUPTED]    = L"Volume corrupted",
        [~EFI_ERROR_MASK & EFI_ACCESS_DENIED]       = L"Access denied",
        [~EFI_ERROR_MASK & EFI_OUT_OF_RESOURCES]    = L"Out of resources",
        [~EFI_ERROR_MASK & EFI_VOLUME_FULL]         = L"Volume is full",
        [~EFI_ERROR_MASK & EFI_SECURITY_VIOLATION]  = L"Security violation",
        [~EFI_ERROR_MASK & EFI_CRC_ERROR]           = L"CRC error",
        [~EFI_ERROR_MASK & EFI_COMPROMISED_DATA]    = L"Compromised data",
        [~EFI_ERROR_MASK & EFI_BUFFER_TOO_SMALL]    = L"Buffer too small",
    };
    EFI_STATUS ErrIdx = ErrCode & ~EFI_ERROR_MASK;

    StdOut = StdErr;
    PrintErr((CHAR16 *)mesg);
    PrintErr(L": ");

    if( (ErrIdx < ARRAY_SIZE(ErrCodeToStr)) && ErrCodeToStr[ErrIdx] )
        mesg = ErrCodeToStr[ErrIdx];
    else
    {
        PrintErr(L"ErrCode: ");
        DisplayUint(ErrCode, 0);
        mesg = NULL;
    }
    blexit(mesg);
}

static unsigned int __init get_argv(unsigned int argc, CHAR16 **argv,
                                    CHAR16 *cmdline, UINTN cmdsize,
                                    CHAR16 **options)
{
    CHAR16 *ptr = (CHAR16 *)(argv + argc + 1), *prev = NULL;
    bool_t prev_sep = TRUE;

    for ( ; cmdsize > sizeof(*cmdline) && *cmdline;
            cmdsize -= sizeof(*cmdline), ++cmdline )
    {
        bool_t cur_sep = *cmdline == L' ' || *cmdline == L'\t';

        if ( !prev_sep )
        {
            if ( cur_sep )
                ++ptr;
            else if ( argv )
            {
                *ptr = *cmdline;
                *++ptr = 0;
            }
        }
        else if ( !cur_sep )
        {
            if ( !argv )
                ++argc;
            else if ( prev && wstrcmp(prev, L"--") == 0 )
            {
                --argv;
                if ( options )
                    *options = cmdline;
                break;
            }
            else
            {
                *argv++ = prev = ptr;
                *ptr = *cmdline;
                *++ptr = 0;
            }
        }
        prev_sep = cur_sep;
    }
    if ( argv )
        *argv = NULL;
    return argc;
}

static EFI_FILE_HANDLE __init get_parent_handle(EFI_LOADED_IMAGE *loaded_image,
                                                CHAR16 **leaf)
{
    static EFI_GUID __initdata fs_protocol = SIMPLE_FILE_SYSTEM_PROTOCOL;
    EFI_FILE_HANDLE dir_handle;
    EFI_DEVICE_PATH *dp;
    CHAR16 *pathend, *ptr;
    EFI_STATUS ret;

    do {
        EFI_FILE_IO_INTERFACE *fio;

        /* Get the file system interface. */
        ret = efi_bs->HandleProtocol(loaded_image->DeviceHandle,
                                     &fs_protocol, (void **)&fio);
        if ( EFI_ERROR(ret) )
            PrintErrMesg(L"Couldn't obtain the File System Protocol Interface",
                         ret);
        ret = fio->OpenVolume(fio, &dir_handle);
    } while ( ret == EFI_MEDIA_CHANGED );
    if ( ret != EFI_SUCCESS )
        PrintErrMesg(L"OpenVolume failure", ret);

#define buffer ((CHAR16 *)keyhandler_scratch)
#define BUFFERSIZE sizeof(keyhandler_scratch)
    for ( dp = loaded_image->FilePath, *buffer = 0;
          DevicePathType(dp) != END_DEVICE_PATH_TYPE;
          dp = (void *)dp + DevicePathNodeLength(dp) )
    {
        FILEPATH_DEVICE_PATH *fp;

        if ( DevicePathType(dp) != MEDIA_DEVICE_PATH ||
             DevicePathSubType(dp) != MEDIA_FILEPATH_DP )
            blexit(L"Unsupported device path component");

        if ( *buffer )
        {
            EFI_FILE_HANDLE new_handle;

            ret = dir_handle->Open(dir_handle, &new_handle, buffer,
                                   EFI_FILE_MODE_READ, 0);
            if ( ret != EFI_SUCCESS )
            {
                PrintErr(L"Open failed for ");
                PrintErrMesg(buffer, ret);
            }
            dir_handle->Close(dir_handle);
            dir_handle = new_handle;
        }
        fp = (void *)dp;
        if ( BUFFERSIZE < DevicePathNodeLength(dp) -
                          sizeof(*dp) + sizeof(*buffer) )
            blexit(L"Increase BUFFERSIZE");
        memcpy(buffer, fp->PathName, DevicePathNodeLength(dp) - sizeof(*dp));
        buffer[(DevicePathNodeLength(dp) - sizeof(*dp)) / sizeof(*buffer)] = 0;
    }
    for ( ptr = buffer, pathend = NULL; *ptr; ++ptr )
        if ( *ptr == L'\\' )
            pathend = ptr;
    if ( pathend )
    {
        *pathend = 0;
        *leaf = pathend + 1;
        if ( *buffer )
        {
            EFI_FILE_HANDLE new_handle;

            ret = dir_handle->Open(dir_handle, &new_handle, buffer,
                                   EFI_FILE_MODE_READ, 0);
            if ( ret != EFI_SUCCESS ) {
                PrintErr(L"Open failed for ");
                PrintErrMesg(buffer, ret);
            }
            dir_handle->Close(dir_handle);
            dir_handle = new_handle;
        }
    }
    else
        *leaf = buffer;
#undef BUFFERSIZE
#undef buffer

    return dir_handle;
}

static CHAR16 *__init point_tail(CHAR16 *fn)
{
    CHAR16 *tail = NULL;

    for ( ; ; ++fn )
        switch ( *fn )
        {
        case 0:
            return tail;
        case L'.':
        case L'-':
        case L'_':
            tail = fn;
            break;
        }
}
/*
 * Truncate string at first space, and return pointer
 * to remainder of string, if any/ NULL returned if
 * no remainder after space.
 */
static char * __init split_string(char *s)
{
    while ( *s && !isspace(*s) )
        ++s;
    if ( *s )
    {
        *s = 0;
        return s + 1;
    }
    return NULL;
}

static bool_t __init read_file(EFI_FILE_HANDLE dir_handle, CHAR16 *name,
                               struct file *file, char *options)
{
    EFI_FILE_HANDLE FileHandle = NULL;
    UINT64 size;
    EFI_STATUS ret;
    CHAR16 *what = NULL;

    if ( !name )
        PrintErrMesg(L"No filename", EFI_OUT_OF_RESOURCES);
    ret = dir_handle->Open(dir_handle, &FileHandle, name,
                           EFI_FILE_MODE_READ, 0);
    if ( file == &cfg && ret == EFI_NOT_FOUND )
        return 0;
    if ( EFI_ERROR(ret) )
        what = L"Open";
    else
        ret = FileHandle->SetPosition(FileHandle, -1);
    if ( EFI_ERROR(ret) )
        what = what ?: L"Seek";
    else
        ret = FileHandle->GetPosition(FileHandle, &size);
    if ( EFI_ERROR(ret) )
        what = what ?: L"Get size";
    else
        ret = FileHandle->SetPosition(FileHandle, 0);
    if ( EFI_ERROR(ret) )
        what = what ?: L"Seek";
    else
    {
        file->addr = min(1UL << (32 + PAGE_SHIFT),
                         HYPERVISOR_VIRT_END - DIRECTMAP_VIRT_START);
        ret = efi_bs->AllocatePages(AllocateMaxAddress, EfiLoaderData,
                                    PFN_UP(size), &file->addr);
    }
    if ( EFI_ERROR(ret) )
    {
        file->addr = 0;
        what = what ?: L"Allocation";
    }
    else
    {
        file->size = size;
        if ( file != &cfg )
        {
            PrintStr(name);
            PrintStr(L": ");
            DisplayUint(file->addr, 2 * sizeof(file->addr));
            PrintStr(L"-");
            DisplayUint(file->addr + size, 2 * sizeof(file->addr));
            PrintStr(newline);
            efi_arch_handle_module(file, name, options);
        }

        ret = FileHandle->Read(FileHandle, &file->size, file->ptr);
        if ( !EFI_ERROR(ret) && file->size != size )
            ret = EFI_ABORTED;
        if ( EFI_ERROR(ret) )
            what = L"Read";
    }

    if ( FileHandle )
        FileHandle->Close(FileHandle);

    if ( what )
    {
        PrintErr(what);
        PrintErr(L" failed for ");
        PrintErrMesg(name, ret);
    }

    efi_arch_flush_dcache_area(file->ptr, file->size);

    return 1;
}

static void __init pre_parse(const struct file *cfg)
{
    char *ptr = cfg->ptr, *end = ptr + cfg->size;
    bool_t start = 1, comment = 0;

    for ( ; ptr < end; ++ptr )
    {
        if ( iscntrl(*ptr) )
        {
            comment = 0;
            start = 1;
            *ptr = 0;
        }
        else if ( comment || (start && isspace(*ptr)) )
            *ptr = 0;
        else if ( *ptr == '#' || (start && *ptr == ';') )
        {
            comment = 1;
            *ptr = 0;
        }
        else
            start = 0;
    }
    if ( cfg->size && end[-1] )
         PrintStr(L"No newline at end of config file,"
                   " last line will be ignored.\r\n");
}

static char *__init get_value(const struct file *cfg, const char *section,
                              const char *item)
{
    char *ptr = cfg->ptr, *end = ptr + cfg->size;
    size_t slen = section ? strlen(section) : 0, ilen = strlen(item);
    bool_t match = !slen;

    for ( ; ptr < end; ++ptr )
    {
        switch ( *ptr )
        {
        case 0:
            continue;
        case '[':
            if ( !slen )
                break;
            if ( match )
                return NULL;
            match = strncmp(++ptr, section, slen) == 0 && ptr[slen] == ']';
            break;
        default:
            if ( match && strncmp(ptr, item, ilen) == 0 && ptr[ilen] == '=' )
            {
                ptr += ilen + 1;
                /* strip off any leading spaces */
                while ( *ptr && isspace(*ptr) )
                    ptr++;
                return ptr;
            }
            break;
        }
        ptr += strlen(ptr);
    }
    return NULL;
}

static void __init efi_init(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    efi_ih = ImageHandle;
    efi_bs = SystemTable->BootServices;
    efi_bs_revision = efi_bs->Hdr.Revision;
    efi_rs = SystemTable->RuntimeServices;
    efi_ct = SystemTable->ConfigurationTable;
    efi_num_ct = SystemTable->NumberOfTableEntries;
    efi_version = SystemTable->Hdr.Revision;
    efi_fw_vendor = SystemTable->FirmwareVendor;
    efi_fw_revision = SystemTable->FirmwareRevision;

    StdOut = SystemTable->ConOut;
    StdErr = SystemTable->StdErr ?: StdOut;
}

static void __init efi_console_set_mode(void)
{
    UINTN cols, rows, size;
    unsigned int best, i;

    for ( i = 0, size = 0, best = StdOut->Mode->Mode;
          i < StdOut->Mode->MaxMode; ++i )
    {
        if ( StdOut->QueryMode(StdOut, i, &cols, &rows) == EFI_SUCCESS &&
             cols * rows > size )
        {
            size = cols * rows;
            best = i;
        }
    }
    if ( best != StdOut->Mode->Mode )
        StdOut->SetMode(StdOut, best);
}

static EFI_GRAPHICS_OUTPUT_PROTOCOL __init *efi_get_gop(void)
{
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode_info;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = NULL;
    EFI_HANDLE *handles = NULL;
    EFI_STATUS status;
    UINTN info_size, size = 0;
    static EFI_GUID __initdata gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
    unsigned int i;

    status = efi_bs->LocateHandle(ByProtocol, &gop_guid, NULL, &size, NULL);
    if ( status == EFI_BUFFER_TOO_SMALL )
        status = efi_bs->AllocatePool(EfiLoaderData, size, (void **)&handles);
    if ( !EFI_ERROR(status) )
        status = efi_bs->LocateHandle(ByProtocol, &gop_guid, NULL, &size,
                                      handles);
    if ( EFI_ERROR(status) )
        size = 0;
    for ( i = 0; i < size / sizeof(*handles); ++i )
    {
        status = efi_bs->HandleProtocol(handles[i], &gop_guid, (void **)&gop);
        if ( EFI_ERROR(status) )
            continue;
        status = gop->QueryMode(gop, gop->Mode->Mode, &info_size, &mode_info);
        if ( !EFI_ERROR(status) )
            break;
    }
    if ( handles )
        efi_bs->FreePool(handles);
    if ( EFI_ERROR(status) )
        gop = NULL;

    return gop;
}

static UINTN __init efi_find_gop_mode(EFI_GRAPHICS_OUTPUT_PROTOCOL *gop,
                                      UINTN cols, UINTN rows, UINTN depth)
{
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode_info;
    EFI_STATUS status;
    UINTN gop_mode = ~0, info_size, size;
    unsigned int i;

    for ( i = size = 0; i < gop->Mode->MaxMode; ++i )
    {
        unsigned int bpp = 0;

        status = gop->QueryMode(gop, i, &info_size, &mode_info);
        if ( EFI_ERROR(status) )
            continue;
        switch ( mode_info->PixelFormat )
        {
        case PixelBitMask:
            bpp = hweight32(mode_info->PixelInformation.RedMask |
                            mode_info->PixelInformation.GreenMask |
                            mode_info->PixelInformation.BlueMask);
            break;
        case PixelRedGreenBlueReserved8BitPerColor:
        case PixelBlueGreenRedReserved8BitPerColor:
            bpp = 24;
            break;
        default:
            continue;
        }
        if ( cols == mode_info->HorizontalResolution &&
             rows == mode_info->VerticalResolution &&
             (!depth || bpp == depth) )
        {
            gop_mode = i;
            break;
        }
        if ( !cols && !rows &&
             mode_info->HorizontalResolution *
             mode_info->VerticalResolution > size )
        {
            size = mode_info->HorizontalResolution *
                   mode_info->VerticalResolution;
            gop_mode = i;
        }
    }

    return gop_mode;
}

static void __init efi_tables(void)
{
    unsigned int i;

    /* Obtain basic table pointers. */
    for ( i = 0; i < efi_num_ct; ++i )
    {
        static EFI_GUID __initdata acpi2_guid = ACPI_20_TABLE_GUID;
        static EFI_GUID __initdata acpi_guid = ACPI_TABLE_GUID;
        static EFI_GUID __initdata mps_guid = MPS_TABLE_GUID;
        static EFI_GUID __initdata smbios_guid = SMBIOS_TABLE_GUID;
        static EFI_GUID __initdata smbios3_guid = SMBIOS3_TABLE_GUID;

        if ( match_guid(&acpi2_guid, &efi_ct[i].VendorGuid) )
	       efi.acpi20 = (long)efi_ct[i].VendorTable;
        if ( match_guid(&acpi_guid, &efi_ct[i].VendorGuid) )
	       efi.acpi = (long)efi_ct[i].VendorTable;
        if ( match_guid(&mps_guid, &efi_ct[i].VendorGuid) )
	       efi.mps = (long)efi_ct[i].VendorTable;
        if ( match_guid(&smbios_guid, &efi_ct[i].VendorGuid) )
	       efi.smbios = (long)efi_ct[i].VendorTable;
        if ( match_guid(&smbios3_guid, &efi_ct[i].VendorGuid) )
	       efi.smbios3 = (long)efi_ct[i].VendorTable;
    }

#ifndef CONFIG_ARM /* TODO - disabled until implemented on ARM */
    dmi_efi_get_table(efi.smbios != EFI_INVALID_TABLE_ADDR
                      ? (void *)(long)efi.smbios : NULL,
                      efi.smbios3 != EFI_INVALID_TABLE_ADDR
                      ? (void *)(long)efi.smbios3 : NULL);
#endif
}

static void __init setup_efi_pci(void)
{
    EFI_STATUS status;
    EFI_HANDLE *handles;
    static EFI_GUID __initdata pci_guid = EFI_PCI_IO_PROTOCOL;
    UINTN i, nr_pci, size = 0;
    struct efi_pci_rom *last = NULL;

    status = efi_bs->LocateHandle(ByProtocol, &pci_guid, NULL, &size, NULL);
    if ( status != EFI_BUFFER_TOO_SMALL )
        return;
    status = efi_bs->AllocatePool(EfiLoaderData, size, (void **)&handles);
    if ( EFI_ERROR(status) )
        return;
    status = efi_bs->LocateHandle(ByProtocol, &pci_guid, NULL, &size, handles);
    if ( EFI_ERROR(status) )
        size = 0;

    nr_pci = size / sizeof(*handles);
    for ( i = 0; i < nr_pci; ++i )
    {
        EFI_PCI_IO *pci = NULL;
        u64 attributes;
        struct efi_pci_rom *rom, *va;
        UINTN segment, bus, device, function;

        status = efi_bs->HandleProtocol(handles[i], &pci_guid, (void **)&pci);
        if ( EFI_ERROR(status) || !pci || !pci->RomImage || !pci->RomSize )
            continue;

        status = pci->Attributes(pci, EfiPciIoAttributeOperationGet, 0,
                                 &attributes);
        if ( EFI_ERROR(status) ||
             !(attributes & EFI_PCI_IO_ATTRIBUTE_EMBEDDED_ROM) ||
             EFI_ERROR(pci->GetLocation(pci, &segment, &bus, &device,
                       &function)) )
            continue;

        DisplayUint(segment, 4);
        PrintStr(L":");
        DisplayUint(bus, 2);
        PrintStr(L":");
        DisplayUint(device, 2);
        PrintStr(L".");
        DisplayUint(function, 1);
        PrintStr(L": ROM: ");
        DisplayUint(pci->RomSize, 0);
        PrintStr(L" bytes at ");
        DisplayUint((UINTN)pci->RomImage, 0);
        PrintStr(newline);

        size = pci->RomSize + sizeof(*rom);
        status = efi_bs->AllocatePool(EfiRuntimeServicesData, size,
                                      (void **)&rom);
        if ( EFI_ERROR(status) )
            continue;

        rom->next = NULL;
        rom->size = pci->RomSize;

        status = pci->Pci.Read(pci, EfiPciIoWidthUint16, PCI_VENDOR_ID, 1,
                               &rom->vendor);
        if ( !EFI_ERROR(status) )
            status = pci->Pci.Read(pci, EfiPciIoWidthUint16, PCI_DEVICE_ID, 1,
                                   &rom->devid);
        if ( EFI_ERROR(status) )
        {
            efi_bs->FreePool(rom);
            continue;
        }

        rom->segment = segment;
        rom->bus = bus;
        rom->devfn = (device << 3) | function;
        memcpy(rom->data, pci->RomImage, pci->RomSize);

        va = (void *)rom + DIRECTMAP_VIRT_START;
        if ( last )
            last->next = va;
        else
            efi_pci_roms = va;
        last = rom;
    }

    efi_bs->FreePool(handles);
}

static void __init efi_variables(void)
{
    EFI_STATUS status;

    status = (efi_rs->Hdr.Revision >> 16) >= 2 ?
             efi_rs->QueryVariableInfo(EFI_VARIABLE_NON_VOLATILE |
                                       EFI_VARIABLE_BOOTSERVICE_ACCESS |
                                       EFI_VARIABLE_RUNTIME_ACCESS,
                                       &efi_boot_max_var_store_size,
                                       &efi_boot_remain_var_store_size,
                                       &efi_boot_max_var_size) :
             EFI_INCOMPATIBLE_VERSION;
    if ( EFI_ERROR(status) )
    {
        efi_boot_max_var_store_size = 0;
        efi_boot_remain_var_store_size = 0;
        efi_boot_max_var_size = status;
        PrintStr(L"Warning: Could not query variable store: ");
        DisplayUint(status, 0);
        PrintStr(newline);
    }
}

static void __init efi_set_gop_mode(EFI_GRAPHICS_OUTPUT_PROTOCOL *gop, UINTN gop_mode)
{
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode_info;
    EFI_STATUS status;
    UINTN info_size;

    /* Set graphics mode. */
    if ( gop_mode < gop->Mode->MaxMode && gop_mode != gop->Mode->Mode )
        gop->SetMode(gop, gop_mode);

    /* Get graphics and frame buffer info. */
    status = gop->QueryMode(gop, gop->Mode->Mode, &info_size, &mode_info);
    if ( !EFI_ERROR(status) )
        efi_arch_video_init(gop, info_size, mode_info);
}

static void __init efi_exit_boot(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS status;
    UINTN info_size = 0, map_key;
    bool_t retry;

    efi_bs->GetMemoryMap(&info_size, NULL, &map_key,
                         &efi_mdesc_size, &mdesc_ver);
    info_size += 8 * efi_mdesc_size;
    efi_memmap = efi_arch_allocate_mmap_buffer(info_size);
    if ( !efi_memmap )
        blexit(L"Unable to allocate memory for EFI memory map");

    for ( retry = 0; ; retry = 1 )
    {
        efi_memmap_size = info_size;
        status = SystemTable->BootServices->GetMemoryMap(&efi_memmap_size,
                                                         efi_memmap, &map_key,
                                                         &efi_mdesc_size,
                                                         &mdesc_ver);
        if ( EFI_ERROR(status) )
            PrintErrMesg(L"Cannot obtain memory map", status);

        efi_arch_process_memory_map(SystemTable, efi_memmap, efi_memmap_size,
                                    efi_mdesc_size, mdesc_ver);

        efi_arch_pre_exit_boot();

        status = SystemTable->BootServices->ExitBootServices(ImageHandle,
                                                             map_key);
        efi_bs = NULL;
        if ( status != EFI_INVALID_PARAMETER || retry )
            break;
    }

    if ( EFI_ERROR(status) )
        PrintErrMesg(L"Cannot exit boot services", status);

    /* Adjust pointers into EFI. */
    efi_ct = (void *)efi_ct + DIRECTMAP_VIRT_START;
#ifdef USE_SET_VIRTUAL_ADDRESS_MAP
    efi_rs = (void *)efi_rs + DIRECTMAP_VIRT_START;
#endif
    efi_memmap = (void *)efi_memmap + DIRECTMAP_VIRT_START;
    efi_fw_vendor = (void *)efi_fw_vendor + DIRECTMAP_VIRT_START;
}

static int __init __maybe_unused set_color(u32 mask, int bpp, u8 *pos, u8 *sz)
{
   if ( bpp < 0 )
       return bpp;
   if ( !mask )
       return -EINVAL;
   for ( *pos = 0; !(mask & 1); ++*pos )
       mask >>= 1;
   for ( *sz = 0; mask & 1; ++sz)
       mask >>= 1;
   if ( mask )
       return -EINVAL;
   return max(*pos + *sz, bpp);
}

void EFIAPI __init noreturn
efi_start(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    static EFI_GUID __initdata loaded_image_guid = LOADED_IMAGE_PROTOCOL;
    static EFI_GUID __initdata shim_lock_guid = SHIM_LOCK_PROTOCOL_GUID;
    EFI_LOADED_IMAGE *loaded_image;
    EFI_STATUS status;
    unsigned int i, argc;
    CHAR16 **argv, *file_name, *cfg_file_name = NULL, *options = NULL;
    UINTN gop_mode = ~0;
    EFI_SHIM_LOCK_PROTOCOL *shim_lock;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = NULL;
    union string section = { NULL }, name;
    bool_t base_video = 0;
    char *option_str;
    bool_t use_cfg_file;

    efi_init(ImageHandle, SystemTable);

    use_cfg_file = efi_arch_use_config_file(SystemTable);

    status = efi_bs->HandleProtocol(ImageHandle, &loaded_image_guid,
                                    (void **)&loaded_image);
    if ( status != EFI_SUCCESS )
        PrintErrMesg(L"No Loaded Image Protocol", status);

    efi_arch_load_addr_check(loaded_image);

    if ( use_cfg_file )
    {
        argc = get_argv(0, NULL, loaded_image->LoadOptions,
                        loaded_image->LoadOptionsSize, NULL);
        if ( argc > 0 &&
             efi_bs->AllocatePool(EfiLoaderData,
                                  (argc + 1) * sizeof(*argv) +
                                      loaded_image->LoadOptionsSize,
                                  (void **)&argv) == EFI_SUCCESS )
            get_argv(argc, argv, loaded_image->LoadOptions,
                     loaded_image->LoadOptionsSize, &options);
        else
            argc = 0;
        for ( i = 1; i < argc; ++i )
        {
            CHAR16 *ptr = argv[i];

            if ( !ptr )
                break;
            if ( *ptr == L'/' || *ptr == L'-' )
            {
                if ( wstrcmp(ptr + 1, L"basevideo") == 0 )
                    base_video = 1;
                else if ( wstrcmp(ptr + 1, L"mapbs") == 0 )
                    map_bs = 1;
                else if ( wstrncmp(ptr + 1, L"cfg=", 4) == 0 )
                    cfg_file_name = ptr + 5;
                else if ( i + 1 < argc && wstrcmp(ptr + 1, L"cfg") == 0 )
                    cfg_file_name = argv[++i];
                else if ( wstrcmp(ptr + 1, L"help") == 0 ||
                          (ptr[1] == L'?' && !ptr[2]) )
                {
                    PrintStr(L"Xen EFI Loader options:\r\n");
                    PrintStr(L"-basevideo   retain current video mode\r\n");
                    PrintStr(L"-mapbs       map EfiBootServices{Code,Data}\r\n");
                    PrintStr(L"-cfg=<file>  specify configuration file\r\n");
                    PrintStr(L"-help, -?    display this help\r\n");
                    blexit(NULL);
                }
                else
                {
                    PrintStr(L"WARNING: Unknown command line option '");
                    PrintStr(ptr);
                    PrintStr(L"' ignored\r\n");
                }
            }
            else
                section.w = ptr;
        }

        if ( !base_video )
            efi_console_set_mode();
    }

    PrintStr(L"Xen " __stringify(XEN_VERSION) "." __stringify(XEN_SUBVERSION)
             XEN_EXTRAVERSION " (c/s " XEN_CHANGESET ") EFI loader\r\n");

    efi_arch_relocate_image(0);

    if ( use_cfg_file )
    {
        EFI_FILE_HANDLE dir_handle;
        UINTN depth, cols, rows, size;

        size = cols = rows = depth = 0;

        if ( StdOut->QueryMode(StdOut, StdOut->Mode->Mode,
                               &cols, &rows) == EFI_SUCCESS )
            efi_arch_console_init(cols, rows);

        gop = efi_get_gop();

        /* Get the file system interface. */
        dir_handle = get_parent_handle(loaded_image, &file_name);

        /* Read and parse the config file. */
        if ( !cfg_file_name )
        {
            CHAR16 *tail;

            while ( (tail = point_tail(file_name)) != NULL )
            {
                wstrcpy(tail, L".cfg");
                if ( read_file(dir_handle, file_name, &cfg, NULL) )
                    break;
                *tail = 0;
            }
            if ( !tail )
                blexit(L"No configuration file found.");
            PrintStr(L"Using configuration file '");
            PrintStr(file_name);
            PrintStr(L"'\r\n");
        }
        else if ( !read_file(dir_handle, cfg_file_name, &cfg, NULL) )
            blexit(L"Configuration file not found.");
        pre_parse(&cfg);

        if ( section.w )
            w2s(&section);
        else
            section.s = get_value(&cfg, "global", "default");

        for ( ; ; )
        {
            name.s = get_value(&cfg, section.s, "kernel");
            if ( name.s )
                break;
            name.s = get_value(&cfg, "global", "chain");
            if ( !name.s )
                break;
            efi_bs->FreePages(cfg.addr, PFN_UP(cfg.size));
            cfg.addr = 0;
            if ( !read_file(dir_handle, s2w(&name), &cfg, NULL) )
            {
                PrintStr(L"Chained configuration file '");
                PrintStr(name.w);
                efi_bs->FreePool(name.w);
                blexit(L"'not found.");
            }
            pre_parse(&cfg);
            efi_bs->FreePool(name.w);
        }

        if ( !name.s )
            blexit(L"No Dom0 kernel image specified.");

        efi_arch_cfg_file_early(dir_handle, section.s);

        option_str = split_string(name.s);
        read_file(dir_handle, s2w(&name), &kernel, option_str);
        efi_bs->FreePool(name.w);

        if ( !EFI_ERROR(efi_bs->LocateProtocol(&shim_lock_guid, NULL,
                        (void **)&shim_lock)) &&
             (status = shim_lock->Verify(kernel.ptr, kernel.size)) != EFI_SUCCESS )
            PrintErrMesg(L"Dom0 kernel image could not be verified", status);

        name.s = get_value(&cfg, section.s, "ramdisk");
        if ( name.s )
        {
            read_file(dir_handle, s2w(&name), &ramdisk, NULL);
            efi_bs->FreePool(name.w);
        }

        name.s = get_value(&cfg, section.s, "xsm");
        if ( name.s )
        {
            read_file(dir_handle, s2w(&name), &xsm, NULL);
            efi_bs->FreePool(name.w);
        }

        name.s = get_value(&cfg, section.s, "options");
        efi_arch_handle_cmdline(argc ? *argv : NULL, options, name.s);

        if ( !base_video )
        {
            name.cs = get_value(&cfg, section.s, "video");
            if ( !name.cs )
                name.cs = get_value(&cfg, "global", "video");
            if ( name.cs && !strncmp(name.cs, "gfx-", 4) )
            {
                cols = simple_strtoul(name.cs + 4, &name.cs, 10);
                if ( *name.cs == 'x' )
                    rows = simple_strtoul(name.cs + 1, &name.cs, 10);
                if ( *name.cs == 'x' )
                    depth = simple_strtoul(name.cs + 1, &name.cs, 10);
                if ( *name.cs )
                    cols = rows = depth = 0;
            }
        }

        efi_arch_cfg_file_late(dir_handle, section.s);

        efi_bs->FreePages(cfg.addr, PFN_UP(cfg.size));
        cfg.addr = 0;

        dir_handle->Close(dir_handle);

        if ( gop && !base_video )
            gop_mode = efi_find_gop_mode(gop, cols, rows, depth);
    }

    efi_arch_edd();

    /* XXX Collect EDID info. */
    efi_arch_cpu();

    efi_tables();

    /* Collect PCI ROM contents. */
    setup_efi_pci();

    /* Get snapshot of variable store parameters. */
    efi_variables();

    efi_arch_memory_setup();

    if ( gop )
        efi_set_gop_mode(gop, gop_mode);

    efi_exit_boot(ImageHandle, SystemTable);

    efi_arch_post_exit_boot();
    for( ; ; ); /* not reached */
}

#ifndef CONFIG_ARM /* TODO - runtime service support */

static bool_t __initdata efi_rs_enable = 1;
static bool_t __initdata efi_map_uc;

static void __init parse_efi_param(char *s)
{
    char *ss;

    do {
        bool_t val = !!strncmp(s, "no-", 3);

        if ( !val )
            s += 3;

        ss = strchr(s, ',');
        if ( ss )
            *ss = '\0';

        if ( !strcmp(s, "rs") )
            efi_rs_enable = val;
        else if ( !strcmp(s, "attr=uc") )
            efi_map_uc = val;

        s = ss + 1;
    } while ( ss );
}
custom_param("efi", parse_efi_param);

#ifndef USE_SET_VIRTUAL_ADDRESS_MAP
static __init void copy_mapping(unsigned long mfn, unsigned long end,
                                bool_t (*is_valid)(unsigned long smfn,
                                                   unsigned long emfn))
{
    unsigned long next;

    for ( ; mfn < end; mfn = next )
    {
        l4_pgentry_t l4e = efi_l4_pgtable[l4_table_offset(mfn << PAGE_SHIFT)];
        l3_pgentry_t *l3src, *l3dst;
        unsigned long va = (unsigned long)mfn_to_virt(mfn);

        next = mfn + (1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT));
        if ( !is_valid(mfn, min(next, end)) )
            continue;
        if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        {
            l3dst = alloc_xen_pagetable();
            BUG_ON(!l3dst);
            clear_page(l3dst);
            efi_l4_pgtable[l4_table_offset(mfn << PAGE_SHIFT)] =
                l4e_from_paddr(virt_to_maddr(l3dst), __PAGE_HYPERVISOR);
        }
        else
            l3dst = l4e_to_l3e(l4e);
        l3src = l4e_to_l3e(idle_pg_table[l4_table_offset(va)]);
        l3dst[l3_table_offset(mfn << PAGE_SHIFT)] = l3src[l3_table_offset(va)];
    }
}

static bool_t __init ram_range_valid(unsigned long smfn, unsigned long emfn)
{
    unsigned long sz = pfn_to_pdx(emfn - 1) / PDX_GROUP_COUNT + 1;

    return !(smfn & pfn_hole_mask) &&
           find_next_bit(pdx_group_valid, sz,
                         pfn_to_pdx(smfn) / PDX_GROUP_COUNT) < sz;
}

static bool_t __init rt_range_valid(unsigned long smfn, unsigned long emfn)
{
    return 1;
}
#endif

#define INVALID_VIRTUAL_ADDRESS (0xBAAADUL << \
                                 (EFI_PAGE_SHIFT + BITS_PER_LONG - 32))

void __init efi_init_memory(void)
{
    unsigned int i;
#ifndef USE_SET_VIRTUAL_ADDRESS_MAP
    struct rt_extra {
        struct rt_extra *next;
        unsigned long smfn, emfn;
        unsigned int prot;
    } *extra, *extra_head = NULL;
#endif

    printk(XENLOG_INFO "EFI memory map:%s\n",
           map_bs ? " (mapping BootServices)" : "");
    for ( i = 0; i < efi_memmap_size; i += efi_mdesc_size )
    {
        EFI_MEMORY_DESCRIPTOR *desc = efi_memmap + i;
        u64 len = desc->NumberOfPages << EFI_PAGE_SHIFT;
        unsigned long smfn, emfn;
        unsigned int prot = PAGE_HYPERVISOR_RWX;

        printk(XENLOG_INFO " %013" PRIx64 "-%013" PRIx64
                           " type=%u attr=%016" PRIx64 "\n",
               desc->PhysicalStart, desc->PhysicalStart + len - 1,
               desc->Type, desc->Attribute);

        if ( !efi_rs_enable ||
             (!(desc->Attribute & EFI_MEMORY_RUNTIME) &&
              (!map_bs ||
               (desc->Type != EfiBootServicesCode &&
                desc->Type != EfiBootServicesData))) )
            continue;

        desc->VirtualStart = INVALID_VIRTUAL_ADDRESS;

        smfn = PFN_DOWN(desc->PhysicalStart);
        emfn = PFN_UP(desc->PhysicalStart + len);

        if ( desc->Attribute & EFI_MEMORY_WB )
            /* nothing */;
        else if ( desc->Attribute & EFI_MEMORY_WT )
            prot |= _PAGE_PWT | MAP_SMALL_PAGES;
        else if ( desc->Attribute & EFI_MEMORY_WC )
            prot |= _PAGE_PAT | MAP_SMALL_PAGES;
        else if ( desc->Attribute & (EFI_MEMORY_UC | EFI_MEMORY_UCE) )
            prot |= _PAGE_PWT | _PAGE_PCD | MAP_SMALL_PAGES;
        else if ( efi_bs_revision >= EFI_REVISION(2, 5) &&
                  (desc->Attribute & EFI_MEMORY_WP) )
            prot |= _PAGE_PAT | _PAGE_PWT | MAP_SMALL_PAGES;
        else
        {
            printk(XENLOG_ERR "Unknown cachability for MFNs %#lx-%#lx%s\n",
                   smfn, emfn - 1, efi_map_uc ? ", assuming UC" : "");
            if ( !efi_map_uc )
                continue;
            prot |= _PAGE_PWT | _PAGE_PCD | MAP_SMALL_PAGES;
        }

        if ( desc->Attribute & (efi_bs_revision < EFI_REVISION(2, 5)
                                ? EFI_MEMORY_WP : EFI_MEMORY_RO) )
            prot &= ~_PAGE_RW;
        if ( desc->Attribute & EFI_MEMORY_XP )
            prot |= _PAGE_NX;

        if ( pfn_to_pdx(emfn - 1) < (DIRECTMAP_SIZE >> PAGE_SHIFT) &&
             !(smfn & pfn_hole_mask) &&
             !((smfn ^ (emfn - 1)) & ~pfn_pdx_bottom_mask) )
        {
            if ( (unsigned long)mfn_to_virt(emfn - 1) >= HYPERVISOR_VIRT_END )
                prot &= ~_PAGE_GLOBAL;
            if ( map_pages_to_xen((unsigned long)mfn_to_virt(smfn),
                                  smfn, emfn - smfn, prot) == 0 )
                desc->VirtualStart =
                    (unsigned long)maddr_to_virt(desc->PhysicalStart);
            else
                printk(XENLOG_ERR "Could not map MFNs %#lx-%#lx\n",
                       smfn, emfn - 1);
        }
#ifndef USE_SET_VIRTUAL_ADDRESS_MAP
        else if ( !((desc->PhysicalStart + len - 1) >> (VADDR_BITS - 1)) &&
                  (extra = xmalloc(struct rt_extra)) != NULL )
        {
            extra->smfn = smfn;
            extra->emfn = emfn;
            extra->prot = prot & ~_PAGE_GLOBAL;
            extra->next = extra_head;
            extra_head = extra;
            desc->VirtualStart = desc->PhysicalStart;
        }
#endif
        else
        {
#ifdef USE_SET_VIRTUAL_ADDRESS_MAP
            /* XXX allocate e.g. down from FIXADDR_START */
#endif
            printk(XENLOG_ERR "No mapping for MFNs %#lx-%#lx\n",
                   smfn, emfn - 1);
        }
    }

    if ( !efi_rs_enable )
    {
        efi_fw_vendor = NULL;
        return;
    }

#ifdef USE_SET_VIRTUAL_ADDRESS_MAP
    efi_rs->SetVirtualAddressMap(efi_memmap_size, efi_mdesc_size,
                                 mdesc_ver, efi_memmap);
#else
    /* Set up 1:1 page tables to do runtime calls in "physical" mode. */
    efi_l4_pgtable = alloc_xen_pagetable();
    BUG_ON(!efi_l4_pgtable);
    clear_page(efi_l4_pgtable);

    copy_mapping(0, max_page, ram_range_valid);

    /* Insert non-RAM runtime mappings inside the direct map. */
    for ( i = 0; i < efi_memmap_size; i += efi_mdesc_size )
    {
        const EFI_MEMORY_DESCRIPTOR *desc = efi_memmap + i;

        if ( ((desc->Attribute & EFI_MEMORY_RUNTIME) ||
              (map_bs &&
               (desc->Type == EfiBootServicesCode ||
                desc->Type == EfiBootServicesData))) &&
             desc->VirtualStart != INVALID_VIRTUAL_ADDRESS &&
             desc->VirtualStart != desc->PhysicalStart )
            copy_mapping(PFN_DOWN(desc->PhysicalStart),
                         PFN_UP(desc->PhysicalStart +
                                (desc->NumberOfPages << EFI_PAGE_SHIFT)),
                         rt_range_valid);
    }

    /* Insert non-RAM runtime mappings outside of the direct map. */
    while ( (extra = extra_head) != NULL )
    {
        unsigned long addr = extra->smfn << PAGE_SHIFT;
        l4_pgentry_t l4e = efi_l4_pgtable[l4_table_offset(addr)];
        l3_pgentry_t *pl3e;
        l2_pgentry_t *pl2e;
        l1_pgentry_t *l1t;

        if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        {
            pl3e = alloc_xen_pagetable();
            BUG_ON(!pl3e);
            clear_page(pl3e);
            efi_l4_pgtable[l4_table_offset(addr)] =
                l4e_from_paddr(virt_to_maddr(pl3e), __PAGE_HYPERVISOR);
        }
        else
            pl3e = l4e_to_l3e(l4e);
        pl3e += l3_table_offset(addr);
        if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
        {
            pl2e = alloc_xen_pagetable();
            BUG_ON(!pl2e);
            clear_page(pl2e);
            *pl3e = l3e_from_paddr(virt_to_maddr(pl2e), __PAGE_HYPERVISOR);
        }
        else
        {
            BUG_ON(l3e_get_flags(*pl3e) & _PAGE_PSE);
            pl2e = l3e_to_l2e(*pl3e);
        }
        pl2e += l2_table_offset(addr);
        if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
        {
            l1t = alloc_xen_pagetable();
            BUG_ON(!l1t);
            clear_page(l1t);
            *pl2e = l2e_from_paddr(virt_to_maddr(l1t), __PAGE_HYPERVISOR);
        }
        else
        {
            BUG_ON(l2e_get_flags(*pl2e) & _PAGE_PSE);
            l1t = l2e_to_l1e(*pl2e);
        }
        for ( i = l1_table_offset(addr);
              i < L1_PAGETABLE_ENTRIES && extra->smfn < extra->emfn;
              ++i, ++extra->smfn )
            l1t[i] = l1e_from_pfn(extra->smfn, extra->prot);

        if ( extra->smfn == extra->emfn )
        {
            extra_head = extra->next;
            xfree(extra);
        }
    }

    /* Insert Xen mappings. */
    for ( i = l4_table_offset(HYPERVISOR_VIRT_START);
          i < l4_table_offset(DIRECTMAP_VIRT_END); ++i )
        efi_l4_pgtable[i] = idle_pg_table[i];
#endif
}
#endif
