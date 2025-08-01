#include "efi.h"
#include <efi/efiprot.h>
#include <efi/efipciio.h>
#include <public/xen.h>
#include <xen/bitops.h>
#include <xen/compile.h>
#include <xen/ctype.h>
#include <xen/dmi.h>
#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/keyhandler.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/multiboot.h>
#include <xen/param.h>
#include <xen/pci_regs.h>
#include <xen/pdx.h>
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

#define EFI_REVISION(major, minor) (((major) << 16) | (minor))

#define SMBIOS3_TABLE_GUID \
  { 0xf2fd1544U, 0x9794, 0x4a2c, {0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94} }
#define SHIM_LOCK_PROTOCOL_GUID \
  { 0x605dab50U, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23} }
#define APPLE_PROPERTIES_PROTOCOL_GUID \
  { 0x91bd12feU, 0xf6c3, 0x44fb, {0xa5, 0xb7, 0x51, 0x22, 0xab, 0x30, 0x3a, 0xe0} }
#define EFI_SYSTEM_RESOURCE_TABLE_GUID    \
  { 0xb122a263U, 0x3661, 0x4f68, {0x99, 0x29, 0x78, 0xf8, 0xb0, 0xd6, 0x21, 0x80} }
#define EFI_SYSTEM_RESOURCE_TABLE_FIRMWARE_RESOURCE_VERSION 1

typedef struct {
    EFI_GUID FwClass;
    UINT32 FwType;
    UINT32 FwVersion;
    UINT32 LowestSupportedFwVersion;
    UINT32 CapsuleFlags;
    UINT32 LastAttemptVersion;
    UINT32 LastAttemptStatus;
} EFI_SYSTEM_RESOURCE_ENTRY;

typedef struct {
    UINT32 FwResourceCount;
    UINT32 FwResourceCountMax;
    UINT64 FwResourceVersion;
    EFI_SYSTEM_RESOURCE_ENTRY Entries[];
} EFI_SYSTEM_RESOURCE_TABLE;

typedef EFI_STATUS
(/* _not_ EFIAPI */ *EFI_SHIM_LOCK_VERIFY) (
    IN const VOID *Buffer,
    IN UINT32 Size);

typedef struct {
    EFI_SHIM_LOCK_VERIFY Verify;
} EFI_SHIM_LOCK_PROTOCOL;

struct _EFI_APPLE_PROPERTIES;

typedef EFI_STATUS
(EFIAPI *EFI_APPLE_PROPERTIES_GET) (
    IN struct _EFI_APPLE_PROPERTIES *This,
    IN const EFI_DEVICE_PATH *Device,
    IN const CHAR16 *PropertyName,
    OUT VOID *Buffer,
    IN OUT UINT32 *BufferSize);

typedef EFI_STATUS
(EFIAPI *EFI_APPLE_PROPERTIES_SET) (
    IN struct _EFI_APPLE_PROPERTIES *This,
    IN const EFI_DEVICE_PATH *Device,
    IN const CHAR16 *PropertyName,
    IN const VOID *Value,
    IN UINT32 ValueLen);

typedef EFI_STATUS
(EFIAPI *EFI_APPLE_PROPERTIES_DELETE) (
    IN struct _EFI_APPLE_PROPERTIES *This,
    IN const EFI_DEVICE_PATH *Device,
    IN const CHAR16 *PropertyName);

typedef EFI_STATUS
(EFIAPI *EFI_APPLE_PROPERTIES_GETALL) (
    IN struct _EFI_APPLE_PROPERTIES *This,
    OUT VOID *Buffer,
    IN OUT UINT32 *BufferSize);

typedef struct _EFI_APPLE_PROPERTIES {
    UINTN Version; /* 0x10000 */
    EFI_APPLE_PROPERTIES_GET Get;
    EFI_APPLE_PROPERTIES_SET Set;
    EFI_APPLE_PROPERTIES_DELETE Delete;
    EFI_APPLE_PROPERTIES_GETALL GetAll;
} EFI_APPLE_PROPERTIES;

typedef struct _EFI_LOAD_OPTION {
    UINT32 Attributes;
    UINT16 FilePathListLength;
    CHAR16 Description[];
} EFI_LOAD_OPTION;

#define LOAD_OPTION_ACTIVE              0x00000001

union string {
    CHAR16 *w;
    char *s;
    const char *cs;
};

struct file {
    UINTN size;
    bool need_to_free;
    union {
        EFI_PHYSICAL_ADDRESS addr;
        char *str;
        const void *ptr;
    };
};

static bool read_file(EFI_FILE_HANDLE dir_handle, CHAR16 *name,
                      struct file *file, const char *options);
static bool read_section(const EFI_LOADED_IMAGE *image, const CHAR16 *name,
                         struct file *file, const char *options);

static void efi_init(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable);
static void efi_console_set_mode(void);
static EFI_GRAPHICS_OUTPUT_PROTOCOL *efi_get_gop(EFI_HANDLE *gop_handle);
static UINTN efi_find_gop_mode(EFI_GRAPHICS_OUTPUT_PROTOCOL *gop,
                               UINTN cols, UINTN rows, UINTN depth);
static void efi_tables(void);
static void setup_efi_pci(void);
static void efi_variables(void);
static void efi_set_gop_mode(EFI_GRAPHICS_OUTPUT_PROTOCOL *gop, UINTN gop_mode);
static void efi_exit_boot(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable);

static const EFI_BOOT_SERVICES *__initdata efi_bs;
static UINT32 __initdata efi_bs_revision;
static EFI_HANDLE __initdata efi_ih;

static SIMPLE_TEXT_OUTPUT_INTERFACE *__initdata StdOut;
static SIMPLE_TEXT_OUTPUT_INTERFACE *__initdata StdErr;

static UINT32 __initdata mdesc_ver;
static bool __initdata map_bs;

static struct file __initdata cfg;
static struct file __initdata kernel;
static struct file __initdata ramdisk;
static struct file __initdata xsm;
static const CHAR16 __initconst newline[] = L"\r\n";

static void __init PrintStr(const CHAR16 *s)
{
    StdOut->OutputString(StdOut, (CHAR16 *)s );
}

static void __init PrintErr(const CHAR16 *s)
{
    StdErr->OutputString(StdErr, (CHAR16 *)s );
}

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

static bool __init match_guid(const EFI_GUID *guid1, const EFI_GUID *guid2)
{
    return guid1->Data1 == guid2->Data1 &&
           guid1->Data2 == guid2->Data2 &&
           guid1->Data3 == guid2->Data3 &&
           !memcmp(guid1->Data4, guid2->Data4, sizeof(guid1->Data4));
}

/* generic routine for printing error messages */
static void __init noreturn PrintErrMesg(const CHAR16 *mesg, EFI_STATUS ErrCode)
{
    StdOut = StdErr;
    PrintErr(mesg);
    PrintErr(L": ");

    switch (ErrCode)
    {
    case EFI_NOT_FOUND:
        mesg = L"Not found";
        break;
    case EFI_NO_MEDIA:
        mesg = L"The device has no media";
        break;
    case EFI_MEDIA_CHANGED:
        mesg = L"Media changed";
        break;
    case EFI_DEVICE_ERROR:
        mesg = L"Device error";
        break;
    case EFI_VOLUME_CORRUPTED:
        mesg = L"Volume corrupted";
        break;
    case EFI_ACCESS_DENIED:
        mesg = L"Access denied";
        break;
    case EFI_OUT_OF_RESOURCES:
        mesg = L"Out of resources";
        break;
    case EFI_VOLUME_FULL:
        mesg = L"Volume is full";
        break;
    case EFI_SECURITY_VIOLATION:
        mesg = L"Security violation";
        break;
    case EFI_CRC_ERROR:
        mesg = L"CRC error";
        break;
    case EFI_COMPROMISED_DATA:
        mesg = L"Compromised data";
        break;
    case EFI_BUFFER_TOO_SMALL:
        mesg = L"Buffer too small";
        break;
    case EFI_INVALID_PARAMETER:
        mesg = L"Invalid parameter";
        break;
    default:
        PrintErr(L"ErrCode: ");
        DisplayUint(ErrCode, 0);
        mesg = NULL;
        break;
    }
    blexit(mesg);
}

static unsigned int __init get_argv(unsigned int argc, CHAR16 **argv,
                                    VOID *data, UINTN size, UINTN *offset,
                                    CHAR16 **options)
{
    CHAR16 *ptr = (CHAR16 *)(argv + argc + 1), *prev = NULL, *cmdline = NULL;
    bool prev_sep = true;

    if ( argc )
    {
        cmdline = data + *offset;
        /* EFI_LOAD_OPTION does not supply an image name as first component. */
        if ( *offset )
            *argv++ = NULL;
    }
    else if ( size > sizeof(*cmdline) && !(size % sizeof(*cmdline)) &&
              (wmemchr(data, 0, size / sizeof(*cmdline)) ==
               data + size - sizeof(*cmdline)) )
    {
        /* Plain command line, as usually passed by the EFI shell. */
        *offset = 0;
        cmdline = data;
    }
    else if ( size > sizeof(EFI_LOAD_OPTION) )
    {
        const EFI_LOAD_OPTION *elo = data;
        /* The minimum size the buffer needs to be. */
        size_t elo_min = offsetof(EFI_LOAD_OPTION, Description[1]) +
                         elo->FilePathListLength;

        if ( (elo->Attributes & LOAD_OPTION_ACTIVE) && size > elo_min &&
             !((size - elo_min) % sizeof(*cmdline)) )
        {
            const CHAR16 *desc = elo->Description;
            const CHAR16 *end = wmemchr(desc, 0,
                                        (size - elo_min) / sizeof(*desc) + 1);

            if ( end )
            {
                *offset = elo_min + (end - desc) * sizeof(*desc);
                if ( (size -= *offset) > sizeof(*cmdline) )
                {
                    cmdline = data + *offset;
                    /* Cater for the image name as first component. */
                    ++argc;
                }
            }
        }
    }

    if ( !cmdline )
        return 0;

    for ( ; size > sizeof(*cmdline) && *cmdline;
            size -= sizeof(*cmdline), ++cmdline )
    {
        bool cur_sep = *cmdline == L' ' || *cmdline == L'\t';

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

static EFI_FILE_HANDLE __init get_parent_handle(const EFI_LOADED_IMAGE *loaded_image,
                                                CHAR16 **leaf)
{
    static EFI_GUID __initdata fs_protocol = SIMPLE_FILE_SYSTEM_PROTOCOL;
    static CHAR16 __initdata buffer[512];
    EFI_FILE_HANDLE dir_handle;
    EFI_DEVICE_PATH *dp;
    CHAR16 *pathend, *ptr;
    EFI_STATUS ret;

    /*
     * In some cases the image could not come from a specific device.
     * For instance this can happen if Xen was loaded using GRUB2 "linux"
     * command.
     */
    *leaf = NULL;
    if ( !loaded_image->DeviceHandle )
    {
        PrintStr(L"Xen image loaded without providing a device\r\n");
        return NULL;
    }

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

#define BUFFERSIZE sizeof(buffer)
    for ( dp = loaded_image->FilePath, *buffer = 0;
          DevicePathType(dp) != END_DEVICE_PATH_TYPE;
          dp = (void *)dp + DevicePathNodeLength(dp) )
    {
        FILEPATH_DEVICE_PATH *fp;

        if ( DevicePathType(dp) != MEDIA_DEVICE_PATH ||
             DevicePathSubType(dp) != MEDIA_FILEPATH_DP )
        {
            /*
             * The image could come from an unsupported device.
             * For instance this can happen if Xen was loaded using GRUB2
             * "chainloader" command and the file was not from ESP.
             */
            PrintStr(L"Unsupported device path component\r\n");
            return NULL;
        }

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

static char *__init get_value(const struct file *file, const char *section,
                              const char *item)
{
    char *ptr = file->str, *end = ptr + file->size;
    size_t slen = section ? strlen(section) : 0, ilen = strlen(item);
    bool match = !slen;

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

static int __init __maybe_unused set_color(uint32_t mask, int bpp,
                                           uint8_t *pos, uint8_t *sz)
{
   if ( bpp < 0 )
       return bpp;
   if ( !mask )
       return -EINVAL;
   for ( *pos = 0; !(mask & 1); ++*pos )
       mask >>= 1;
   for ( *sz = 0; mask & 1; ++*sz)
       mask >>= 1;
   if ( mask )
       return -EINVAL;
   return max(*pos + *sz, bpp);
}

#ifndef CONFIG_HAS_DEVICE_TREE_DISCOVERY
static int __init efi_check_dt_boot(const EFI_LOADED_IMAGE *loaded_image)
{
    return 0;
}
#endif

static UINTN __initdata esrt = EFI_INVALID_TABLE_ADDR;

static size_t __init get_esrt_size(const EFI_MEMORY_DESCRIPTOR *desc)
{
    size_t available_len, len;
    const UINTN physical_start = desc->PhysicalStart;
    const EFI_SYSTEM_RESOURCE_TABLE *esrt_ptr;

    len = desc->NumberOfPages << EFI_PAGE_SHIFT;
    if ( esrt == EFI_INVALID_TABLE_ADDR )
        return 0;
    if ( physical_start > esrt || esrt - physical_start >= len )
        return 0;
    /*
     * The specification requires EfiBootServicesData, but also accept
     * EfiRuntimeServicesData (for compatibility with buggy firmware)
     * and EfiACPIReclaimMemory (which will contain the tables after
     * successful kexec).
     */
    if ( (desc->Type != EfiRuntimeServicesData) &&
         (desc->Type != EfiBootServicesData) &&
         (desc->Type != EfiACPIReclaimMemory) )
        return 0;
    available_len = len - (esrt - physical_start);
    if ( available_len <= offsetof(EFI_SYSTEM_RESOURCE_TABLE, Entries) )
        return 0;
    available_len -= offsetof(EFI_SYSTEM_RESOURCE_TABLE, Entries);
    esrt_ptr = (const EFI_SYSTEM_RESOURCE_TABLE *)esrt;
    if ( (esrt_ptr->FwResourceVersion !=
          EFI_SYSTEM_RESOURCE_TABLE_FIRMWARE_RESOURCE_VERSION) ||
         !esrt_ptr->FwResourceCount )
        return 0;
    if ( esrt_ptr->FwResourceCount > available_len / sizeof(esrt_ptr->Entries[0]) )
        return 0;

    return esrt_ptr->FwResourceCount * sizeof(esrt_ptr->Entries[0]);
}

static EFI_GUID __initdata esrt_guid = EFI_SYSTEM_RESOURCE_TABLE_GUID;

static void __init efi_relocate_esrt(EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS status;
    UINTN info_size = 0, map_key, mdesc_size;
    void *memory_map = NULL;
    UINT32 ver;
    unsigned int i;

    for ( ; ; )
    {
        status = efi_bs->GetMemoryMap(&info_size, memory_map, &map_key,
                                      &mdesc_size, &ver);
        if ( status == EFI_SUCCESS && memory_map != NULL )
            break;
        if ( status == EFI_BUFFER_TOO_SMALL || memory_map == NULL )
        {
            info_size += 8 * mdesc_size;
            if ( memory_map != NULL )
                efi_bs->FreePool(memory_map);
            memory_map = NULL;
            status = efi_bs->AllocatePool(EfiLoaderData, info_size, &memory_map);
            if ( status == EFI_SUCCESS )
                continue;
            PrintErr(L"Cannot allocate memory to relocate ESRT\r\n");
        }
        else
            PrintErr(L"Cannot obtain memory map to relocate ESRT\r\n");
        return;
    }

    /* Try to obtain the ESRT.  Errors are not fatal. */
    for ( i = 0; i < info_size; i += mdesc_size )
    {
        /*
         * ESRT needs to be moved to memory of type EfiACPIReclaimMemory
         * so that the memory it is in will not be used for other purposes.
         */
        void *new_esrt = NULL;
        const EFI_MEMORY_DESCRIPTOR *desc = memory_map + i;
        size_t esrt_size = get_esrt_size(desc);

        if ( !esrt_size )
            continue;
        if ( desc->Type == EfiRuntimeServicesData ||
             desc->Type == EfiACPIReclaimMemory )
            break; /* ESRT already safe from reuse */
        status = efi_bs->AllocatePool(EfiACPIReclaimMemory, esrt_size,
                                      &new_esrt);
        if ( status == EFI_SUCCESS && new_esrt )
        {
            memcpy(new_esrt, (void *)esrt, esrt_size);
            status = efi_bs->InstallConfigurationTable(&esrt_guid, new_esrt);
            if ( status != EFI_SUCCESS )
            {
                PrintErr(L"Cannot install new ESRT\r\n");
                efi_bs->FreePool(new_esrt);
            }
        }
        else
            PrintErr(L"Cannot allocate memory for ESRT\r\n");
        break;
    }

    efi_bs->FreePool(memory_map);
}

/*
 * Include architecture specific implementation here, which references the
 * static globals defined above.
 */
#include "efi-boot.h"

void __init noreturn blexit(const CHAR16 *str)
{
    if ( str )
        PrintStr(str);
    PrintStr(newline);

    if ( !efi_bs )
        efi_arch_halt();

    if ( cfg.need_to_free )
        efi_bs->FreePages(cfg.addr, PFN_UP(cfg.size));
    if ( kernel.need_to_free )
        efi_bs->FreePages(kernel.addr, PFN_UP(kernel.size));
    if ( ramdisk.need_to_free )
        efi_bs->FreePages(ramdisk.addr, PFN_UP(ramdisk.size));
    if ( xsm.need_to_free )
        efi_bs->FreePages(xsm.addr, PFN_UP(xsm.size));

    efi_arch_blexit();

    efi_bs->Exit(efi_ih, EFI_SUCCESS, 0, NULL);
    unreachable(); /* not reached */
}

static void __init handle_file_info(const CHAR16 *name,
                                    const struct file *file, const char *options)
{
    if ( file == &cfg )
        return;

    PrintStr(name);
    PrintStr(L": ");
    DisplayUint(file->addr, 2 * sizeof(file->addr));
    PrintStr(L"-");
    DisplayUint(file->addr + file->size, 2 * sizeof(file->addr));
    PrintStr(newline);

    efi_arch_handle_module(file, name, options);
}

static bool __init read_file(EFI_FILE_HANDLE dir_handle, CHAR16 *name,
                             struct file *file, const char *options)
{
    EFI_FILE_HANDLE FileHandle = NULL;
    UINT64 size;
    EFI_STATUS ret;
    const CHAR16 *what = NULL;

    if ( !name )
        PrintErrMesg(L"No filename", EFI_OUT_OF_RESOURCES);

    what = L"Open";
    if ( dir_handle )
        ret = dir_handle->Open(dir_handle, &FileHandle, name,
                               EFI_FILE_MODE_READ, 0);
    else
        ret = EFI_NOT_FOUND;
    if ( file == &cfg && ret == EFI_NOT_FOUND )
        return false;
    if ( EFI_ERROR(ret) )
        goto fail;

    what = L"Seek";
    ret = FileHandle->SetPosition(FileHandle, -1);
    if ( EFI_ERROR(ret) )
        goto fail;

    what = L"Get size";
    ret = FileHandle->GetPosition(FileHandle, &size);
    if ( EFI_ERROR(ret) )
        goto fail;

    what = L"Seek";
    ret = FileHandle->SetPosition(FileHandle, 0);
    if ( EFI_ERROR(ret) )
        goto fail;

    what = L"Allocation";
    file->addr = min(1UL << (32 + PAGE_SHIFT),
                     HYPERVISOR_VIRT_END - DIRECTMAP_VIRT_START);
    ret = efi_bs->AllocatePages(AllocateMaxAddress, EfiLoaderData,
                                PFN_UP(size), &file->addr);
    if ( EFI_ERROR(ret) )
        goto fail;

    file->need_to_free = true;
    file->size = size;
    handle_file_info(name, file, options);

    what = L"Read";
    ret = FileHandle->Read(FileHandle, &file->size, file->str);
    if ( !EFI_ERROR(ret) && file->size != size )
        ret = EFI_ABORTED;
    if ( EFI_ERROR(ret) )
        goto fail;

    FileHandle->Close(FileHandle);

    efi_arch_flush_dcache_area(file->ptr, file->size);

    return true;

 fail:
    if ( FileHandle )
        FileHandle->Close(FileHandle);

    PrintErr(what);
    PrintErr(L" failed for ");
    PrintErrMesg(name, ret);

    /* not reached */
    return false;
}

static bool __init read_section(const EFI_LOADED_IMAGE *image,
                                const CHAR16 *name, struct file *file,
                                const char *options)
{
    const void *ptr = pe_find_section(image->ImageBase, image->ImageSize,
                                      name, &file->size);

    if ( !ptr )
        return false;

    file->ptr = ptr;

    handle_file_info(name, file, options);

    return true;
}

static void __init pre_parse(const struct file *file)
{
    char *ptr = file->str, *end = ptr + file->size;
    bool start = true, comment = false;

    for ( ; ptr < end; ++ptr )
    {
        if ( iscntrl(*ptr) )
        {
            comment = false;
            start = true;
            *ptr = 0;
        }
        else if ( comment || (start && isspace(*ptr)) )
            *ptr = 0;
        else if ( *ptr == '#' || (start && *ptr == ';') )
        {
            comment = true;
            *ptr = 0;
        }
        else
            start = 0;
    }
    if ( file->size && end[-1] )
         PrintStr(L"No newline at end of config file,"
                   " last line will be ignored.\r\n");
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

static EFI_GRAPHICS_OUTPUT_PROTOCOL __init *efi_get_gop(EFI_HANDLE *gop_handle)
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
        {
            *gop_handle = handles[i];
            break;
        }
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
             (UINTN)mode_info->HorizontalResolution *
             mode_info->VerticalResolution > size )
        {
            size = (UINTN)mode_info->HorizontalResolution *
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
            efi.acpi20 = (unsigned long)efi_ct[i].VendorTable;
        if ( match_guid(&acpi_guid, &efi_ct[i].VendorGuid) )
            efi.acpi = (unsigned long)efi_ct[i].VendorTable;
        if ( match_guid(&mps_guid, &efi_ct[i].VendorGuid) )
            efi.mps = (unsigned long)efi_ct[i].VendorTable;
        if ( match_guid(&smbios_guid, &efi_ct[i].VendorGuid) )
            efi.smbios = (unsigned long)efi_ct[i].VendorTable;
        if ( match_guid(&smbios3_guid, &efi_ct[i].VendorGuid) )
            efi.smbios3 = (unsigned long)efi_ct[i].VendorTable;
        if ( match_guid(&esrt_guid, &efi_ct[i].VendorGuid) )
            esrt = (UINTN)efi_ct[i].VendorTable;
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

static void __init efi_get_apple_properties(void)
{
    static EFI_GUID __initdata props_guid = APPLE_PROPERTIES_PROTOCOL_GUID;
    EFI_APPLE_PROPERTIES *props;
    UINT32 size = 0;
    VOID *data;
    EFI_STATUS status;

    if ( efi_bs->LocateProtocol(&props_guid, NULL,
                                (void **)&props) != EFI_SUCCESS )
        return;
    if ( props->Version != 0x10000 )
    {
        PrintStr(L"Warning: Unsupported Apple device properties version: ");
        DisplayUint(props->Version, 0);
        PrintStr(newline);
        return;
    }

    props->GetAll(props, NULL, &size);
    if ( !size ||
         efi_bs->AllocatePool(EfiRuntimeServicesData, size,
                              &data) != EFI_SUCCESS )
        return;

    status = props->GetAll(props, data, &size);
    if ( status == EFI_SUCCESS )
    {
        efi_apple_properties_addr = (UINTN)data;
        efi_apple_properties_len = size;
    }
    else
    {
        efi_bs->FreePool(data);
        PrintStr(L"Warning: Could not query Apple device properties: ");
        DisplayUint(status, 0);
        PrintStr(newline);
    }
}

static void __init efi_set_gop_mode(EFI_GRAPHICS_OUTPUT_PROTOCOL *gop, UINTN gop_mode)
{
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode_info;
    EFI_STATUS status;
    UINTN info_size;

    /*
     * Set graphics mode to a selected one and reset it if we didn't come
     * directly from EFI loader as video settings might have been already modified.
     */
    if ( gop_mode < gop->Mode->MaxMode &&
         (gop_mode != gop->Mode->Mode || !efi_enabled(EFI_LOADER)) )
        gop->SetMode(gop, gop_mode);

    /* Get graphics and frame buffer info. */
    status = gop->QueryMode(gop, gop->Mode->Mode, &info_size, &mode_info);
    if ( !EFI_ERROR(status) )
        efi_arch_video_init(gop, info_size, mode_info);
}

#define INVALID_VIRTUAL_ADDRESS (0xBAAADUL << \
                                 (EFI_PAGE_SHIFT + BITS_PER_LONG - 32))

static void __init efi_exit_boot(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS status;
    UINTN info_size = 0, map_key;
    bool retry;
#ifdef CONFIG_EFI_SET_VIRTUAL_ADDRESS_MAP
    unsigned int i;
#endif

    efi_bs->GetMemoryMap(&info_size, NULL, &map_key,
                         &efi_mdesc_size, &mdesc_ver);
    info_size += 8 * efi_mdesc_size;
    efi_memmap = efi_arch_allocate_mmap_buffer(info_size);
    if ( !efi_memmap )
        blexit(L"Unable to allocate memory for EFI memory map");

    for ( retry = false; ; retry = true )
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

#ifdef CONFIG_EFI_SET_VIRTUAL_ADDRESS_MAP
    for ( i = 0; i < efi_memmap_size; i += efi_mdesc_size )
    {
        EFI_MEMORY_DESCRIPTOR *desc = efi_memmap + i;

        /*
         * Runtime services regions are always mapped here.
         * Attributes may be adjusted in efi_init_memory().
         */
        if ( (desc->Attribute & EFI_MEMORY_RUNTIME) ||
             desc->Type == EfiRuntimeServicesCode ||
             desc->Type == EfiRuntimeServicesData )
            desc->VirtualStart = desc->PhysicalStart;
        else
            desc->VirtualStart = INVALID_VIRTUAL_ADDRESS;
    }
    status = efi_rs->SetVirtualAddressMap(efi_memmap_size, efi_mdesc_size,
                                          mdesc_ver, efi_memmap);
    if ( status != EFI_SUCCESS )
    {
        printk(XENLOG_ERR "EFI: SetVirtualAddressMap() failed (%#lx), disabling runtime services\n",
               status);
        __clear_bit(EFI_RS, &efi_flags);
    }
#endif

    /* Adjust pointers into EFI. */
    efi_ct = (const void *)efi_ct + DIRECTMAP_VIRT_START;
    efi_rs = (const void *)efi_rs + DIRECTMAP_VIRT_START;
    efi_memmap = (void *)efi_memmap + DIRECTMAP_VIRT_START;
    efi_fw_vendor = (const void *)efi_fw_vendor + DIRECTMAP_VIRT_START;
}

/* SAF-1-safe */
void EFIAPI __init noreturn efi_start(EFI_HANDLE ImageHandle,
                                      EFI_SYSTEM_TABLE *SystemTable)
{
    static EFI_GUID __initdata loaded_image_guid = LOADED_IMAGE_PROTOCOL;
    static EFI_GUID __initdata shim_lock_guid = SHIM_LOCK_PROTOCOL_GUID;
    EFI_LOADED_IMAGE *loaded_image;
    EFI_STATUS status;
    unsigned int i;
    CHAR16 *file_name, *cfg_file_name = NULL, *options = NULL;
    UINTN gop_mode = ~0;
    EFI_SHIM_LOCK_PROTOCOL *shim_lock;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = NULL;
    union string section = { NULL }, name;
    bool base_video = false;
    const char *option_str;
    bool use_cfg_file;
    bool kernel_verified = false;
    int dt_modules_found;

    __set_bit(EFI_BOOT, &efi_flags);
    __set_bit(EFI_LOADER, &efi_flags);

#ifndef CONFIG_ARM /* Disabled until runtime services implemented. */
    __set_bit(EFI_RS, &efi_flags);
#endif

    efi_init(ImageHandle, SystemTable);

    use_cfg_file = efi_arch_use_config_file(SystemTable);

    status = efi_bs->HandleProtocol(ImageHandle, &loaded_image_guid,
                                    (void **)&loaded_image);
    if ( status != EFI_SUCCESS )
        PrintErrMesg(L"No Loaded Image Protocol", status);

    efi_arch_load_addr_check(loaded_image);

    if ( use_cfg_file )
    {
        unsigned int argc;
        CHAR16 **argv;
        UINTN offset = 0;

        argc = get_argv(0, NULL, loaded_image->LoadOptions,
                        loaded_image->LoadOptionsSize, &offset, NULL);
        if ( argc > 0 &&
             efi_bs->AllocatePool(EfiLoaderData,
                                  (argc + 1) * sizeof(*argv) +
                                      loaded_image->LoadOptionsSize,
                                  (void **)&argv) == EFI_SUCCESS )
            get_argv(argc, argv, loaded_image->LoadOptions,
                     loaded_image->LoadOptionsSize, &offset, &options);
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
                    base_video = true;
                else if ( wstrcmp(ptr + 1, L"mapbs") == 0 )
                    map_bs = true;
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

    PrintStr(L"Xen " XEN_VERSION_STRING XEN_EXTRAVERSION
	     " (c/s " XEN_CHANGESET ") EFI loader\r\n");

    efi_arch_relocate_image(0);

    if ( use_cfg_file )
    {
        EFI_FILE_HANDLE dir_handle;
        EFI_HANDLE gop_handle;
        UINTN depth, cols, rows;

        cols = rows = depth = 0;

        if ( StdOut->QueryMode(StdOut, StdOut->Mode->Mode,
                               &cols, &rows) == EFI_SUCCESS )
            efi_arch_console_init(cols, rows);

        gop = efi_get_gop(&gop_handle);

        /* Get the file system interface. */
        dir_handle = get_parent_handle(loaded_image, &file_name);

        /* Read and parse the config file. */
        if ( read_section(loaded_image, L"config", &cfg, NULL) )
            PrintStr(L"Using builtin config file\r\n");
        else if ( !cfg_file_name && file_name )
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
            if ( cfg.need_to_free )
            {
                efi_bs->FreePages(cfg.addr, PFN_UP(cfg.size));
                cfg.need_to_free = false;
            }
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

        efi_arch_cfg_file_early(loaded_image, dir_handle, section.s);

        option_str = name.s ? split_string(name.s) : NULL;

        if ( !read_section(loaded_image, L"kernel", &kernel, option_str) &&
             name.s )
        {
            read_file(dir_handle, s2w(&name), &kernel, option_str);
            efi_bs->FreePool(name.w);
        }
        else
        {
            /* Kernel was embedded so Xen signature includes it. */
            kernel_verified = true;
        }

        if ( !read_section(loaded_image, L"ramdisk", &ramdisk, NULL) )
        {
            name.s = get_value(&cfg, section.s, "ramdisk");
            if ( name.s )
            {
                read_file(dir_handle, s2w(&name), &ramdisk, NULL);
                efi_bs->FreePool(name.w);
            }
        }

        if ( !read_section(loaded_image, L"xsm", &xsm, NULL) )
        {
            name.s = get_value(&cfg, section.s, "xsm");
            if ( name.s )
            {
                read_file(dir_handle, s2w(&name), &xsm, NULL);
                efi_bs->FreePool(name.w);
            }
        }

        name.s = get_value(&cfg, section.s, "options");
        efi_arch_handle_cmdline(options, name.s);

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

        efi_arch_cfg_file_late(loaded_image, dir_handle, section.s);

        efi_bs->FreePages(cfg.addr, PFN_UP(cfg.size));
        cfg.addr = 0;

        if ( dir_handle )
            dir_handle->Close(dir_handle);

        if ( gop && !base_video )
        {
            gop_mode = efi_find_gop_mode(gop, cols, rows, depth);

            efi_arch_edid(gop_handle);
        }
    }

    /* Get the number of boot modules specified on the DT or an error (<0) */
    dt_modules_found = efi_check_dt_boot(loaded_image);

    if ( dt_modules_found < 0 )
        /* efi_check_dt_boot throws some error */
        blexit(L"Error processing boot modules on DT.");

    /* Check if at least one of Dom0 or DomU(s) is specified */
    if ( !dt_modules_found && !kernel.ptr )
        blexit(L"No initial domain kernel specified.");

    /*
     * The Dom0 kernel can be loaded from the configuration file or by the
     * device tree through the efi_check_dt_boot function, in this stage
     * verify it.
     */
    if ( kernel.ptr &&
         !kernel_verified &&
         !EFI_ERROR(efi_bs->LocateProtocol(&shim_lock_guid, NULL,
                                           (void **)&shim_lock)) &&
         (status = shim_lock->Verify(kernel.ptr, kernel.size)) != EFI_SUCCESS )
        PrintErrMesg(L"Dom0 kernel image could not be verified", status);

    efi_arch_edd();

    efi_arch_cpu();

    efi_tables();

    /* Collect PCI ROM contents. */
    setup_efi_pci();

    /* Get snapshot of variable store parameters. */
    efi_variables();

    /* Collect Apple device properties, if any. */
    efi_get_apple_properties();

    efi_arch_memory_setup();

    if ( gop )
        efi_set_gop_mode(gop, gop_mode);

    efi_relocate_esrt(SystemTable);

    efi_exit_boot(ImageHandle, SystemTable);

    efi_arch_post_exit_boot(); /* Doesn't return. */
}

#ifndef CONFIG_ARM /* TODO - runtime service support */

#include <asm/spec_ctrl.h>

static bool __initdata efi_map_uc;

static int __init cf_check parse_efi_param(const char *s)
{
    const char *ss;
    int rc = 0, val;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_boolean("rs", s, ss)) >= 0 )
        {
            if ( val )
                __set_bit(EFI_RS, &efi_flags);
            else
                __clear_bit(EFI_RS, &efi_flags);
        }
        else if ( (ss - s) > 5 && !memcmp(s, "attr=", 5) )
        {
            if ( !cmdline_strcmp(s + 5, "uc") )
                efi_map_uc = true;
            else if ( !cmdline_strcmp(s + 5, "no") )
                efi_map_uc = false;
            else
                rc = -EINVAL;
        }
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("efi", parse_efi_param);

static __init void copy_mapping(unsigned long mfn, unsigned long end,
                                bool (*is_valid)(unsigned long smfn,
                                                 unsigned long emfn),
                                l4_pgentry_t *efi_l4t)
{
    unsigned long next;
    l3_pgentry_t *l3src = NULL, *l3dst = NULL;

    for ( ; mfn < end; mfn = next )
    {
        l4_pgentry_t l4e = efi_l4t[l4_table_offset(mfn << PAGE_SHIFT)];
        unsigned long va = (unsigned long)mfn_to_virt(mfn);

        if ( !(mfn & ((1UL << (L4_PAGETABLE_SHIFT - PAGE_SHIFT)) - 1)) )
            UNMAP_DOMAIN_PAGE(l3dst);
        if ( !(va & ((1UL << L4_PAGETABLE_SHIFT) - 1)) )
            UNMAP_DOMAIN_PAGE(l3src);
        next = mfn + (1UL << (L3_PAGETABLE_SHIFT - PAGE_SHIFT));
        if ( !is_valid(mfn, min(next, end)) )
            continue;

        if ( l3dst )
            /* nothing */;
        else if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        {
            mfn_t l3mfn;

            l3dst = alloc_mapped_pagetable(&l3mfn);
            BUG_ON(!l3dst);
            efi_l4t[l4_table_offset(mfn << PAGE_SHIFT)] =
                l4e_from_mfn(l3mfn, __PAGE_HYPERVISOR);
        }
        else
            l3dst = map_l3t_from_l4e(l4e);

        if ( !l3src )
            l3src = map_l3t_from_l4e(idle_pg_table[l4_table_offset(va)]);
        l3dst[l3_table_offset(mfn << PAGE_SHIFT)] = l3src[l3_table_offset(va)];
    }

    unmap_domain_page(l3src);
    unmap_domain_page(l3dst);
}

static bool __init cf_check ram_range_valid(unsigned long smfn, unsigned long emfn)
{
    paddr_t ram_base = pfn_to_paddr(smfn);
    unsigned long ram_npages = emfn - smfn;
    unsigned long sz = pfn_to_pdx(emfn - 1) / PDX_GROUP_COUNT + 1;

    return pdx_is_region_compressible(ram_base, ram_npages) &&
           find_next_bit(pdx_group_valid, sz,
                         pfn_to_pdx(smfn) / PDX_GROUP_COUNT) < sz;
}

static bool __init cf_check rt_range_valid(unsigned long smfn, unsigned long emfn)
{
    return true;
}


void __init efi_init_memory(void)
{
    unsigned int i;
    l4_pgentry_t *efi_l4t;
    struct rt_extra {
        struct rt_extra *next;
        unsigned long smfn, emfn;
        pte_attr_t prot;
    } *extra, *extra_head = NULL;

    free_ebmalloc_unused_mem();

    if ( !efi_enabled(EFI_BOOT) )
        return;

    printk(XENLOG_DEBUG "EFI memory map:%s\n",
           map_bs ? " (mapping BootServices)" : "");
    for ( i = 0; i < efi_memmap_size; i += efi_mdesc_size )
    {
        EFI_MEMORY_DESCRIPTOR *desc = efi_memmap + i;
        u64 len = desc->NumberOfPages << EFI_PAGE_SHIFT;
        unsigned long smfn, emfn;
        pte_attr_t prot = PAGE_HYPERVISOR_RWX;
        paddr_t mem_base;
        unsigned long mem_npages;

        printk(XENLOG_DEBUG " %013" PRIx64 "-%013" PRIx64
                            " type=%u attr=%016" PRIx64 "\n",
               desc->PhysicalStart, desc->PhysicalStart + len - 1,
               desc->Type, desc->Attribute);

        if ( (desc->Attribute & (EFI_MEMORY_WB | EFI_MEMORY_WT)) ||
             (efi_bs_revision >= EFI_REVISION(2, 5) &&
              (desc->Attribute & EFI_MEMORY_WP)) )
        {
            /* Supplement the heuristics in l1tf_calculations(). */
            l1tf_safe_maddr =
                max(l1tf_safe_maddr,
                    ROUNDUP(desc->PhysicalStart + len, PAGE_SIZE));
        }

        if ( !efi_enabled(EFI_RS) )
            continue;

        if ( !(desc->Attribute & EFI_MEMORY_RUNTIME) )
        {
            switch ( desc->Type )
            {
            default:
                continue;

            /*
             * Adjust runtime services regions. Keep in sync with
             * efi_exit_boot().
             */
            case EfiRuntimeServicesCode:
            case EfiRuntimeServicesData:
                printk(XENLOG_WARNING
                       "Setting RUNTIME attribute for %013" PRIx64 "-%013" PRIx64 "\n",
                       desc->PhysicalStart, desc->PhysicalStart + len - 1);
                desc->Attribute |= EFI_MEMORY_RUNTIME;
                break;

            case EfiBootServicesCode:
            case EfiBootServicesData:
                if ( !map_bs )
                    continue;
                break;
            }
        }

        desc->VirtualStart = INVALID_VIRTUAL_ADDRESS;

        smfn = PFN_DOWN(desc->PhysicalStart);
        emfn = PFN_UP(desc->PhysicalStart + len);

        mem_base = pfn_to_paddr(smfn);
        mem_npages = emfn - smfn;

        if ( desc->Attribute & EFI_MEMORY_WB )
            prot |= _PAGE_WB;
        else if ( desc->Attribute & EFI_MEMORY_WT )
            prot |= _PAGE_WT | MAP_SMALL_PAGES;
        else if ( desc->Attribute & EFI_MEMORY_WC )
            prot |= _PAGE_WC | MAP_SMALL_PAGES;
        else if ( desc->Attribute & (EFI_MEMORY_UC | EFI_MEMORY_UCE) )
            prot |= _PAGE_UC | MAP_SMALL_PAGES;
        else if ( efi_bs_revision >= EFI_REVISION(2, 5) &&
                  (desc->Attribute & EFI_MEMORY_WP) )
            prot |= _PAGE_WP | MAP_SMALL_PAGES;
        else
        {
            printk(XENLOG_ERR "Unknown cachability for MFNs %#lx-%#lx%s\n",
                   smfn, emfn - 1, efi_map_uc ? ", assuming UC" : "");
            if ( !efi_map_uc )
                continue;
            prot |= _PAGE_UC | MAP_SMALL_PAGES;
        }

        if ( desc->Attribute & (efi_bs_revision < EFI_REVISION(2, 5)
                                ? EFI_MEMORY_WP : EFI_MEMORY_RO) )
            prot &= ~(_PAGE_DIRTY | _PAGE_RW);
        if ( desc->Attribute & EFI_MEMORY_XP )
            prot |= _PAGE_NX;

        if ( pfn_to_pdx(emfn - 1) < (DIRECTMAP_SIZE >> PAGE_SHIFT) &&
             pdx_is_region_compressible(mem_base, mem_npages) )
        {
            if ( (unsigned long)mfn_to_virt(emfn - 1) >= HYPERVISOR_VIRT_END )
                prot &= ~_PAGE_GLOBAL;
            if ( map_pages_to_xen((unsigned long)mfn_to_virt(smfn),
                                  _mfn(smfn), emfn - smfn, prot) == 0 )
                desc->VirtualStart =
                    (unsigned long)maddr_to_virt(desc->PhysicalStart);
            else
                printk(XENLOG_ERR "Could not map MFNs %#lx-%#lx\n",
                       smfn, emfn - 1);
        }
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
        else
        {
            printk(XENLOG_ERR "No mapping for MFNs %#lx-%#lx\n",
                   smfn, emfn - 1);
        }
    }

    if ( !efi_enabled(EFI_RS) )
    {
        efi_fw_vendor = NULL;
        return;
    }

    /*
     * Set up 1:1 page tables for runtime calls. See SetVirtualAddressMap() in
     * efi_exit_boot().
     */
    efi_l4t = alloc_mapped_pagetable(&efi_l4_mfn);
    BUG_ON(!efi_l4t);

    copy_mapping(0, max_page, ram_range_valid, efi_l4t);

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
                         rt_range_valid, efi_l4t);
    }

    /* Insert non-RAM runtime mappings outside of the direct map. */
    while ( (extra = extra_head) != NULL )
    {
        unsigned long addr = extra->smfn << PAGE_SHIFT;
        l4_pgentry_t l4e = efi_l4t[l4_table_offset(addr)];
        l3_pgentry_t *pl3e;
        l2_pgentry_t *pl2e;
        l1_pgentry_t *l1t;

        if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) )
        {
            mfn_t l3mfn;

            pl3e = alloc_mapped_pagetable(&l3mfn);
            BUG_ON(!pl3e);
            efi_l4t[l4_table_offset(addr)] =
                l4e_from_mfn(l3mfn, __PAGE_HYPERVISOR);
        }
        else
            pl3e = map_l3t_from_l4e(l4e);
        pl3e += l3_table_offset(addr);
        if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) )
        {
            mfn_t l2mfn;

            pl2e = alloc_mapped_pagetable(&l2mfn);
            BUG_ON(!pl2e);
            *pl3e = l3e_from_mfn(l2mfn, __PAGE_HYPERVISOR);
        }
        else
        {
            BUG_ON(l3e_get_flags(*pl3e) & _PAGE_PSE);
            pl2e = map_l2t_from_l3e(*pl3e);
        }
        UNMAP_DOMAIN_PAGE(pl3e);
        pl2e += l2_table_offset(addr);
        if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
        {
            mfn_t l1mfn;

            l1t = alloc_mapped_pagetable(&l1mfn);
            BUG_ON(!l1t);
            *pl2e = l2e_from_mfn(l1mfn, __PAGE_HYPERVISOR);
        }
        else
        {
            BUG_ON(l2e_get_flags(*pl2e) & _PAGE_PSE);
            l1t = map_l1t_from_l2e(*pl2e);
        }
        UNMAP_DOMAIN_PAGE(pl2e);
        for ( i = l1_table_offset(addr);
              i < L1_PAGETABLE_ENTRIES && extra->smfn < extra->emfn;
              ++i, ++extra->smfn )
            l1t[i] = l1e_from_pfn(extra->smfn, extra->prot);
        UNMAP_DOMAIN_PAGE(l1t);

        if ( extra->smfn == extra->emfn )
        {
            extra_head = extra->next;
            xfree(extra);
        }
    }

    /* Insert Xen mappings. */
    for ( i = l4_table_offset(HYPERVISOR_VIRT_START);
          i < l4_table_offset(DIRECTMAP_VIRT_END); ++i )
        efi_l4t[i] = idle_pg_table[i];

    unmap_domain_page(efi_l4t);
}
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
