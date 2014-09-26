/*++

Copyright (c) 1998  Intel Corporation

Module Name:

    efefind.h

Abstract:

    EFI to compile bindings




Revision History

--*/

#ifndef __GNUC__
#pragma pack()
#endif

#define EFIERR(a)           (0x8000000000000000 | a)
#define EFI_ERROR_MASK      0x8000000000000000
#define EFIERR_OEM(a)       (0xc000000000000000 | a)

#define BAD_POINTER         0xFBFBFBFBFBFBFBFB
#define MAX_ADDRESS         0xFFFFFFFFFFFFFFFF

#define EFI_STUB_ERROR      MAX_ADDRESS

#ifndef __ASSEMBLY__
//
// Basic int types of various widths
//

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L )

    // No ANSI C 1999/2000 stdint.h integer width declarations

    #if defined(__GNUC__)
        typedef unsigned long long  uint64_t __attribute__((aligned (8)));
        typedef long long           int64_t __attribute__((aligned (8)));
        typedef unsigned int        uint32_t;
        typedef int                 int32_t;
        typedef unsigned short      uint16_t;
        typedef short               int16_t;
        typedef unsigned char       uint8_t;
        typedef char                int8_t;
    #elif defined(UNIX_LP64)

        /*  Use LP64 programming model from C_FLAGS for integer width declarations */

       typedef unsigned long       uint64_t;
       typedef long                int64_t;
       typedef unsigned int        uint32_t;
       typedef int                 int32_t;
       typedef unsigned short      uint16_t;
       typedef short               int16_t;
       typedef unsigned char       uint8_t;
       typedef char                int8_t;
    #else

       /*  Assume P64 programming model from C_FLAGS for integer width declarations */

       typedef unsigned long long  uint64_t __attribute__((aligned (8)));
       typedef long long           int64_t __attribute__((aligned (8)));
       typedef unsigned int        uint32_t;
       typedef int                 int32_t;
       typedef unsigned short      uint16_t;
       typedef short               int16_t;
       typedef unsigned char       uint8_t;
       typedef char                int8_t;
    #endif
#endif

//
// Basic EFI types of various widths
//

#ifndef __WCHAR_TYPE__
# define __WCHAR_TYPE__ short
#endif

typedef uint64_t   UINT64;
typedef int64_t    INT64;

#ifndef _BASETSD_H_
    typedef uint32_t   UINT32;
    typedef int32_t    INT32;
#endif

typedef uint16_t   UINT16;
typedef int16_t    INT16;
typedef uint8_t    UINT8;
typedef int8_t     INT8;
typedef __WCHAR_TYPE__ WCHAR;

#undef VOID
#define VOID    void


typedef int64_t    INTN;
typedef uint64_t   UINTN;

#define POST_CODE(_Data)


#define BREAKPOINT()        while (TRUE);    // Make it hang on Bios[Dbg]32

//
// Pointers must be aligned to these address to function
//

#define MIN_ALIGNMENT_SIZE  4

#define ALIGN_VARIABLE(Value ,Adjustment) \
            (UINTN)Adjustment = 0; \
            if((UINTN)Value % MIN_ALIGNMENT_SIZE) \
                (UINTN)Adjustment = MIN_ALIGNMENT_SIZE - ((UINTN)Value % MIN_ALIGNMENT_SIZE); \
            Value = (UINTN)Value + (UINTN)Adjustment


//
// Define macros to build data structure signatures from characters.
//

#define EFI_SIGNATURE_16(A,B)             ((A) | (B<<8))
#define EFI_SIGNATURE_32(A,B,C,D)         (EFI_SIGNATURE_16(A,B)     | (EFI_SIGNATURE_16(C,D)     << 16))
#define EFI_SIGNATURE_64(A,B,C,D,E,F,G,H) (EFI_SIGNATURE_32(A,B,C,D) | ((UINT64)(EFI_SIGNATURE_32(E,F,G,H)) << 32))

#define EXPORTAPI


//
// EFIAPI - prototype calling convention for EFI function pointers
// BOOTSERVICE - prototype for implementation of a boot service interface
// RUNTIMESERVICE - prototype for implementation of a runtime service interface
// RUNTIMEFUNCTION - prototype for implementation of a runtime function that is not a service
// RUNTIME_CODE - pragma macro for declaring runtime code
//

#ifndef EFIAPI                  // Forces EFI calling conventions reguardless of compiler options
        #define EFIAPI          // Substitute expresion to force C calling convention
#endif

#define BOOTSERVICE
//#define RUNTIMESERVICE(proto,a)    alloc_text("rtcode",a); proto a
//#define RUNTIMEFUNCTION(proto,a)   alloc_text("rtcode",a); proto a
#define RUNTIMESERVICE
#define RUNTIMEFUNCTION


#define RUNTIME_CODE(a)         alloc_text("rtcode", a)
#define BEGIN_RUNTIME_DATA()    data_seg("rtdata")
#define END_RUNTIME_DATA()      data_seg("")

#define VOLATILE    volatile

#define MEMORY_FENCE()


//
// When build similiar to FW, then link everything together as
// one big module.
//

#define EFI_DRIVER_ENTRY_POINT(InitFunction)    \
    UINTN                                       \
    InitializeDriver (                          \
        VOID    *ImageHandle,                   \
        VOID    *SystemTable                    \
        )                                       \
    {                                           \
        return InitFunction(ImageHandle,        \
                SystemTable);                   \
    }                                           \
                                                \
    EFI_STATUS efi_main(                        \
        EFI_HANDLE image,                       \
        EFI_SYSTEM_TABLE *systab                \
        ) __attribute__((weak,                  \
                alias ("InitializeDriver")));

#define LOAD_INTERNAL_DRIVER(_if, type, name, entry)    \
        (_if)->LoadInternal(type, name, entry)


//
// Some compilers don't support the forward reference construct:
//  typedef struct XXXXX
//
// The following macro provide a workaround for such cases.
//
#ifdef NO_INTERFACE_DECL
#define INTERFACE_DECL(x)
#else
#ifdef __GNUC__
#define INTERFACE_DECL(x) struct x
#else
#define INTERFACE_DECL(x) typedef struct x
#endif
#endif

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
