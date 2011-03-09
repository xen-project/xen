/******************************************************************************
 *
 * Name: actypes.h - Common data types for the entire ACPI subsystem
 *
 *****************************************************************************/

/*
 * Copyright (C) 2000 - 2007, R. Byron Moore
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */

#ifndef __ACTYPES_H__
#define __ACTYPES_H__

/* acpisrc:struct_defs -- for acpisrc conversion */

/*
 * ACPI_MACHINE_WIDTH must be specified in an OS- or compiler-dependent header
 * and must be either 32 or 64. 16-bit ACPICA is no longer supported, as of
 * 12/2006.
 */
#ifndef ACPI_MACHINE_WIDTH
#error ACPI_MACHINE_WIDTH not defined
#endif

/*! [Begin] no source code translation */

/*
 * Data type ranges
 * Note: These macros are designed to be compiler independent as well as
 * working around problems that some 32-bit compilers have with 64-bit
 * constants.
 */
#define ACPI_UINT8_MAX                  (UINT8) (~((UINT8)  0))	/* 0xFF               */
#define ACPI_UINT16_MAX                 (UINT16)(~((UINT16) 0))	/* 0xFFFF             */
#define ACPI_UINT32_MAX                 (UINT32)(~((UINT32) 0))	/* 0xFFFFFFFF         */
#define ACPI_UINT64_MAX                 (UINT64)(~((UINT64) 0))	/* 0xFFFFFFFFFFFFFFFF */
#define ACPI_ASCII_MAX                  0x7F

/*
 * Architecture-specific ACPICA Subsystem Data Types
 *
 * The goal of these types is to provide source code portability across
 * 16-bit, 32-bit, and 64-bit targets.
 *
 * 1) The following types are of fixed size for all targets (16/32/64):
 *
 * BOOLEAN      Logical boolean
 *
 * UINT8        8-bit  (1 byte) unsigned value
 * UINT16       16-bit (2 byte) unsigned value
 * UINT32       32-bit (4 byte) unsigned value
 * UINT64       64-bit (8 byte) unsigned value
 *
 * INT16        16-bit (2 byte) signed value
 * INT32        32-bit (4 byte) signed value
 * INT64        64-bit (8 byte) signed value
 *
 * COMPILER_DEPENDENT_UINT64/INT64 - These types are defined in the
 * compiler-dependent header(s) and were introduced because there is no common
 * 64-bit integer type across the various compilation models, as shown in
 * the table below.
 *
 * Datatype  LP64 ILP64 LLP64 ILP32 LP32 16bit
 * char      8    8     8     8     8    8
 * short     16   16    16    16    16   16
 * _int32         32
 * int       32   64    32    32    16   16
 * long      64   64    32    32    32   32
 * long long            64    64
 * pointer   64   64    64    32    32   32
 *
 * Note: ILP64 and LP32 are currently not supported.
 *
 *
 * 2) These types represent the native word size of the target mode of the
 * processor, and may be 16-bit, 32-bit, or 64-bit as required. They are
 * usually used for memory allocation, efficient loop counters, and array
 * indexes. The types are similar to the size_t type in the C library and are
 * required because there is no C type that consistently represents the native
 * data width.
 *
 * ACPI_SIZE        16/32/64-bit unsigned value
 * ACPI_NATIVE_UINT 16/32/64-bit unsigned value
 * ACPI_NATIVE_INT  16/32/64-bit signed value
 *
 */

/*******************************************************************************
 *
 * Common types for all compilers, all targets
 *
 ******************************************************************************/

typedef unsigned char BOOLEAN;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef COMPILER_DEPENDENT_UINT64 UINT64;
typedef COMPILER_DEPENDENT_INT64 INT64;

/*! [End] no source code translation !*/

/*******************************************************************************
 *
 * Types specific to 64-bit targets
 *
 ******************************************************************************/

#if ACPI_MACHINE_WIDTH == 64

/*! [Begin] no source code translation (keep the typedefs as-is) */

typedef unsigned int UINT32;
typedef int INT32;

/*! [End] no source code translation !*/

typedef u64 acpi_native_uint;
typedef s64 acpi_native_int;

typedef u64 acpi_io_address;
typedef u64 acpi_physical_address;

#define ACPI_MAX_PTR                    ACPI_UINT64_MAX
#define ACPI_SIZE_MAX                   ACPI_UINT64_MAX

#define ACPI_USE_NATIVE_DIVIDE	/* Has native 64-bit integer support */

/*
 * In the case of the Itanium Processor Family (IPF), the hardware does not
 * support misaligned memory transfers. Set the MISALIGNMENT_NOT_SUPPORTED flag
 * to indicate that special precautions must be taken to avoid alignment faults.
 * (IA64 or ia64 is currently used by existing compilers to indicate IPF.)
 *
 * Note: Em64_t and other X86-64 processors support misaligned transfers,
 * so there is no need to define this flag.
 */
#if defined (__IA64__) || defined (__ia64__)
#define ACPI_MISALIGNMENT_NOT_SUPPORTED
#endif

/*******************************************************************************
 *
 * Types specific to 32-bit targets
 *
 ******************************************************************************/

#elif ACPI_MACHINE_WIDTH == 32

/*! [Begin] no source code translation (keep the typedefs as-is) */

typedef unsigned int UINT32;
typedef int INT32;

/*! [End] no source code translation !*/

typedef u32 acpi_native_uint;
typedef s32 acpi_native_int;

typedef u32 acpi_io_address;
typedef u32 acpi_physical_address;

#define ACPI_MAX_PTR                    ACPI_UINT32_MAX
#define ACPI_SIZE_MAX                   ACPI_UINT32_MAX

#else

/* ACPI_MACHINE_WIDTH must be either 64 or 32 */

#error unknown ACPI_MACHINE_WIDTH
#endif

/* Variable-width type, used instead of clib size_t */

typedef acpi_native_uint acpi_size;

/*******************************************************************************
 *
 * OS-dependent and compiler-dependent types
 *
 * If the defaults below are not appropriate for the host system, they can
 * be defined in the compiler-specific or OS-specific header, and this will
 * take precedence.
 *
 ******************************************************************************/

/* Value returned by acpi_os_get_thread_id */

#ifndef acpi_thread_id
#define acpi_thread_id                  acpi_native_uint
#endif

/* Use C99 uintptr_t for pointer casting if available, "void *" otherwise */

#ifndef acpi_uintptr_t
#define acpi_uintptr_t                  void *
#endif

/*
 * ACPI_PRINTF_LIKE is used to tag functions as "printf-like" because
 * some compilers can catch printf format string problems
 */
#ifndef ACPI_PRINTF_LIKE
#define ACPI_PRINTF_LIKE(c)
#endif

/*
 * Some compilers complain about unused variables. Sometimes we don't want to
 * use all the variables (for example, _acpi_module_name). This allows us
 * to to tell the compiler in a per-variable manner that a variable
 * is unused
 */
#ifndef ACPI_UNUSED_VAR
#define ACPI_UNUSED_VAR
#endif

/*
 * All ACPICA functions that are available to the rest of the kernel are
 * tagged with this macro which can be defined as appropriate for the host.
 */
#ifndef ACPI_EXPORT_SYMBOL
#define ACPI_EXPORT_SYMBOL(symbol)
#endif

/*******************************************************************************
 *
 * Independent types
 *
 ******************************************************************************/

/* Logical defines and NULL */

#ifdef FALSE
#undef FALSE
#endif
#define FALSE                           (1 == 0)

#ifdef TRUE
#undef TRUE
#endif
#define TRUE                            (1 == 1)

#ifndef NULL
#define NULL                            (void *) 0
#endif

/*
 * Mescellaneous types
 */
typedef u32 acpi_status;	/* All ACPI Exceptions */
typedef u32 acpi_name;		/* 4-byte ACPI name */
typedef char *acpi_string;	/* Null terminated ASCII string */
typedef void *acpi_handle;	/* Actually a ptr to a NS Node */

struct uint64_struct {
	u32 lo;
	u32 hi;
};

union uint64_overlay {
	u64 full;
	struct uint64_struct part;
};

struct uint32_struct {
	u32 lo;
	u32 hi;
};

/* Synchronization objects */

#define acpi_mutex                      void *
#define acpi_semaphore                  void *

/*
 * Acpi integer width. In ACPI version 1, integers are
 * 32 bits.  In ACPI version 2, integers are 64 bits.
 * Note that this pertains to the ACPI integer type only, not
 * other integers used in the implementation of the ACPI CA
 * subsystem.
 */
#ifdef ACPI_NO_INTEGER64_SUPPORT

/* 32-bit integers only, no 64-bit support */

typedef u32 acpi_integer;
#define ACPI_INTEGER_MAX                ACPI_UINT32_MAX
#define ACPI_INTEGER_BIT_SIZE           32
#define ACPI_MAX_DECIMAL_DIGITS         10	/* 2^32 = 4,294,967,296 */

#define ACPI_USE_NATIVE_DIVIDE	/* Use compiler native 32-bit divide */

#else

/* 64-bit integers */

typedef unsigned long long acpi_integer;
#define ACPI_INTEGER_MAX                ACPI_UINT64_MAX
#define ACPI_INTEGER_BIT_SIZE           64
#define ACPI_MAX_DECIMAL_DIGITS         20	/* 2^64 = 18,446,744,073,709,551,616 */

#if ACPI_MACHINE_WIDTH == 64
#define ACPI_USE_NATIVE_DIVIDE	/* Use compiler native 64-bit divide */
#endif
#endif

#define ACPI_MAX64_DECIMAL_DIGITS       20
#define ACPI_MAX32_DECIMAL_DIGITS       10
#define ACPI_MAX16_DECIMAL_DIGITS        5
#define ACPI_MAX8_DECIMAL_DIGITS         3

/*
 * Constants with special meanings
 */
#define ACPI_ROOT_OBJECT                ACPI_ADD_PTR (acpi_handle, NULL, ACPI_MAX_PTR)

/*
 * Initialization sequence
 */
#define ACPI_FULL_INITIALIZATION        0x00
#define ACPI_NO_ADDRESS_SPACE_INIT      0x01
#define ACPI_NO_HARDWARE_INIT           0x02
#define ACPI_NO_EVENT_INIT              0x04
#define ACPI_NO_HANDLER_INIT            0x08
#define ACPI_NO_ACPI_ENABLE             0x10
#define ACPI_NO_DEVICE_INIT             0x20
#define ACPI_NO_OBJECT_INIT             0x40

/*
 * Initialization state
 */
#define ACPI_SUBSYSTEM_INITIALIZE       0x01
#define ACPI_INITIALIZED_OK             0x02

/*
 * Power state values
 */
#define ACPI_STATE_UNKNOWN              (u8) 0xFF

#define ACPI_STATE_S0                   (u8) 0
#define ACPI_STATE_S1                   (u8) 1
#define ACPI_STATE_S2                   (u8) 2
#define ACPI_STATE_S3                   (u8) 3
#define ACPI_STATE_S4                   (u8) 4
#define ACPI_STATE_S5                   (u8) 5
#define ACPI_S_STATES_MAX               ACPI_STATE_S5
#define ACPI_S_STATE_COUNT              6

#define ACPI_STATE_D0                   (u8) 0
#define ACPI_STATE_D1                   (u8) 1
#define ACPI_STATE_D2                   (u8) 2
#define ACPI_STATE_D3                   (u8) 3
#define ACPI_D_STATES_MAX               ACPI_STATE_D3
#define ACPI_D_STATE_COUNT              4

#define ACPI_STATE_C0                   (u8) 0
#define ACPI_STATE_C1                   (u8) 1
#define ACPI_STATE_C2                   (u8) 2
#define ACPI_STATE_C3                   (u8) 3
#define ACPI_C_STATES_MAX               ACPI_STATE_C3
#define ACPI_C_STATE_COUNT              4

/*
 * Sleep type invalid value
 */
#define ACPI_SLEEP_TYPE_MAX             0x7
#define ACPI_SLEEP_TYPE_INVALID         0xFF

/*
 * Standard notify values
 */
#define ACPI_NOTIFY_BUS_CHECK           (u8) 0
#define ACPI_NOTIFY_DEVICE_CHECK        (u8) 1
#define ACPI_NOTIFY_DEVICE_WAKE         (u8) 2
#define ACPI_NOTIFY_EJECT_REQUEST       (u8) 3
#define ACPI_NOTIFY_DEVICE_CHECK_LIGHT  (u8) 4
#define ACPI_NOTIFY_FREQUENCY_MISMATCH  (u8) 5
#define ACPI_NOTIFY_BUS_MODE_MISMATCH   (u8) 6
#define ACPI_NOTIFY_POWER_FAULT         (u8) 7

/*
 * Types associated with ACPI names and objects.  The first group of
 * values (up to ACPI_TYPE_EXTERNAL_MAX) correspond to the definition
 * of the ACPI object_type() operator (See the ACPI Spec). Therefore,
 * only add to the first group if the spec changes.
 *
 * NOTE: Types must be kept in sync with the global acpi_ns_properties
 * and acpi_ns_type_names arrays.
 */
typedef u32 acpi_object_type;

#define ACPI_TYPE_ANY                   0x00
#define ACPI_TYPE_INTEGER               0x01	/* Byte/Word/Dword/Zero/One/Ones */
#define ACPI_TYPE_STRING                0x02
#define ACPI_TYPE_BUFFER                0x03
#define ACPI_TYPE_PACKAGE               0x04	/* byte_const, multiple data_term/Constant/super_name */
#define ACPI_TYPE_FIELD_UNIT            0x05
#define ACPI_TYPE_DEVICE                0x06	/* Name, multiple Node */
#define ACPI_TYPE_EVENT                 0x07
#define ACPI_TYPE_METHOD                0x08	/* Name, byte_const, multiple Code */
#define ACPI_TYPE_MUTEX                 0x09
#define ACPI_TYPE_REGION                0x0A
#define ACPI_TYPE_POWER                 0x0B	/* Name,byte_const,word_const,multi Node */
#define ACPI_TYPE_PROCESSOR             0x0C	/* Name,byte_const,Dword_const,byte_const,multi nm_o */
#define ACPI_TYPE_THERMAL               0x0D	/* Name, multiple Node */
#define ACPI_TYPE_BUFFER_FIELD          0x0E
#define ACPI_TYPE_DDB_HANDLE            0x0F
#define ACPI_TYPE_DEBUG_OBJECT          0x10

#define ACPI_TYPE_EXTERNAL_MAX          0x10

/*
 * These are object types that do not map directly to the ACPI
 * object_type() operator. They are used for various internal purposes only.
 * If new predefined ACPI_TYPEs are added (via the ACPI specification), these
 * internal types must move upwards. (There is code that depends on these
 * values being contiguous with the external types above.)
 */
#define ACPI_TYPE_LOCAL_REGION_FIELD    0x11
#define ACPI_TYPE_LOCAL_BANK_FIELD      0x12
#define ACPI_TYPE_LOCAL_INDEX_FIELD     0x13
#define ACPI_TYPE_LOCAL_REFERENCE       0x14	/* Arg#, Local#, Name, Debug, ref_of, Index */
#define ACPI_TYPE_LOCAL_ALIAS           0x15
#define ACPI_TYPE_LOCAL_METHOD_ALIAS    0x16
#define ACPI_TYPE_LOCAL_NOTIFY          0x17
#define ACPI_TYPE_LOCAL_ADDRESS_HANDLER 0x18
#define ACPI_TYPE_LOCAL_RESOURCE        0x19
#define ACPI_TYPE_LOCAL_RESOURCE_FIELD  0x1A
#define ACPI_TYPE_LOCAL_SCOPE           0x1B	/* 1 Name, multiple object_list Nodes */

#define ACPI_TYPE_NS_NODE_MAX           0x1B	/* Last typecode used within a NS Node */

/*
 * These are special object types that never appear in
 * a Namespace node, only in an union acpi_operand_object
 */
#define ACPI_TYPE_LOCAL_EXTRA           0x1C
#define ACPI_TYPE_LOCAL_DATA            0x1D

#define ACPI_TYPE_LOCAL_MAX             0x1D

/* All types above here are invalid */

#define ACPI_TYPE_INVALID               0x1E
#define ACPI_TYPE_NOT_FOUND             0xFF

/*
 * All I/O
 */
#define ACPI_READ                       0
#define ACPI_WRITE                      1
#define ACPI_IO_MASK                    1

/*
 * Event Types: Fixed & General Purpose
 */
typedef u32 acpi_event_type;

/*
 * Fixed events
 */
#define ACPI_EVENT_PMTIMER              0
#define ACPI_EVENT_GLOBAL               1
#define ACPI_EVENT_POWER_BUTTON         2
#define ACPI_EVENT_SLEEP_BUTTON         3
#define ACPI_EVENT_RTC                  4
#define ACPI_EVENT_MAX                  4
#define ACPI_NUM_FIXED_EVENTS           ACPI_EVENT_MAX + 1

/*
 * Event Status - Per event
 * -------------
 * The encoding of acpi_event_status is illustrated below.
 * Note that a set bit (1) indicates the property is TRUE
 * (e.g. if bit 0 is set then the event is enabled).
 * +-------------+-+-+-+
 * |   Bits 31:3 |2|1|0|
 * +-------------+-+-+-+
 *          |     | | |
 *          |     | | +- Enabled?
 *          |     | +--- Enabled for wake?
 *          |     +----- Set?
 *          +----------- <Reserved>
 */
typedef u32 acpi_event_status;

#define ACPI_EVENT_FLAG_DISABLED        (acpi_event_status) 0x00
#define ACPI_EVENT_FLAG_ENABLED         (acpi_event_status) 0x01
#define ACPI_EVENT_FLAG_WAKE_ENABLED    (acpi_event_status) 0x02
#define ACPI_EVENT_FLAG_SET             (acpi_event_status) 0x04

/* Notify types */

#define ACPI_SYSTEM_NOTIFY              0x1
#define ACPI_DEVICE_NOTIFY              0x2
#define ACPI_ALL_NOTIFY                 0x3
#define ACPI_MAX_NOTIFY_HANDLER_TYPE    0x3

#define ACPI_MAX_SYS_NOTIFY             0x7f

/* Address Space (Operation Region) Types */

typedef u8 acpi_adr_space_type;

#define ACPI_ADR_SPACE_SYSTEM_MEMORY    (acpi_adr_space_type) 0
#define ACPI_ADR_SPACE_SYSTEM_IO        (acpi_adr_space_type) 1
#define ACPI_ADR_SPACE_PCI_CONFIG       (acpi_adr_space_type) 2
#define ACPI_ADR_SPACE_EC               (acpi_adr_space_type) 3
#define ACPI_ADR_SPACE_SMBUS            (acpi_adr_space_type) 4
#define ACPI_ADR_SPACE_CMOS             (acpi_adr_space_type) 5
#define ACPI_ADR_SPACE_PCI_BAR_TARGET   (acpi_adr_space_type) 6
#define ACPI_ADR_SPACE_DATA_TABLE       (acpi_adr_space_type) 7
#define ACPI_ADR_SPACE_FIXED_HARDWARE   (acpi_adr_space_type) 127

/*
 * bit_register IDs
 * These are bitfields defined within the full ACPI registers
 */
#define ACPI_BITREG_TIMER_STATUS                0x00
#define ACPI_BITREG_BUS_MASTER_STATUS           0x01
#define ACPI_BITREG_GLOBAL_LOCK_STATUS          0x02
#define ACPI_BITREG_POWER_BUTTON_STATUS         0x03
#define ACPI_BITREG_SLEEP_BUTTON_STATUS         0x04
#define ACPI_BITREG_RT_CLOCK_STATUS             0x05
#define ACPI_BITREG_WAKE_STATUS                 0x06
#define ACPI_BITREG_PCIEXP_WAKE_STATUS          0x07

#define ACPI_BITREG_TIMER_ENABLE                0x08
#define ACPI_BITREG_GLOBAL_LOCK_ENABLE          0x09
#define ACPI_BITREG_POWER_BUTTON_ENABLE         0x0A
#define ACPI_BITREG_SLEEP_BUTTON_ENABLE         0x0B
#define ACPI_BITREG_RT_CLOCK_ENABLE             0x0C
#define ACPI_BITREG_WAKE_ENABLE                 0x0D
#define ACPI_BITREG_PCIEXP_WAKE_DISABLE         0x0E

#define ACPI_BITREG_SCI_ENABLE                  0x0F
#define ACPI_BITREG_BUS_MASTER_RLD              0x10
#define ACPI_BITREG_GLOBAL_LOCK_RELEASE         0x11
#define ACPI_BITREG_SLEEP_TYPE_A                0x12
#define ACPI_BITREG_SLEEP_TYPE_B                0x13
#define ACPI_BITREG_SLEEP_ENABLE                0x14

#define ACPI_BITREG_ARB_DISABLE                 0x15

#define ACPI_BITREG_MAX                         0x15
#define ACPI_NUM_BITREG                         ACPI_BITREG_MAX + 1

/*
 * External ACPI object definition
 */
union acpi_object {
	acpi_object_type type;	/* See definition of acpi_ns_type for values */
	struct {
		acpi_object_type type;
		acpi_integer value;	/* The actual number */
	} integer;

	struct {
		acpi_object_type type;
		u32 length;	/* # of bytes in string, excluding trailing null */
		char *pointer;	/* points to the string value */
	} string;

	struct {
		acpi_object_type type;
		u32 length;	/* # of bytes in buffer */
		u8 *pointer;	/* points to the buffer */
	} buffer;

	struct {
		acpi_object_type type;
		u32 fill1;
		acpi_handle handle;	/* object reference */
	} reference;

	struct {
		acpi_object_type type;
		u32 count;	/* # of elements in package */
		union acpi_object *elements;	/* Pointer to an array of ACPI_OBJECTs */
	} package;

	struct {
		acpi_object_type type;
		u32 proc_id;
		acpi_io_address pblk_address;
		u32 pblk_length;
	} processor;

	struct {
		acpi_object_type type;
		u32 system_level;
		u32 resource_order;
	} power_resource;
};

/*
 * List of objects, used as a parameter list for control method evaluation
 */
struct acpi_object_list {
	u32 count;
	union acpi_object *pointer;
};

/*
 * Miscellaneous common Data Structures used by the interfaces
 */
#define ACPI_NO_BUFFER              0
#define ACPI_ALLOCATE_BUFFER        (acpi_size) (-1)
#define ACPI_ALLOCATE_LOCAL_BUFFER  (acpi_size) (-2)

struct acpi_buffer {
	acpi_size length;	/* Length in bytes of the buffer */
	void *pointer;		/* pointer to buffer */
};

/*
 *  Memory Attributes
 */
#define ACPI_READ_ONLY_MEMORY           (u8) 0x00
#define ACPI_READ_WRITE_MEMORY          (u8) 0x01

#define ACPI_NON_CACHEABLE_MEMORY       (u8) 0x00
#define ACPI_CACHABLE_MEMORY            (u8) 0x01
#define ACPI_WRITE_COMBINING_MEMORY     (u8) 0x02
#define ACPI_PREFETCHABLE_MEMORY        (u8) 0x03

/*
 *  IO Attributes
 *  The ISA IO ranges are:     n000-n0_fFh, n400-n4_fFh, n800-n8_fFh, n_c00-n_cFFh.
 *  The non-ISA IO ranges are: n100-n3_fFh, n500-n7_fFh, n900-n_bFFh, n_cd0-n_fFFh.
 */
#define ACPI_NON_ISA_ONLY_RANGES        (u8) 0x01
#define ACPI_ISA_ONLY_RANGES            (u8) 0x02
#define ACPI_ENTIRE_RANGE               (ACPI_NON_ISA_ONLY_RANGES | ACPI_ISA_ONLY_RANGES)

/* Type of translation - 1=Sparse, 0=Dense */

#define ACPI_SPARSE_TRANSLATION         (u8) 0x01

/*
 *  IO Port Descriptor Decode
 */
#define ACPI_DECODE_10                  (u8) 0x00	/* 10-bit IO address decode */
#define ACPI_DECODE_16                  (u8) 0x01	/* 16-bit IO address decode */

/*
 *  IRQ Attributes
 */
#define ACPI_LEVEL_SENSITIVE            (u8) 0x00
#define ACPI_EDGE_SENSITIVE             (u8) 0x01

#define ACPI_ACTIVE_HIGH                (u8) 0x00
#define ACPI_ACTIVE_LOW                 (u8) 0x01

#define ACPI_EXCLUSIVE                  (u8) 0x00
#define ACPI_SHARED                     (u8) 0x01

/*
 *  DMA Attributes
 */
#define ACPI_COMPATIBILITY              (u8) 0x00
#define ACPI_TYPE_A                     (u8) 0x01
#define ACPI_TYPE_B                     (u8) 0x02
#define ACPI_TYPE_F                     (u8) 0x03

#define ACPI_NOT_BUS_MASTER             (u8) 0x00
#define ACPI_BUS_MASTER                 (u8) 0x01

#define ACPI_TRANSFER_8                 (u8) 0x00
#define ACPI_TRANSFER_8_16              (u8) 0x01
#define ACPI_TRANSFER_16                (u8) 0x02

/*
 * Start Dependent Functions Priority definitions
 */
#define ACPI_GOOD_CONFIGURATION         (u8) 0x00
#define ACPI_ACCEPTABLE_CONFIGURATION   (u8) 0x01
#define ACPI_SUB_OPTIMAL_CONFIGURATION  (u8) 0x02

/*
 *  16, 32 and 64-bit Address Descriptor resource types
 */
#define ACPI_MEMORY_RANGE               (u8) 0x00
#define ACPI_IO_RANGE                   (u8) 0x01
#define ACPI_BUS_NUMBER_RANGE           (u8) 0x02

#define ACPI_ADDRESS_NOT_FIXED          (u8) 0x00
#define ACPI_ADDRESS_FIXED              (u8) 0x01

#define ACPI_POS_DECODE                 (u8) 0x00
#define ACPI_SUB_DECODE                 (u8) 0x01

#define ACPI_PRODUCER                   (u8) 0x00
#define ACPI_CONSUMER                   (u8) 0x01

#endif				/* __ACTYPES_H__ */
