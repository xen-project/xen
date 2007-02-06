#ifndef PROTOS_HIGHBIOS
#define PROTOS_HIGHBIOS

/* shared include file for bcc and gcc */

/* bcc does not like 'enum' */
#define IDX_TCGINTERRUPTHANDLER            0
#define IDX_TCPA_ACPI_INIT                 1
#define IDX_TCPA_EXTEND_ACPI_LOG           2
#define IDX_TCPA_CALLING_INT19H            3
#define IDX_TCPA_RETURNED_INT19H           4
#define IDX_TCPA_ADD_EVENT_SEPARATORS      5
#define IDX_TCPA_WAKE_EVENT                6
#define IDX_TCPA_ADD_BOOTDEVICE            7
#define IDX_TCPA_START_OPTION_ROM_SCAN     8
#define IDX_TCPA_OPTION_ROM                9
#define IDX_TCPA_IPL                       10
#define IDX_TCPA_INITIALIZE_TPM            11
#define IDX_TCPA_MEASURE_POST              12

#define IDX_LAST                           13 /* keep last! */

#ifdef GCC_PROTOS
  #define PARMS(x...) x
#else
  /* bcc doesn't want any parameter types in prototypes */
  #define PARMS(x...)
#endif

Bit32u TCGInterruptHandler( PARMS(pushad_regs_t *regs, Bit32u esds, Bit32u flags_ptr));

void tcpa_acpi_init( PARMS(void) );
Bit32u tcpa_extend_acpi_log( PARMS(Bit32u entry_ptr) );
void tcpa_calling_int19h( PARMS(void) );
void tcpa_returned_int19h( PARMS(void) );
void tcpa_add_event_separators( PARMS(void) );
void tcpa_wake_event( PARMS(void) );
void tcpa_add_bootdevice( PARMS(Bit32u bootcd, Bit32u bootdrv) );
void tcpa_start_option_rom_scan( PARMS(void) );
void tcpa_option_rom( PARMS(Bit32u seg) );
void tcpa_ipl( PARMS(Bit32u seg) );
void tcpa_measure_post( PARMS(Bit32u from, Bit32u to) );
Bit32u tcpa_initialize_tpm( PARMS(Bit32u physpres) );

#endif
