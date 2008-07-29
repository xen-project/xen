#ifndef TCGBIOS_H
#define TCGBIOS_H

/* TCPA ACPI definitions */
#define TCPA_ACPI_CLASS_CLIENT          0
#define TCPA_ACPI_CLASS_SERVER          1

/* Define for section 12.3 */
#define TCG_PC_OK                       0x0
#define TCG_PC_TPMERROR                 0x1
#define TCG_PC_LOGOVERFLOW              0x2
#define TCG_PC_UNSUPPORTED              0x3

#define TPM_ALG_SHA                     0x4

#define TCG_MAGIC                       0x41504354L
#define TCG_VERSION_MAJOR               1
#define TCG_VERSION_MINOR               2

#define TPM_OK                          0x0
#define TPM_RET_BASE                    0x1
#define TCG_GENERAL_ERROR               (TPM_RET_BASE + 0x0)
#define TCG_TPM_IS_LOCKED               (TPM_RET_BASE + 0x1)
#define TCG_NO_RESPONSE                 (TPM_RET_BASE + 0x2)
#define TCG_INVALID_RESPONSE            (TPM_RET_BASE + 0x3)
#define TCG_INVALID_ACCESS_REQUEST      (TPM_RET_BASE + 0x4)
#define TCG_FIRMWARE_ERROR              (TPM_RET_BASE + 0x5)
#define TCG_INTEGRITY_CHECK_FAILED      (TPM_RET_BASE + 0x6)
#define TCG_INVALID_DEVICE_ID           (TPM_RET_BASE + 0x7)
#define TCG_INVALID_VENDOR_ID           (TPM_RET_BASE + 0x8)
#define TCG_UNABLE_TO_OPEN              (TPM_RET_BASE + 0x9)
#define TCG_UNABLE_TO_CLOSE             (TPM_RET_BASE + 0xa)
#define TCG_RESPONSE_TIMEOUT            (TPM_RET_BASE + 0xb)
#define TCG_INVALID_COM_REQUEST         (TPM_RET_BASE + 0xc)
#define TCG_INVALID_ADR_REQUEST         (TPM_RET_BASE + 0xd)
#define TCG_WRITE_BYTE_ERROR            (TPM_RET_BASE + 0xe)
#define TCG_READ_BYTE_ERROR             (TPM_RET_BASE + 0xf)
#define TCG_BLOCK_WRITE_TIMEOUT         (TPM_RET_BASE + 0x10)
#define TCG_CHAR_WRITE_TIMEOUT          (TPM_RET_BASE + 0x11)
#define TCG_CHAR_READ_TIMEOUT           (TPM_RET_BASE + 0x12)
#define TCG_BLOCK_READ_TIMEOUT          (TPM_RET_BASE + 0x13)
#define TCG_TRANSFER_ABORT              (TPM_RET_BASE + 0x14)
#define TCG_INVALID_DRV_FUNCTION        (TPM_RET_BASE + 0x15)
#define TCG_OUTPUT_BUFFER_TOO_SHORT     (TPM_RET_BASE + 0x16)
#define TCG_FATAL_COM_ERROR             (TPM_RET_BASE + 0x17)
#define TCG_INVALID_INPUT_PARA          (TPM_RET_BASE + 0x18)
#define TCG_TCG_COMMAND_ERROR           (TPM_RET_BASE + 0x19)
#define TCG_INTERFACE_SHUTDOWN          (TPM_RET_BASE + 0x20)
//define TCG_PC_UNSUPPORTED             (TPM_RET_BASE + 0x21)
#define TCG_PC_TPM_NOT_PRESENT          (TPM_RET_BASE + 0x22)
#define TCG_PC_TPM_DEACTIVATED          (TPM_RET_BASE + 0x23)


#define TPM_INVALID_ADR_REQUEST          TCG_INVALID_ADR_REQUEST
#define TPM_IS_LOCKED                    TCG_TPM_IS_LOCKED
#define TPM_INVALID_DEVICE_ID            TCG_INVALID_DEVICE_ID
#define TPM_INVALID_VENDOR_ID            TCG_INVALID_VENDOR_ID
//define TPM_RESERVED_REG_INVALID
#define TPM_FIRMWARE_ERROR               TCG_FIRMWARE_ERROR
#define TPM_UNABLE_TO_OPEN               TCG_UNABLE_TO_OPEN
#define TPM_UNABLE_TO_CLOSE              TCG_UNABLE_TO_CLOSE
#define TPM_INVALID_RESPONSE             TCG_INVALID_RESPONSE
#define TPM_RESPONSE_TIMEOUT             TCG_RESPONSE_TIMEOUT
#define TPM_INVALID_ACCESS_REQUEST       TCG_INVALID_ACCESS_REQUEST
#define TPM_TRANSFER_ABORT               TCG_TRANSFER_ABORT
#define TPM_GENERAL_ERROR                TCG_GENERAL_ERROR

#define TPM_ST_CLEAR                      0x0
#define TPM_ST_STATE                      0x1
#define TPM_ST_DEACTIVATED                0x2

/* event types: 10.4.1 / table 11 */
#define EV_POST_CODE             1
#define EV_SEPARATOR             4
#define EV_ACTION                5
#define EV_EVENT_TAG             6
#define EV_COMPACT_HASH         12
#define EV_IPL                  13
#define EV_IPL_PARTITION_DATA   14


// MA Driver defines
#define CODE_MAInitTPM                    0x01
#define CODE_MAHashAllExtendTPM           0x02
#define CODE_MAPhysicalPresenceTPM        0x03
/* vendor specific ones */
#define CODE_MAIsTPMPresent               0x80
#define CODE_MAHashAll                    0x81
#define CODE_MATransmit                   0x82

/*
  indices for commands to be sent via proprietary
   _TCG_SendCommand function
 */
#define IDX_CMD_TPM_Startup_0x01                0
#define IDX_CMD_TSC_PhysicalPresence_0x20       1
#define IDX_CMD_TSC_PhysicalPresence_0x08       2
#define IDX_CMD_TSC_PhysicalPresence_0x100      3
#define IDX_CMD_TSC_PhysicalPresence_0x10       4
#define IDX_CMD_TPM_PhysicalEnable              5
#define IDX_CMD_TPM_PhysicalSetDeactivated_0x00 6
#define IDX_CMD_TPM_SHA1Start                   7


/* hardware registers for TPM TIS */
#define TPM_ACCESS                 0x0
#define TPM_INT_ENABLE             0x8
#define TPM_INT_VECTOR             0xc
#define TPM_INT_STATUS             0x10
#define TPM_INTF_CAPABILITY        0x14
#define TPM_STS                    0x18
#define TPM_DATA_FIFO              0x24
#define TPM_DID_VID                0xf00
#define TPM_RID                    0xf04

/* address of locality 0 (TIS) */
#define TPM_TIS_BASE_ADDRESS        0xfed40000

#define STATUS_FLAG_SHUTDOWN                (1 << 0)

/* Input and Output blocks for the TCG BIOS commands */

struct hleei_short
{
	uint16_t   ipblength;
	uint16_t   reserved;
	uint32_t   hashdataptr;
	uint32_t   hashdatalen;
	uint32_t   pcrindex;
	uint32_t   logdataptr;
	uint32_t   logdatalen;
} __attribute__((packed));

struct hleei_long
{
	uint16_t   ipblength;
	uint16_t   reserved;
	uint32_t   hashdataptr;
	uint32_t   hashdatalen;
	uint32_t   pcrindex;
	uint32_t   reserved2;
	uint32_t   logdataptr;
	uint32_t   logdatalen;
} __attribute__((packed));

struct hleeo
{
	uint16_t    opblength;
	uint16_t    reserved;
	uint32_t    eventnumber;
	uint8_t     hashvalue[20];
} __attribute__((packed));



struct pttti
{
	uint16_t    ipblength;
	uint16_t    reserved;
	uint16_t    opblength;
	uint16_t    reserved2;
	uint8_t     tpmoperandin[0];
} __attribute__((packed));

struct pttto
{
	uint16_t    opblength;
	uint16_t    reserved;
	uint8_t     tpmoperandout[0];
};


struct hlei
{
	uint16_t    ipblength;
	uint16_t    reserved;
	uint32_t    hashdataptr;
	uint32_t    hashdatalen;
	uint32_t    pcrindex;
	uint32_t    logeventtype;
	uint32_t    logdataptr;
	uint32_t    logdatalen;
} __attribute__((packed));

struct hleo
{
	uint16_t    opblength;
	uint16_t    reserved;
	uint32_t    eventnumber;
} __attribute__((packed));

struct hai
{
	uint16_t    ipblength;
	uint16_t    reserved;
	uint32_t    hashdataptr;
	uint32_t    hashdatalen;
	uint32_t    algorithmid;
} __attribute__((packed));

struct ti
{
	uint16_t    ipblength;
	uint16_t    reserved;
        uint16_t    opblength;
        uint16_t    reserved2;
        uint8_t     tssoperandin[0];
} __attribute__((packed));

struct to
{
	uint16_t    opblength;
	uint16_t    reserved;
	uint8_t     tssoperandout[0];
} __attribute__((packed));


struct pcpes
{
	uint32_t    pcrindex;
	uint32_t    eventtype;
	uint8_t     digest[20];
	uint32_t    eventdatasize;
	uint32_t    event;
} __attribute__((packed));

struct acpi_20_tcpa_client {
	uint32_t laml;
	uint64_t lasa;
} __attribute__((packed));

struct acpi_20_tcpa_server {
	uint16_t reserved;
	uint32_t laml;
	uint64_t lasa;
	/* more here */
} __attribute__((packed));

struct acpi_20_tcpa_clisrv {
	struct acpi_header header;
	uint16_t platform_class;
	union {
		struct acpi_20_tcpa_client client;
		struct acpi_20_tcpa_server server;
	} u;
} __attribute__((packed));


#endif
