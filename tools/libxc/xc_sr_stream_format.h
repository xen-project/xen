#ifndef __STREAM_FORMAT__H
#define __STREAM_FORMAT__H

/*
 * C structures for the Migration v2 stream format.
 * See docs/specs/libxc-migration-stream.pandoc
 */

#include <inttypes.h>

/*
 * Image Header
 */
struct xc_sr_ihdr
{
    uint64_t marker;
    uint32_t id;
    uint32_t version;
    uint16_t options;
    uint16_t _res1;
    uint32_t _res2;
};

#define IHDR_MARKER  0xffffffffffffffffULL
#define IHDR_ID      0x58454E46U

#define _IHDR_OPT_ENDIAN 0
#define IHDR_OPT_LITTLE_ENDIAN (0 << _IHDR_OPT_ENDIAN)
#define IHDR_OPT_BIG_ENDIAN    (1 << _IHDR_OPT_ENDIAN)

/*
 * Domain Header
 */
struct xc_sr_dhdr
{
    uint32_t type;
    uint16_t page_shift;
    uint16_t _res1;
    uint32_t xen_major;
    uint32_t xen_minor;
};

#define DHDR_TYPE_X86_PV  0x00000001U
#define DHDR_TYPE_X86_HVM 0x00000002U

/*
 * Record Header
 */
struct xc_sr_rhdr
{
    uint32_t type;
    uint32_t length;
};

/* All records must be aligned up to an 8 octet boundary */
#define REC_ALIGN_ORDER               (3U)
/* Somewhat arbitrary - 128MB */
#define REC_LENGTH_MAX                (128U << 20)

#define REC_TYPE_END                        0x00000000U
#define REC_TYPE_PAGE_DATA                  0x00000001U
#define REC_TYPE_X86_PV_INFO                0x00000002U
#define REC_TYPE_X86_PV_P2M_FRAMES          0x00000003U
#define REC_TYPE_X86_PV_VCPU_BASIC          0x00000004U
#define REC_TYPE_X86_PV_VCPU_EXTENDED       0x00000005U
#define REC_TYPE_X86_PV_VCPU_XSAVE          0x00000006U
#define REC_TYPE_SHARED_INFO                0x00000007U
#define REC_TYPE_X86_TSC_INFO               0x00000008U
#define REC_TYPE_HVM_CONTEXT                0x00000009U
#define REC_TYPE_HVM_PARAMS                 0x0000000aU
#define REC_TYPE_TOOLSTACK                  0x0000000bU
#define REC_TYPE_X86_PV_VCPU_MSRS           0x0000000cU
#define REC_TYPE_VERIFY                     0x0000000dU
#define REC_TYPE_CHECKPOINT                 0x0000000eU
#define REC_TYPE_CHECKPOINT_DIRTY_PFN_LIST  0x0000000fU

#define REC_TYPE_OPTIONAL             0x80000000U

/* PAGE_DATA */
struct xc_sr_rec_page_data_header
{
    uint32_t count;
    uint32_t _res1;
    uint64_t pfn[0];
};

#define PAGE_DATA_PFN_MASK  0x000fffffffffffffULL
#define PAGE_DATA_TYPE_MASK 0xf000000000000000ULL

/* X86_PV_INFO */
struct xc_sr_rec_x86_pv_info
{
    uint8_t guest_width;
    uint8_t pt_levels;
    uint8_t _res[6];
};

/* X86_PV_P2M_FRAMES */
struct xc_sr_rec_x86_pv_p2m_frames
{
    uint32_t start_pfn;
    uint32_t end_pfn;
    uint64_t p2m_pfns[0];
};

/* X86_PV_VCPU_{BASIC,EXTENDED,XSAVE,MSRS} */
struct xc_sr_rec_x86_pv_vcpu_hdr
{
    uint32_t vcpu_id;
    uint32_t _res1;
    uint8_t context[0];
};

/* X86_TSC_INFO */
struct xc_sr_rec_x86_tsc_info
{
    uint32_t mode;
    uint32_t khz;
    uint64_t nsec;
    uint32_t incarnation;
    uint32_t _res1;
};

/* HVM_PARAMS */
struct xc_sr_rec_hvm_params_entry
{
    uint64_t index;
    uint64_t value;
};

struct xc_sr_rec_hvm_params
{
    uint32_t count;
    uint32_t _res1;
    struct xc_sr_rec_hvm_params_entry param[0];
};

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
