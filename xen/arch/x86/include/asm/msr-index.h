#ifndef __ASM_MSR_INDEX_H
#define __ASM_MSR_INDEX_H

/*
 * CPU model specific register (MSR) numbers
 *
 * Definitions for an MSR should follow this style:
 *
 * #define MSR_$NAME                        0x$INDEX
 * #define  $NAME_$FIELD1                   (_AC($X, ULL) << $POS1)
 * #define  $NAME_$FIELD2                   (_AC($Y, ULL) << $POS2)
 *
 * Blocks of related constants should be sorted by MSR index.  The constant
 * names should be as concise as possible, and the bit names may have an
 * abbreviated name.  Exceptions will be considered on a case-by-case basis.
 */

#define MSR_P5_MC_ADDR                      0
#define MSR_P5_MC_TYPE                      0x00000001

#define MSR_APIC_BASE                       0x0000001b
#define  APIC_BASE_BSP                      (_AC(1, ULL) <<  8)
#define  APIC_BASE_EXTD                     (_AC(1, ULL) << 10)
#define  APIC_BASE_ENABLE                   (_AC(1, ULL) << 11)
#define  APIC_BASE_ADDR_MASK                0x000ffffffffff000ULL

#define MSR_TEST_CTRL                       0x00000033
#define  TEST_CTRL_SPLITLOCK_DETECT         (_AC(1, ULL) << 29)
#define  TEST_CTRL_SPLITLOCK_DISABLE        (_AC(1, ULL) << 31)

#define MSR_INTEL_CORE_THREAD_COUNT         0x00000035
#define  MSR_CTC_THREAD_MASK                0x0000ffff
#define  MSR_CTC_CORE_MASK                  0xffff0000

#define MSR_SPEC_CTRL                       0x00000048
#define  SPEC_CTRL_IBRS                     (_AC(1, ULL) <<  0)
#define  SPEC_CTRL_STIBP                    (_AC(1, ULL) <<  1)
#define  SPEC_CTRL_SSBD                     (_AC(1, ULL) <<  2)
#define  SPEC_CTRL_IPRED_DIS_U              (_AC(1, ULL) <<  3)
#define  SPEC_CTRL_IPRED_DIS_S              (_AC(1, ULL) <<  4)
#define  SPEC_CTRL_RRSBA_DIS_U              (_AC(1, ULL) <<  5)
#define  SPEC_CTRL_RRSBA_DIS_S              (_AC(1, ULL) <<  6)
#define  SPEC_CTRL_PSFD                     (_AC(1, ULL) <<  7)
#define  SPEC_CTRL_DDP_DIS_U                (_AC(1, ULL) <<  8)
#define  SPEC_CTRL_BHI_DIS_S                (_AC(1, ULL) << 10)

#define MSR_PRED_CMD                        0x00000049
#define  PRED_CMD_IBPB                      (_AC(1, ULL) <<  0)
#define  PRED_CMD_SBPB                      (_AC(1, ULL) <<  7)

#define MSR_PPIN_CTL                        0x0000004e
#define  PPIN_LOCKOUT                       (_AC(1, ULL) <<  0)
#define  PPIN_ENABLE                        (_AC(1, ULL) <<  1)
#define MSR_PPIN                            0x0000004f

#define MSR_MISC_PACKAGE_CTRL               0x000000bc
#define  PGK_CTRL_ENERGY_FILTER_EN          (_AC(1, ULL) <<  0)

#define MSR_CORE_CAPABILITIES               0x000000cf
#define  CORE_CAPS_SPLITLOCK_DETECT         (_AC(1, ULL) <<  5)

#define MSR_PKG_CST_CONFIG_CONTROL          0x000000e2
#define  NHM_C3_AUTO_DEMOTE                 (_AC(1, ULL) << 25)
#define  NHM_C1_AUTO_DEMOTE                 (_AC(1, ULL) << 26)
#define  ATM_LNC_C6_AUTO_DEMOTE             (_AC(1, ULL) << 25)
#define  SNB_C3_AUTO_UNDEMOTE               (_AC(1, ULL) << 27)
#define  SNB_C1_AUTO_UNDEMOTE               (_AC(1, ULL) << 28)

#define MSR_ARCH_CAPABILITIES               0x0000010a
#define  ARCH_CAPS_RDCL_NO                  (_AC(1, ULL) <<  0)
#define  ARCH_CAPS_EIBRS                    (_AC(1, ULL) <<  1)
#define  ARCH_CAPS_RSBA                     (_AC(1, ULL) <<  2)
#define  ARCH_CAPS_SKIP_L1DFL               (_AC(1, ULL) <<  3)
#define  ARCH_CAPS_SSB_NO                   (_AC(1, ULL) <<  4)
#define  ARCH_CAPS_MDS_NO                   (_AC(1, ULL) <<  5)
#define  ARCH_CAPS_IF_PSCHANGE_MC_NO        (_AC(1, ULL) <<  6)
#define  ARCH_CAPS_TSX_CTRL                 (_AC(1, ULL) <<  7)
#define  ARCH_CAPS_TAA_NO                   (_AC(1, ULL) <<  8)
#define  ARCH_CAPS_MISC_PACKAGE_CTRL        (_AC(1, ULL) << 10)
#define  ARCH_CAPS_ENERGY_FILTERING         (_AC(1, ULL) << 11)
#define  ARCH_CAPS_DOITM                    (_AC(1, ULL) << 12)
#define  ARCH_CAPS_SBDR_SSDP_NO             (_AC(1, ULL) << 13)
#define  ARCH_CAPS_FBSDP_NO                 (_AC(1, ULL) << 14)
#define  ARCH_CAPS_PSDP_NO                  (_AC(1, ULL) << 15)
#define  ARCH_CAPS_FB_CLEAR                 (_AC(1, ULL) << 17)
#define  ARCH_CAPS_FB_CLEAR_CTRL            (_AC(1, ULL) << 18)
#define  ARCH_CAPS_RRSBA                    (_AC(1, ULL) << 19)
#define  ARCH_CAPS_BHI_NO                   (_AC(1, ULL) << 20)
#define  ARCH_CAPS_PBRSB_NO                 (_AC(1, ULL) << 24)
#define  ARCH_CAPS_GDS_CTRL                 (_AC(1, ULL) << 25)
#define  ARCH_CAPS_GDS_NO                   (_AC(1, ULL) << 26)

#define MSR_FLUSH_CMD                       0x0000010b
#define  FLUSH_CMD_L1D                      (_AC(1, ULL) <<  0)

#define MSR_TSX_FORCE_ABORT                 0x0000010f
#define  TSX_FORCE_ABORT_RTM                (_AC(1, ULL) <<  0)
#define  TSX_CPUID_CLEAR                    (_AC(1, ULL) <<  1)
#define  TSX_ENABLE_RTM                     (_AC(1, ULL) <<  2)

#define MSR_TSX_CTRL                        0x00000122
#define  TSX_CTRL_RTM_DISABLE               (_AC(1, ULL) <<  0)
#define  TSX_CTRL_CPUID_CLEAR               (_AC(1, ULL) <<  1)

#define MSR_MCU_OPT_CTRL                    0x00000123
#define  MCU_OPT_CTRL_RNGDS_MITG_DIS        (_AC(1, ULL) <<  0)
#define  MCU_OPT_CTRL_RTM_ALLOW             (_AC(1, ULL) <<  1)
#define  MCU_OPT_CTRL_RTM_LOCKED            (_AC(1, ULL) <<  2)
#define  MCU_OPT_CTRL_FB_CLEAR_DIS          (_AC(1, ULL) <<  3)
#define  MCU_OPT_CTRL_GDS_MIT_DIS           (_AC(1, ULL) <<  4)
#define  MCU_OPT_CTRL_GDS_MIT_LOCK          (_AC(1, ULL) <<  5)

#define MSR_RTIT_OUTPUT_BASE                0x00000560
#define MSR_RTIT_OUTPUT_MASK                0x00000561
#define MSR_RTIT_CTL                        0x00000570
#define  RTIT_CTL_TRACE_EN                  (_AC(1, ULL) <<  0)
#define  RTIT_CTL_CYC_EN                    (_AC(1, ULL) <<  1)
#define  RTIT_CTL_OS                        (_AC(1, ULL) <<  2)
#define  RTIT_CTL_USR                       (_AC(1, ULL) <<  3)
#define  RTIT_CTL_PWR_EVT_EN                (_AC(1, ULL) <<  4)
#define  RTIT_CTL_FUP_ON_PTW                (_AC(1, ULL) <<  5)
#define  RTIT_CTL_FABRIC_EN                 (_AC(1, ULL) <<  6)
#define  RTIT_CTL_CR3_FILTER                (_AC(1, ULL) <<  7)
#define  RTIT_CTL_TOPA                      (_AC(1, ULL) <<  8)
#define  RTIT_CTL_MTC_EN                    (_AC(1, ULL) <<  9)
#define  RTIT_CTL_TSC_EN                    (_AC(1, ULL) << 10)
#define  RTIT_CTL_DIS_RETC                  (_AC(1, ULL) << 11)
#define  RTIT_CTL_PTW_EN                    (_AC(1, ULL) << 12)
#define  RTIT_CTL_BRANCH_EN                 (_AC(1, ULL) << 13)
#define  RTIT_CTL_MTC_FREQ                  (_AC(0xf, ULL) << 14)
#define  RTIT_CTL_CYC_THRESH                (_AC(0xf, ULL) << 19)
#define  RTIT_CTL_PSB_FREQ                  (_AC(0xf, ULL) << 24)
#define  RTIT_CTL_ADDR(n)                   (_AC(0xf, ULL) << (32 + 4 * (n)))
#define MSR_RTIT_STATUS                     0x00000571
#define  RTIT_STATUS_FILTER_EN              (_AC(1, ULL) <<  0)
#define  RTIT_STATUS_CONTEXT_EN             (_AC(1, ULL) <<  1)
#define  RTIT_STATUS_TRIGGER_EN             (_AC(1, ULL) <<  2)
#define  RTIT_STATUS_ERROR                  (_AC(1, ULL) <<  4)
#define  RTIT_STATUS_STOPPED                (_AC(1, ULL) <<  5)
#define  RTIT_STATUS_BYTECNT                (_AC(0x1ffff, ULL) << 32)
#define MSR_RTIT_CR3_MATCH                  0x00000572
#define MSR_RTIT_ADDR_A(n)                 (0x00000580 + (n) * 2)
#define MSR_RTIT_ADDR_B(n)                 (0x00000581 + (n) * 2)

#define MSR_U_CET                           0x000006a0
#define MSR_S_CET                           0x000006a2
#define  CET_SHSTK_EN                       (_AC(1, ULL) <<  0)
#define  CET_WRSS_EN                        (_AC(1, ULL) <<  1)
#define  CET_ENDBR_EN                       (_AC(1, ULL) <<  2)

#define MSR_PL0_SSP                         0x000006a4
#define MSR_PL1_SSP                         0x000006a5
#define MSR_PL2_SSP                         0x000006a6
#define MSR_PL3_SSP                         0x000006a7
#define MSR_INTERRUPT_SSP_TABLE             0x000006a8

#define MSR_PKRS                            0x000006e1

#define MSR_PM_ENABLE                       0x00000770
#define  PM_ENABLE_HWP_ENABLE               BIT(0, ULL)

#define MSR_HWP_CAPABILITIES                0x00000771
#define MSR_HWP_INTERRUPT                   0x00000773
#define MSR_HWP_REQUEST                     0x00000774
#define MSR_HWP_STATUS                      0x00000777

#define MSR_X2APIC_FIRST                    0x00000800
#define MSR_X2APIC_LAST                     0x000008ff

#define MSR_X2APIC_TPR                      0x00000808
#define MSR_X2APIC_PPR                      0x0000080a
#define MSR_X2APIC_EOI                      0x0000080b
#define MSR_X2APIC_TMICT                    0x00000838
#define MSR_X2APIC_TMCCT                    0x00000839
#define MSR_X2APIC_SELF                     0x0000083f

#define MSR_PASID                           0x00000d93
#define  PASID_PASID_MASK                   0x000fffff
#define  PASID_VALID                        (_AC(1, ULL) << 31)

#define MSR_PKG_HDC_CTL                     0x00000db0
#define  PKG_HDC_CTL_HDC_PKG_ENABLE         BIT(0, ULL)
#define MSR_PM_CTL1                         0x00000db1
#define  PM_CTL1_HDC_ALLOW_BLOCK            BIT(0, ULL)

#define MSR_MCU_CONTROL                     0x00001406
#define  MCU_CONTROL_LOCK                   (_AC(1, ULL) <<  0)
#define  MCU_CONTROL_DIS_MCU_LOAD           (_AC(1, ULL) <<  1)
#define  MCU_CONTROL_EN_SMM_BYPASS          (_AC(1, ULL) <<  2)

#define MSR_UARCH_MISC_CTRL                 0x00001b01
#define  UARCH_CTRL_DOITM                   (_AC(1, ULL) <<  0)

#define MSR_EFER                            0xc0000080 /* Extended Feature Enable Register */
#define  EFER_SCE                           (_AC(1, ULL) <<  0) /* SYSCALL Enable */
#define  EFER_LME                           (_AC(1, ULL) <<  8) /* Long Mode Enable */
#define  EFER_LMA                           (_AC(1, ULL) << 10) /* Long Mode Active */
#define  EFER_NXE                           (_AC(1, ULL) << 11) /* No Execute Enable */
#define  EFER_SVME                          (_AC(1, ULL) << 12) /* Secure Virtual Machine Enable */
#define  EFER_FFXSE                         (_AC(1, ULL) << 14) /* Fast FXSAVE/FXRSTOR */
#define  EFER_AIBRSE                        (_AC(1, ULL) << 21) /* Automatic IBRS Enable */

#define EFER_KNOWN_MASK \
    (EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE | EFER_SVME | EFER_FFXSE | \
     EFER_AIBRSE)

#define MSR_STAR                            0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR                           0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR                           0xc0000083 /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK                    0xc0000084 /* EFLAGS mask for syscall */
#define MSR_FS_BASE                         0xc0000100 /* 64bit FS base */
#define MSR_GS_BASE                         0xc0000101 /* 64bit GS base */
#define MSR_SHADOW_GS_BASE                  0xc0000102 /* SwapGS GS shadow */
#define MSR_TSC_AUX                         0xc0000103 /* Auxiliary TSC */

#define MSR_K8_SYSCFG                       0xc0010010
#define  SYSCFG_MTRR_FIX_DRAM_EN            (_AC(1, ULL) << 18)
#define  SYSCFG_MTRR_FIX_DRAM_MOD_EN        (_AC(1, ULL) << 19)
#define  SYSCFG_MTRR_VAR_DRAM_EN            (_AC(1, ULL) << 20)
#define  SYSCFG_MTRR_TOM2_EN                (_AC(1, ULL) << 21)
#define  SYSCFG_TOM2_FORCE_WB               (_AC(1, ULL) << 22)

#define MSR_K8_IORR_BASE0                   0xc0010016
#define MSR_K8_IORR_MASK0                   0xc0010017
#define MSR_K8_IORR_BASE1                   0xc0010018
#define MSR_K8_IORR_MASK1                   0xc0010019

#define MSR_K8_TSEG_BASE                    0xc0010112 /* AMD doc: SMMAddr */
#define MSR_K8_TSEG_MASK                    0xc0010113 /* AMD doc: SMMMask */

#define MSR_K8_VM_CR                        0xc0010114
#define  VM_CR_INIT_REDIRECTION             (_AC(1, ULL) <<  1)
#define  VM_CR_SVM_DISABLE                  (_AC(1, ULL) <<  4)

#define MSR_VIRT_SPEC_CTRL                  0xc001011f /* Layout matches MSR_SPEC_CTRL */

#define MSR_AMD_CSTATE_CFG                  0xc0010296

/*
 * Legacy MSR constants in need of cleanup.  No new MSRs below this comment.
 */

/* Intel MSRs. Some also available on other CPUs */
#define MSR_IA32_PERFCTR0		0x000000c1
#define MSR_IA32_A_PERFCTR0		0x000004c1
#define MSR_FSB_FREQ			0x000000cd

#define MSR_MTRRcap			0x000000fe
#define MTRRcap_VCNT			0x000000ff

#define MSR_IA32_BBL_CR_CTL		0x00000119

#define MSR_IA32_SYSENTER_CS		0x00000174
#define MSR_IA32_SYSENTER_ESP		0x00000175
#define MSR_IA32_SYSENTER_EIP		0x00000176

#define MSR_IA32_MCG_CAP		0x00000179
#define MSR_IA32_MCG_STATUS		0x0000017a
#define MSR_IA32_MCG_CTL		0x0000017b
#define MSR_IA32_MCG_EXT_CTL	0x000004d0

#define MSR_IA32_PEBS_ENABLE		0x000003f1
#define MSR_IA32_DS_AREA		0x00000600
#define MSR_IA32_PERF_CAPABILITIES	0x00000345
/* Lower 6 bits define the format of the address in the LBR stack */
#define MSR_IA32_PERF_CAP_LBR_FORMAT	0x3f

#define MSR_IA32_BNDCFGS		0x00000d90
#define IA32_BNDCFGS_ENABLE		0x00000001
#define IA32_BNDCFGS_PRESERVE		0x00000002
#define IA32_BNDCFGS_RESERVED		0x00000ffc

#define MSR_IA32_XSS			0x00000da0

#define MSR_MTRRfix64K_00000		0x00000250
#define MSR_MTRRfix16K_80000		0x00000258
#define MSR_MTRRfix16K_A0000		0x00000259
#define MSR_MTRRfix4K_C0000		0x00000268
#define MSR_MTRRfix4K_C8000		0x00000269
#define MSR_MTRRfix4K_D0000		0x0000026a
#define MSR_MTRRfix4K_D8000		0x0000026b
#define MSR_MTRRfix4K_E0000		0x0000026c
#define MSR_MTRRfix4K_E8000		0x0000026d
#define MSR_MTRRfix4K_F0000		0x0000026e
#define MSR_MTRRfix4K_F8000		0x0000026f
#define MSR_MTRRdefType			0x000002ff
#define MTRRdefType_FE			(1u << 10)
#define MTRRdefType_E			(1u << 11)

#define MSR_IA32_DEBUGCTLMSR		0x000001d9
#define IA32_DEBUGCTLMSR_LBR		(1<<0) /* Last Branch Record */
#define IA32_DEBUGCTLMSR_BTF		(1<<1) /* Single Step on Branches */
#define IA32_DEBUGCTLMSR_TR		(1<<6) /* Trace Message Enable */
#define IA32_DEBUGCTLMSR_BTS		(1<<7) /* Branch Trace Store */
#define IA32_DEBUGCTLMSR_BTINT		(1<<8) /* Branch Trace Interrupt */
#define IA32_DEBUGCTLMSR_BTS_OFF_OS	(1<<9)  /* BTS off if CPL 0 */
#define IA32_DEBUGCTLMSR_BTS_OFF_USR	(1<<10) /* BTS off if CPL > 0 */
#define IA32_DEBUGCTLMSR_RTM		(1<<15) /* RTM debugging enable */

#define MSR_IA32_LASTBRANCHFROMIP	0x000001db
#define MSR_IA32_LASTBRANCHTOIP		0x000001dc
#define MSR_IA32_LASTINTFROMIP		0x000001dd
#define MSR_IA32_LASTINTTOIP		0x000001de

#define MSR_IA32_POWER_CTL		0x000001fc

#define MSR_IA32_MTRR_PHYSBASE(n)   (0x00000200 + 2 * (n))
#define MSR_IA32_MTRR_PHYSMASK(n)   (0x00000201 + 2 * (n))

#define MSR_IA32_CR_PAT             0x00000277
#define MSR_IA32_CR_PAT_RESET       0x0007040600070406ULL

#define MSR_IA32_MC0_CTL		0x00000400
#define MSR_IA32_MC0_STATUS		0x00000401
#define MSR_IA32_MC0_ADDR		0x00000402
#define MSR_IA32_MC0_MISC		0x00000403
#define MSR_IA32_MC0_CTL2		0x00000280
#define CMCI_EN 			(1UL<<30)
#define CMCI_THRESHOLD_MASK		0x7FFF

#define MSR_AMD64_MC0_MASK		0xc0010044

#define MSR_IA32_MCx_CTL(x)		(MSR_IA32_MC0_CTL + 4*(x))
#define MSR_IA32_MCx_STATUS(x)		(MSR_IA32_MC0_STATUS + 4*(x))
#define MSR_IA32_MCx_ADDR(x)		(MSR_IA32_MC0_ADDR + 4*(x))
#define MSR_IA32_MCx_MISC(x)		(MSR_IA32_MC0_MISC + 4*(x)) 
#define MSR_IA32_MCx_CTL2(x)		(MSR_IA32_MC0_CTL2 + (x))

#define MSR_AMD64_MCx_MASK(x)		(MSR_AMD64_MC0_MASK + (x))

/* MSRs & bits used for VMX enabling */
#define MSR_IA32_VMX_BASIC                      0x480
#define MSR_IA32_VMX_PINBASED_CTLS              0x481
#define MSR_IA32_VMX_PROCBASED_CTLS             0x482
#define MSR_IA32_VMX_EXIT_CTLS                  0x483
#define MSR_IA32_VMX_ENTRY_CTLS                 0x484
#define MSR_IA32_VMX_MISC                       0x485
#define MSR_IA32_VMX_CR0_FIXED0                 0x486
#define MSR_IA32_VMX_CR0_FIXED1                 0x487
#define MSR_IA32_VMX_CR4_FIXED0                 0x488
#define MSR_IA32_VMX_CR4_FIXED1                 0x489
#define MSR_IA32_VMX_VMCS_ENUM                  0x48a
#define MSR_IA32_VMX_PROCBASED_CTLS2            0x48b
#define MSR_IA32_VMX_EPT_VPID_CAP               0x48c
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS         0x48d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS        0x48e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS             0x48f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS            0x490
#define MSR_IA32_VMX_VMFUNC                     0x491

/* K7/K8 MSRs. Not complete. See the architecture manual for a more
   complete list. */
#define MSR_K7_EVNTSEL0			0xc0010000
#define MSR_K7_PERFCTR0			0xc0010004
#define MSR_K7_EVNTSEL1			0xc0010001
#define MSR_K7_PERFCTR1			0xc0010005
#define MSR_K7_EVNTSEL2			0xc0010002
#define MSR_K7_PERFCTR2			0xc0010006
#define MSR_K7_EVNTSEL3			0xc0010003
#define MSR_K7_PERFCTR3			0xc0010007
#define MSR_K8_TOP_MEM1			0xc001001a
#define MSR_K8_TOP_MEM2			0xc001001d

#define MSR_K8_HWCR			0xc0010015
#define K8_HWCR_TSC_FREQ_SEL		(1ULL << 24)
#define K8_HWCR_CPUID_USER_DIS		(1ULL << 35)

#define MSR_K7_FID_VID_CTL		0xc0010041
#define MSR_K7_FID_VID_STATUS		0xc0010042
#define MSR_K8_PSTATE_LIMIT		0xc0010061
#define MSR_K8_PSTATE_CTRL		0xc0010062
#define MSR_K8_PSTATE_STATUS		0xc0010063
#define MSR_K8_PSTATE0			0xc0010064
#define MSR_K8_PSTATE1			0xc0010065
#define MSR_K8_PSTATE2			0xc0010066
#define MSR_K8_PSTATE3			0xc0010067
#define MSR_K8_PSTATE4			0xc0010068
#define MSR_K8_PSTATE5			0xc0010069
#define MSR_K8_PSTATE6			0xc001006A
#define MSR_K8_PSTATE7			0xc001006B
#define MSR_K8_ENABLE_C1E		0xc0010055
#define MSR_K8_VM_HSAVE_PA		0xc0010117

#define MSR_AMD_FAM15H_EVNTSEL0		0xc0010200
#define MSR_AMD_FAM15H_PERFCTR0		0xc0010201
#define MSR_AMD_FAM15H_EVNTSEL1		0xc0010202
#define MSR_AMD_FAM15H_PERFCTR1		0xc0010203
#define MSR_AMD_FAM15H_EVNTSEL2		0xc0010204
#define MSR_AMD_FAM15H_PERFCTR2		0xc0010205
#define MSR_AMD_FAM15H_EVNTSEL3		0xc0010206
#define MSR_AMD_FAM15H_PERFCTR3		0xc0010207
#define MSR_AMD_FAM15H_EVNTSEL4		0xc0010208
#define MSR_AMD_FAM15H_PERFCTR4		0xc0010209
#define MSR_AMD_FAM15H_EVNTSEL5		0xc001020a
#define MSR_AMD_FAM15H_PERFCTR5		0xc001020b

#define MSR_AMD_L7S0_FEATURE_MASK	0xc0011002
#define MSR_AMD_THRM_FEATURE_MASK	0xc0011003
#define MSR_K8_FEATURE_MASK		0xc0011004
#define MSR_K8_EXT_FEATURE_MASK		0xc0011005

/* AMD64 MSRs */
#define MSR_AMD64_NB_CFG		0xc001001f
#define AMD64_NB_CFG_CF8_EXT_ENABLE_BIT	46
#define MSR_AMD64_LS_CFG		0xc0011020
#define MSR_AMD64_IC_CFG		0xc0011021
#define MSR_AMD64_DC_CFG		0xc0011022
#define MSR_AMD64_DE_CFG		0xc0011029
#define AMD64_DE_CFG_LFENCE_SERIALISE	(_AC(1, ULL) << 1)
#define MSR_AMD64_EX_CFG		0xc001102c
#define MSR_AMD64_BP_CFG		0xc001102e
#define MSR_AMD64_DE_CFG2		0xc00110e3

#define MSR_AMD64_DR0_ADDRESS_MASK	0xc0011027
#define MSR_AMD64_DR1_ADDRESS_MASK	0xc0011019
#define MSR_AMD64_DR2_ADDRESS_MASK	0xc001101a
#define MSR_AMD64_DR3_ADDRESS_MASK	0xc001101b

/* AMD Family10h machine check MSRs */
#define MSR_F10_MC4_MISC1		0xc0000408
#define MSR_F10_MC4_MISC2		0xc0000409
#define MSR_F10_MC4_MISC3		0xc000040A

/* AMD Family10h Bus Unit MSRs */
#define MSR_F10_BU_CFG 		0xc0011023
#define MSR_F10_BU_CFG2		0xc001102a

/* Other AMD Fam10h MSRs */
#define MSR_FAM10H_MMIO_CONF_BASE	0xc0010058
#define FAM10H_MMIO_CONF_ENABLE         (1<<0)
#define FAM10H_MMIO_CONF_BUSRANGE_MASK	0xf
#define FAM10H_MMIO_CONF_BUSRANGE_SHIFT 2
#define FAM10H_MMIO_CONF_BASE_MASK	0xfffffffULL
#define FAM10H_MMIO_CONF_BASE_SHIFT	20

/* AMD Microcode MSRs */
#define MSR_AMD_PATCHLEVEL		0x0000008b
#define MSR_AMD_PATCHLOADER		0xc0010020

/* AMD TSC RATE MSR */
#define MSR_AMD64_TSC_RATIO		0xc0000104

/* AMD Lightweight Profiling MSRs */
#define MSR_AMD64_LWP_CFG		0xc0000105
#define MSR_AMD64_LWP_CBADDR		0xc0000106

/* AMD OS Visible Workaround MSRs */
#define MSR_AMD_OSVW_ID_LENGTH          0xc0010140
#define MSR_AMD_OSVW_STATUS             0xc0010141

/* AMD Protected Processor Inventory Number */
#define MSR_AMD_PPIN_CTL                0xc00102f0
#define MSR_AMD_PPIN                    0xc00102f1

/* VIA Cyrix defined MSRs*/
#define MSR_VIA_FCR			0x00001107
#define MSR_VIA_RNG			0x0000110b

/* Intel defined MSRs. */
#define MSR_IA32_TSC			0x00000010
#define MSR_IA32_PLATFORM_ID		0x00000017
#define MSR_IA32_EBL_CR_POWERON		0x0000002a
#define MSR_IA32_EBC_FREQUENCY_ID	0x0000002c

#define MSR_IA32_FEATURE_CONTROL	0x0000003a
#define IA32_FEATURE_CONTROL_LOCK                     0x0001
#define IA32_FEATURE_CONTROL_ENABLE_VMXON_INSIDE_SMX  0x0002
#define IA32_FEATURE_CONTROL_ENABLE_VMXON_OUTSIDE_SMX 0x0004
#define IA32_FEATURE_CONTROL_SENTER_PARAM_CTL         0x7f00
#define IA32_FEATURE_CONTROL_ENABLE_SENTER            0x8000
#define IA32_FEATURE_CONTROL_SGX_ENABLE               0x40000
#define IA32_FEATURE_CONTROL_LMCE_ON                  0x100000

#define MSR_IA32_TSC_ADJUST		0x0000003b

#define MSR_IA32_UCODE_WRITE		0x00000079
#define MSR_IA32_UCODE_REV		0x0000008b

#define MSR_IA32_PERF_STATUS		0x00000198
#define MSR_IA32_PERF_CTL		0x00000199

#define MSR_IA32_MPERF			0x000000e7
#define MSR_IA32_APERF			0x000000e8

#define MSR_IA32_THERM_CONTROL		0x0000019a
#define MSR_IA32_THERM_INTERRUPT	0x0000019b
#define MSR_IA32_THERM_STATUS		0x0000019c
#define MSR_IA32_MISC_ENABLE		0x000001a0
#define MSR_IA32_MISC_ENABLE_PERF_AVAIL   (1<<7)
#define MSR_IA32_MISC_ENABLE_BTS_UNAVAIL  (1<<11)
#define MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL (1<<12)
#define MSR_IA32_MISC_ENABLE_MONITOR_ENABLE (1<<18)
#define MSR_IA32_MISC_ENABLE_LIMIT_CPUID  (1<<22)
#define MSR_IA32_MISC_ENABLE_XTPR_DISABLE (1<<23)
#define MSR_IA32_MISC_ENABLE_XD_DISABLE      (_AC(1, ULL) << 34)
#define MSR_IA32_MISC_ENABLE_TURBO_DISENGAGE (_AC(1, ULL) << 38)

#define MSR_IA32_TSC_DEADLINE		0x000006E0
#define MSR_IA32_ENERGY_PERF_BIAS	0x000001b0

/* Platform Shared Resource MSRs */
#define MSR_IA32_CMT_EVTSEL		0x00000c8d
#define MSR_IA32_CMT_EVTSEL_UE_MASK	0x0000ffff
#define MSR_IA32_CMT_CTR		0x00000c8e
#define MSR_IA32_PSR_ASSOC		0x00000c8f
#define MSR_IA32_PSR_L3_QOS_CFG	0x00000c81
#define MSR_IA32_PSR_L3_MASK(n)	(0x00000c90 + (n))
#define MSR_IA32_PSR_L3_MASK_CODE(n)	(0x00000c90 + (n) * 2 + 1)
#define MSR_IA32_PSR_L3_MASK_DATA(n)	(0x00000c90 + (n) * 2)
#define MSR_IA32_PSR_L2_MASK(n)		(0x00000d10 + (n))
#define MSR_IA32_PSR_MBA_MASK(n)	(0x00000d50 + (n))

/* Intel Model 6 */
#define MSR_P6_PERFCTR(n)		(0x000000c1 + (n))
#define MSR_P6_EVNTSEL(n)		(0x00000186 + (n))

/* P4/Xeon+ specific */
#define MSR_IA32_MCG_EAX		0x00000180
#define MSR_IA32_MCG_EBX		0x00000181
#define MSR_IA32_MCG_ECX		0x00000182
#define MSR_IA32_MCG_EDX		0x00000183
#define MSR_IA32_MCG_ESI		0x00000184
#define MSR_IA32_MCG_EDI		0x00000185
#define MSR_IA32_MCG_EBP		0x00000186
#define MSR_IA32_MCG_ESP		0x00000187
#define MSR_IA32_MCG_EFLAGS		0x00000188
#define MSR_IA32_MCG_EIP		0x00000189
#define MSR_IA32_MCG_MISC		0x0000018a
#define MSR_IA32_MCG_R8			0x00000190
#define MSR_IA32_MCG_R9			0x00000191
#define MSR_IA32_MCG_R10		0x00000192
#define MSR_IA32_MCG_R11		0x00000193
#define MSR_IA32_MCG_R12		0x00000194
#define MSR_IA32_MCG_R13		0x00000195
#define MSR_IA32_MCG_R14		0x00000196
#define MSR_IA32_MCG_R15		0x00000197

/* Pentium IV performance counter MSRs */
#define MSR_P4_BPU_PERFCTR0		0x00000300
#define MSR_P4_BPU_PERFCTR1		0x00000301
#define MSR_P4_BPU_PERFCTR2		0x00000302
#define MSR_P4_BPU_PERFCTR3		0x00000303
#define MSR_P4_MS_PERFCTR0		0x00000304
#define MSR_P4_MS_PERFCTR1		0x00000305
#define MSR_P4_MS_PERFCTR2		0x00000306
#define MSR_P4_MS_PERFCTR3		0x00000307
#define MSR_P4_FLAME_PERFCTR0		0x00000308
#define MSR_P4_FLAME_PERFCTR1		0x00000309
#define MSR_P4_FLAME_PERFCTR2		0x0000030a
#define MSR_P4_FLAME_PERFCTR3		0x0000030b
#define MSR_P4_IQ_PERFCTR0		0x0000030c
#define MSR_P4_IQ_PERFCTR1		0x0000030d
#define MSR_P4_IQ_PERFCTR2		0x0000030e
#define MSR_P4_IQ_PERFCTR3		0x0000030f
#define MSR_P4_IQ_PERFCTR4		0x00000310
#define MSR_P4_IQ_PERFCTR5		0x00000311
#define MSR_P4_BPU_CCCR0		0x00000360
#define MSR_P4_BPU_CCCR1		0x00000361
#define MSR_P4_BPU_CCCR2		0x00000362
#define MSR_P4_BPU_CCCR3		0x00000363
#define MSR_P4_MS_CCCR0			0x00000364
#define MSR_P4_MS_CCCR1			0x00000365
#define MSR_P4_MS_CCCR2			0x00000366
#define MSR_P4_MS_CCCR3			0x00000367
#define MSR_P4_FLAME_CCCR0		0x00000368
#define MSR_P4_FLAME_CCCR1		0x00000369
#define MSR_P4_FLAME_CCCR2		0x0000036a
#define MSR_P4_FLAME_CCCR3		0x0000036b
#define MSR_P4_IQ_CCCR0			0x0000036c
#define MSR_P4_IQ_CCCR1			0x0000036d
#define MSR_P4_IQ_CCCR2			0x0000036e
#define MSR_P4_IQ_CCCR3			0x0000036f
#define MSR_P4_IQ_CCCR4			0x00000370
#define MSR_P4_IQ_CCCR5			0x00000371
#define MSR_P4_ALF_ESCR0		0x000003ca
#define MSR_P4_ALF_ESCR1		0x000003cb
#define MSR_P4_BPU_ESCR0		0x000003b2
#define MSR_P4_BPU_ESCR1		0x000003b3
#define MSR_P4_BSU_ESCR0		0x000003a0
#define MSR_P4_BSU_ESCR1		0x000003a1
#define MSR_P4_CRU_ESCR0		0x000003b8
#define MSR_P4_CRU_ESCR1		0x000003b9
#define MSR_P4_CRU_ESCR2		0x000003cc
#define MSR_P4_CRU_ESCR3		0x000003cd
#define MSR_P4_CRU_ESCR4		0x000003e0
#define MSR_P4_CRU_ESCR5		0x000003e1
#define MSR_P4_DAC_ESCR0		0x000003a8
#define MSR_P4_DAC_ESCR1		0x000003a9
#define MSR_P4_FIRM_ESCR0		0x000003a4
#define MSR_P4_FIRM_ESCR1		0x000003a5
#define MSR_P4_FLAME_ESCR0		0x000003a6
#define MSR_P4_FLAME_ESCR1		0x000003a7
#define MSR_P4_FSB_ESCR0		0x000003a2
#define MSR_P4_FSB_ESCR1		0x000003a3
#define MSR_P4_IQ_ESCR0			0x000003ba
#define MSR_P4_IQ_ESCR1			0x000003bb
#define MSR_P4_IS_ESCR0			0x000003b4
#define MSR_P4_IS_ESCR1			0x000003b5
#define MSR_P4_ITLB_ESCR0		0x000003b6
#define MSR_P4_ITLB_ESCR1		0x000003b7
#define MSR_P4_IX_ESCR0			0x000003c8
#define MSR_P4_IX_ESCR1			0x000003c9
#define MSR_P4_MOB_ESCR0		0x000003aa
#define MSR_P4_MOB_ESCR1		0x000003ab
#define MSR_P4_MS_ESCR0			0x000003c0
#define MSR_P4_MS_ESCR1			0x000003c1
#define MSR_P4_PMH_ESCR0		0x000003ac
#define MSR_P4_PMH_ESCR1		0x000003ad
#define MSR_P4_RAT_ESCR0		0x000003bc
#define MSR_P4_RAT_ESCR1		0x000003bd
#define MSR_P4_SAAT_ESCR0		0x000003ae
#define MSR_P4_SAAT_ESCR1		0x000003af
#define MSR_P4_SSU_ESCR0		0x000003be
#define MSR_P4_SSU_ESCR1		0x000003bf /* guess: not in manual */

#define MSR_P4_TBPU_ESCR0		0x000003c2
#define MSR_P4_TBPU_ESCR1		0x000003c3
#define MSR_P4_TC_ESCR0			0x000003c4
#define MSR_P4_TC_ESCR1			0x000003c5
#define MSR_P4_U2L_ESCR0		0x000003b0
#define MSR_P4_U2L_ESCR1		0x000003b1

/* Netburst (P4) last-branch recording */
#define MSR_P4_LER_FROM_LIP 		0x000001d7
#define MSR_P4_LER_TO_LIP 		0x000001d8
#define MSR_P4_LASTBRANCH_TOS		0x000001da
#define MSR_P4_LASTBRANCH_0		0x000001db
#define NUM_MSR_P4_LASTBRANCH		4
#define MSR_P4_LASTBRANCH_0_FROM_LIP	0x00000680
#define MSR_P4_LASTBRANCH_0_TO_LIP	0x000006c0
#define NUM_MSR_P4_LASTBRANCH_FROM_TO	16

/* Core 2 and Atom last-branch recording */
#define MSR_C2_LASTBRANCH_TOS		0x000001c9
#define MSR_C2_LASTBRANCH_0_FROM_IP	0x00000040
#define MSR_C2_LASTBRANCH_0_TO_IP	0x00000060
#define NUM_MSR_C2_LASTBRANCH_FROM_TO	4
#define NUM_MSR_ATOM_LASTBRANCH_FROM_TO	8

/* Nehalem (and newer) last-branch recording */
#define MSR_NHL_LBR_SELECT		0x000001c8
#define MSR_NHL_LASTBRANCH_TOS		0x000001c9

/* Skylake (and newer) last-branch recording */
#define MSR_SKL_LASTBRANCH_0_FROM_IP	0x00000680
#define MSR_SKL_LASTBRANCH_0_TO_IP	0x000006c0
#define MSR_SKL_LASTBRANCH_0_INFO	0x00000dc0
#define NUM_MSR_SKL_LASTBRANCH		32

/* Silvermont (and newer) last-branch recording */
#define MSR_SM_LBR_SELECT		0x000001c8
#define MSR_SM_LASTBRANCH_TOS		0x000001c9

/* Goldmont last-branch recording */
#define MSR_GM_LASTBRANCH_0_FROM_IP	0x00000680
#define MSR_GM_LASTBRANCH_0_TO_IP	0x000006c0
#define NUM_MSR_GM_LASTBRANCH_FROM_TO	32

/* Intel Core-based CPU performance counters */
#define MSR_CORE_PERF_FIXED_CTR0	0x00000309
#define MSR_CORE_PERF_FIXED_CTR1	0x0000030a
#define MSR_CORE_PERF_FIXED_CTR2	0x0000030b
#define MSR_CORE_PERF_FIXED_CTR_CTRL	0x0000038d
#define MSR_CORE_PERF_GLOBAL_STATUS	0x0000038e
#define MSR_CORE_PERF_GLOBAL_CTRL	0x0000038f
#define MSR_CORE_PERF_GLOBAL_OVF_CTRL	0x00000390

/* Intel cpuid spoofing MSRs */
#define MSR_INTEL_MASK_V1_CPUID1        0x00000478

#define MSR_INTEL_MASK_V2_CPUID1        0x00000130
#define MSR_INTEL_MASK_V2_CPUID80000001 0x00000131

#define MSR_INTEL_MASK_V3_CPUID1        0x00000132
#define MSR_INTEL_MASK_V3_CPUID80000001 0x00000133
#define MSR_INTEL_MASK_V3_CPUIDD_01     0x00000134

/* Intel cpuid faulting MSRs */
#define MSR_INTEL_PLATFORM_INFO		0x000000ce
#define _MSR_PLATFORM_INFO_CPUID_FAULTING	31
#define MSR_PLATFORM_INFO_CPUID_FAULTING	(1ULL << _MSR_PLATFORM_INFO_CPUID_FAULTING)

#define MSR_INTEL_MISC_FEATURES_ENABLES	0x00000140
#define _MSR_MISC_FEATURES_CPUID_FAULTING	0
#define MSR_MISC_FEATURES_CPUID_FAULTING	(1ULL << _MSR_MISC_FEATURES_CPUID_FAULTING)

#define MSR_CC6_DEMOTION_POLICY_CONFIG	0x00000668
#define MSR_MC6_DEMOTION_POLICY_CONFIG	0x00000669

/* Interrupt Response Limit */
#define MSR_PKGC3_IRTL			0x0000060a
#define MSR_PKGC6_IRTL			0x0000060b
#define MSR_PKGC7_IRTL			0x0000060c
#define MSR_PKGC8_IRTL			0x00000633
#define MSR_PKGC9_IRTL			0x00000634
#define MSR_PKGC10_IRTL			0x00000635

#endif /* __ASM_MSR_INDEX_H */
