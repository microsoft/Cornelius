// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#define CR0_PE          0x00000001
#define CR0_MP          0x00000002
#define CR0_EM          0x00000004
#define CR0_TS          0x00000008
#define CR0_ET          0x00000010
#define CR0_NE          0x00000020
#define CR0_WP          0x00010000
#define CR0_AM          0x00040000
#define CR0_NW          0x20000000
#define CR0_CD          0x40000000
#define CR0_PG          0x80000000

#define CR4_VME         0x00000001
#define CR4_PVI         0x00000002
#define CR4_TSD         0x00000004
#define CR4_DE          0x00000008
#define CR4_PSE         0x00000010
#define CR4_PAE         0x00000020
#define CR4_MCE         0x00000040
#define CR4_PGE         0x00000080
#define CR4_PCE         0x00000100
#define CR4_OSFXSR      0x00000200
#define CR4_OSXMMEXCPT  0x00000400
#define CR4_UMIP        0x00000800
#define CR4_LA57        0x00001000
#define CR4_VMXE        0x00002000
#define CR4_SMXE        0x00004000
#define CR4_FSGSBASE    0x00010000
#define CR4_PCIDE       0x00020000
#define CR4_OSXSAVE     0x00040000
#define CR4_SMEP        0x00100000
#define CR4_SMAP        0x00200000
#define CR4_PKE         0x00400000
#define CR4_CET         0x00800000
#define CR4_PKS         0x01000000

#define EFER_SCE    0x00000001
#define EFER_LME    0x00000100
#define EFER_LMA    0x00000400
#define EFER_NXE    0x00000800
#define EFER_SVME   0x00001000
#define EFER_LMSLE  0x00002000
#define EFER_FFXSR  0x00004000
#define EFER_TCE    0x00008000

#define IA32_CR_S_CET_SH_STK_EN_MASK           0x0000000000000001
#define IA32_CR_S_CET_ENDBR_EN_MASK            0x0000000000000004
#define IA32_CR_S_CET_NO_TRACK_EN_MASK         0x0000000000000010

/* Fn0000_0001:ECX */
#define CPUID_0_01_ECX_SSE3		__BIT(0)
#define CPUID_0_01_ECX_PCLMULQDQ	__BIT(1)
#define CPUID_0_01_ECX_DTES64		__BIT(2)
#define CPUID_0_01_ECX_MONITOR		__BIT(3)
#define CPUID_0_01_ECX_DS_CPL		__BIT(4)
#define CPUID_0_01_ECX_VMX		__BIT(5)
#define CPUID_0_01_ECX_SMX		__BIT(6)
#define CPUID_0_01_ECX_EIST		__BIT(7)
#define CPUID_0_01_ECX_TM2		__BIT(8)
#define CPUID_0_01_ECX_SSSE3		__BIT(9)
#define CPUID_0_01_ECX_CNXTID		__BIT(10)
#define CPUID_0_01_ECX_SDBG		__BIT(11)
#define CPUID_0_01_ECX_FMA		__BIT(12)
#define CPUID_0_01_ECX_CX16		__BIT(13)
#define CPUID_0_01_ECX_XTPR		__BIT(14)
#define CPUID_0_01_ECX_PDCM		__BIT(15)
#define CPUID_0_01_ECX_PCID		__BIT(17)
#define CPUID_0_01_ECX_DCA		__BIT(18)
#define CPUID_0_01_ECX_SSE41		__BIT(19)
#define CPUID_0_01_ECX_SSE42		__BIT(20)
#define CPUID_0_01_ECX_X2APIC		__BIT(21)
#define CPUID_0_01_ECX_MOVBE		__BIT(22)
#define CPUID_0_01_ECX_POPCNT		__BIT(23)
#define CPUID_0_01_ECX_TSC_DEADLINE	__BIT(24)
#define CPUID_0_01_ECX_AESNI		__BIT(25)
#define CPUID_0_01_ECX_XSAVE		__BIT(26)
#define CPUID_0_01_ECX_OSXSAVE		__BIT(27)
#define CPUID_0_01_ECX_AVX		__BIT(28)
#define CPUID_0_01_ECX_F16C		__BIT(29)
#define CPUID_0_01_ECX_RDRAND		__BIT(30)
#define CPUID_0_01_ECX_RAZ		__BIT(31)
/* Fn0000_0001:EDX */
#define CPUID_0_01_EDX_FPU		__BIT(0)
#define CPUID_0_01_EDX_VME		__BIT(1)
#define CPUID_0_01_EDX_DE		__BIT(2)
#define CPUID_0_01_EDX_PSE		__BIT(3)
#define CPUID_0_01_EDX_TSC		__BIT(4)
#define CPUID_0_01_EDX_MSR		__BIT(5)
#define CPUID_0_01_EDX_PAE		__BIT(6)
#define CPUID_0_01_EDX_MCE		__BIT(7)
#define CPUID_0_01_EDX_CX8		__BIT(8)
#define CPUID_0_01_EDX_APIC		__BIT(9)
#define CPUID_0_01_EDX_SEP		__BIT(11)
#define CPUID_0_01_EDX_MTRR		__BIT(12)
#define CPUID_0_01_EDX_PGE		__BIT(13)
#define CPUID_0_01_EDX_MCA		__BIT(14)
#define CPUID_0_01_EDX_CMOV		__BIT(15)
#define CPUID_0_01_EDX_PAT		__BIT(16)
#define CPUID_0_01_EDX_PSE36		__BIT(17)
#define CPUID_0_01_EDX_PSN		__BIT(18)
#define CPUID_0_01_EDX_CLFSH		__BIT(19)
#define CPUID_0_01_EDX_DS		__BIT(21)
#define CPUID_0_01_EDX_ACPI		__BIT(22)
#define CPUID_0_01_EDX_MMX		__BIT(23)
#define CPUID_0_01_EDX_FXSR		__BIT(24)
#define CPUID_0_01_EDX_SSE		__BIT(25)
#define CPUID_0_01_EDX_SSE2		__BIT(26)
#define CPUID_0_01_EDX_SS		__BIT(27)
#define CPUID_0_01_EDX_HTT		__BIT(28)
#define CPUID_0_01_EDX_TM		__BIT(29)
#define CPUID_0_01_EDX_PBE		__BIT(31)

/* [ECX=0] Fn0000_0007:EBX (Structured Extended Features) */
#define CPUID_0_07_EBX_FSGSBASE		__BIT(0)
#define CPUID_0_07_EBX_TSC_ADJUST	__BIT(1)
#define CPUID_0_07_EBX_SGX		__BIT(2)
#define CPUID_0_07_EBX_BMI1		__BIT(3)
#define CPUID_0_07_EBX_HLE		__BIT(4)
#define CPUID_0_07_EBX_AVX2		__BIT(5)
#define CPUID_0_07_EBX_FDPEXONLY	__BIT(6)
#define CPUID_0_07_EBX_SMEP		__BIT(7)
#define CPUID_0_07_EBX_BMI2		__BIT(8)
#define CPUID_0_07_EBX_ERMS		__BIT(9)
#define CPUID_0_07_EBX_INVPCID		__BIT(10)
#define CPUID_0_07_EBX_RTM		__BIT(11)
#define CPUID_0_07_EBX_QM		__BIT(12)
#define CPUID_0_07_EBX_FPUCSDS		__BIT(13)
#define CPUID_0_07_EBX_MPX		__BIT(14)
#define CPUID_0_07_EBX_PQE		__BIT(15)
#define CPUID_0_07_EBX_AVX512F		__BIT(16)
#define CPUID_0_07_EBX_AVX512DQ		__BIT(17)
#define CPUID_0_07_EBX_RDSEED		__BIT(18)
#define CPUID_0_07_EBX_ADX		__BIT(19)
#define CPUID_0_07_EBX_SMAP		__BIT(20)
#define CPUID_0_07_EBX_AVX512_IFMA	__BIT(21)
#define CPUID_0_07_EBX_CLFLUSHOPT	__BIT(23)
#define CPUID_0_07_EBX_CLWB		__BIT(24)
#define CPUID_0_07_EBX_PT		__BIT(25)
#define CPUID_0_07_EBX_AVX512PF		__BIT(26)
#define CPUID_0_07_EBX_AVX512ER		__BIT(27)
#define CPUID_0_07_EBX_AVX512CD		__BIT(28)
#define CPUID_0_07_EBX_SHA		__BIT(29)
#define CPUID_0_07_EBX_AVX512BW		__BIT(30)
#define CPUID_0_07_EBX_AVX512VL		__BIT(31)
/* [ECX=0] Fn0000_0007:ECX (Structured Extended Features) */
#define CPUID_0_07_ECX_PREFETCHWT1	__BIT(0)
#define CPUID_0_07_ECX_AVX512_VBMI	__BIT(1)
#define CPUID_0_07_ECX_UMIP		__BIT(2)
#define CPUID_0_07_ECX_PKU		__BIT(3)
#define CPUID_0_07_ECX_OSPKE		__BIT(4)
#define CPUID_0_07_ECX_WAITPKG		__BIT(5)
#define CPUID_0_07_ECX_AVX512_VBMI2	__BIT(6)
#define CPUID_0_07_ECX_CET_SS		__BIT(7)
#define CPUID_0_07_ECX_GFNI		__BIT(8)
#define CPUID_0_07_ECX_VAES		__BIT(9)
#define CPUID_0_07_ECX_VPCLMULQDQ	__BIT(10)
#define CPUID_0_07_ECX_AVX512_VNNI	__BIT(11)
#define CPUID_0_07_ECX_AVX512_BITALG	__BIT(12)
#define CPUID_0_07_ECX_AVX512_VPOPCNTDQ __BIT(14)
#define CPUID_0_07_ECX_LA57		__BIT(16)
#define CPUID_0_07_ECX_MAWAU		__BITS(21, 17)
#define CPUID_0_07_ECX_RDPID		__BIT(22)
#define CPUID_0_07_ECX_KL		__BIT(23)
#define CPUID_0_07_ECX_BUS_LOCK_DETECT		__BIT(24)
#define CPUID_0_07_ECX_CLDEMOTE		__BIT(25)
#define CPUID_0_07_ECX_MOVDIRI		__BIT(27)
#define CPUID_0_07_ECX_MOVDIR64B	__BIT(28)
#define CPUID_0_07_ECX_SGXLC		__BIT(30)
#define CPUID_0_07_ECX_PKS		__BIT(31)
/* [ECX=0] Fn0000_0007:EDX (Structured Extended Features) */
#define CPUID_0_07_EDX_AVX512_4VNNIW	__BIT(2)
#define CPUID_0_07_EDX_AVX512_4FMAPS	__BIT(3)
#define CPUID_0_07_EDX_FSREP_MOV	__BIT(4)
#define CPUID_0_07_EDX_AVX512_VP2INTERSECT __BIT(8)
#define CPUID_0_07_EDX_SRBDS_CTRL	__BIT(9)
#define CPUID_0_07_EDX_MD_CLEAR		__BIT(10)
#define CPUID_0_07_EDX_TSX_FORCE_ABORT	__BIT(13)
#define CPUID_0_07_EDX_SERIALIZE	__BIT(14)
#define CPUID_0_07_EDX_HYBRID		__BIT(15)
#define CPUID_0_07_EDX_TSXLDTRK		__BIT(16)
#define CPUID_0_07_EDX_ARCH_LBR		__BIT(19)
#define CPUID_0_07_EDX_CET_IBT		__BIT(20)
#define CPUID_0_07_EDX_IBRS		__BIT(26)
#define CPUID_0_07_EDX_STIBP		__BIT(27)
#define CPUID_0_07_EDX_L1D_FLUSH	__BIT(28)
#define CPUID_0_07_EDX_ARCH_CAP		__BIT(29)
#define CPUID_0_07_EDX_CORE_CAP		__BIT(30)
#define CPUID_0_07_EDX_SSBD		__BIT(31)
/* [ECX=2] Fn0000_0007:EDX (Structured Extended Features) */
#define CPUID_0_07_2_PSFD		__BIT(0)
#define CPUID_0_07_2_IPRED_CTRL	__BIT(1)
#define CPUID_0_07_2_RRSBA_CTRL	__BIT(2)
#define CPUID_0_07_2_DDPD_U	__BIT(3)
#define CPUID_0_07_2_BHI_CTRL	__BIT(4)
#define CPUID_0_07_2_MCDT_NO	__BIT(5)

/* Fn8000_0008:EBX */
#define CPUID_8_08_EBX_CLZERO		__BIT(0)
#define CPUID_8_08_EBX_InstRetCntMsr	__BIT(1)
#define CPUID_8_08_EBX_RstrFpErrPtrs	__BIT(2)
#define CPUID_8_08_EBX_INVLPGB		__BIT(3)
#define CPUID_8_08_EBX_RDPRU		__BIT(4)
#define CPUID_8_08_EBX_MCOMMIT		__BIT(8)
#define CPUID_8_08_EBX_WBNOINVD		__BIT(9)
#define CPUID_8_08_EBX_IBPB		__BIT(12)
#define CPUID_8_08_EBX_INT_WBINVD	__BIT(13)
#define CPUID_8_08_EBX_IBRS		__BIT(14)
#define CPUID_8_08_EBX_STIBP		__BIT(15)
#define CPUID_8_08_EBX_IBRS_ALWAYSON	__BIT(16)
#define CPUID_8_08_EBX_STIBP_ALWAYSON	__BIT(17)
#define CPUID_8_08_EBX_PREFER_IBRS	__BIT(18)
#define CPUID_8_08_EBX_EferLmsleUnsupp	__BIT(20)
#define CPUID_8_08_EBX_INVLPGBnestedPg	__BIT(21)
#define CPUID_8_08_EBX_SSBD		__BIT(24)
#define CPUID_8_08_EBX_VIRT_SSBD	__BIT(25)
#define CPUID_8_08_EBX_SSB_NO		__BIT(26)

#define VMX_GUEST_ES_SELECTOR_ENCODE  0x0800ULL
#define VMX_GUEST_ES_ARBYTE_ENCODE  0x4814ULL
#define VMX_GUEST_ES_LIMIT_ENCODE  0x4800ULL
#define VMX_GUEST_ES_BASE_ENCODE  0x6806ULL
#define VMX_GUEST_CS_SELECTOR_ENCODE  0x0802ULL
#define VMX_GUEST_CS_ARBYTE_ENCODE  0x4816ULL
#define VMX_GUEST_CS_LIMIT_ENCODE  0x4802ULL
#define VMX_GUEST_CS_BASE_ENCODE  0x6808ULL
#define VMX_GUEST_SS_SELECTOR_ENCODE  0x0804ULL
#define VMX_GUEST_SS_ARBYTE_ENCODE  0x4818ULL
#define VMX_GUEST_SS_LIMIT_ENCODE  0x4804ULL
#define VMX_GUEST_SS_BASE_ENCODE  0x680AULL
#define VMX_GUEST_DS_SELECTOR_ENCODE  0x0806ULL
#define VMX_GUEST_DS_ARBYTE_ENCODE  0x481AULL
#define VMX_GUEST_DS_LIMIT_ENCODE  0x4806ULL
#define VMX_GUEST_DS_BASE_ENCODE  0x680CULL
#define VMX_GUEST_LDTR_SELECTOR_ENCODE  0x080CULL
#define VMX_GUEST_LDTR_ARBYTE_ENCODE  0x4820ULL
#define VMX_GUEST_LDTR_LIMIT_ENCODE  0x480CULL
#define VMX_GUEST_LDTR_BASE_ENCODE  0x6812ULL
#define VMX_GUEST_TR_SELECTOR_ENCODE  0x080EULL
#define VMX_GUEST_TR_ARBYTE_ENCODE  0x4822ULL
#define VMX_GUEST_TR_LIMIT_ENCODE  0x480EULL
#define VMX_GUEST_TR_BASE_ENCODE  0x6814ULL
#define VMX_GUEST_FS_SELECTOR_ENCODE  0x0808ULL
#define VMX_GUEST_FS_ARBYTE_ENCODE  0x481CULL
#define VMX_GUEST_FS_LIMIT_ENCODE  0x4808ULL
#define VMX_GUEST_FS_BASE_ENCODE  0x680EULL
#define VMX_GUEST_GS_SELECTOR_ENCODE  0x080AULL
#define VMX_GUEST_GS_ARBYTE_ENCODE  0x481EULL
#define VMX_GUEST_GS_LIMIT_ENCODE  0x480AULL
#define VMX_GUEST_GS_BASE_ENCODE  0x6810ULL
#define VMX_NOTIFY_WINDOW_ENCODE  0x4024ULL
#define VMX_GUEST_GDTR_LIMIT_ENCODE  0x4810ULL
#define VMX_GUEST_GDTR_BASE_ENCODE  0x6816ULL
#define VMX_RSVD_32_BIT_GUEST_STATE_ENCODE  0x4830ULL
#define VMX_GUEST_IDTR_LIMIT_ENCODE  0x4812ULL
#define VMX_GUEST_IDTR_BASE_ENCODE  0x6818ULL
#define VMX_HOST_ES_SELECTOR_ENCODE  0x0C00ULL
#define VMX_HOST_CS_SELECTOR_ENCODE  0x0C02ULL
#define VMX_HOST_SS_SELECTOR_ENCODE  0x0C04ULL
#define VMX_HOST_DS_SELECTOR_ENCODE  0x0C06ULL
#define VMX_HOST_FS_SELECTOR_ENCODE  0x0C08ULL
#define VMX_HOST_GS_SELECTOR_ENCODE  0x0C0AULL
#define VMX_HOST_TR_SELECTOR_ENCODE  0x0C0CULL
#define VMX_GUEST_VPID_ENCODE  0x0000ULL
#define VMX_OSV_CVP_FULL_ENCODE  0x200CULL
#define VMX_OSV_CVP_HIGH_ENCODE  0x200dULL
#define VMX_VM_INSTRUCTION_ERRORCODE_ENCODE  0x4400ULL
#define VMX_PAUSE_LOOP_EXITING_GAP_ENCODE  0x4020ULL
#define VMX_PAUSE_LOOP_EXITING_WINDOW_ENCODE  0x4022ULL
#define VMX_GUEST_SAVED_WORKING_VMCS_POINTER_FULL_ENCODE  0x2800ULL
#define VMX_GUEST_SAVED_WORKING_VMCS_POINTER_HIGH_ENCODE  0x2801ULL
#define VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE  0x2802ULL
#define VMX_GUEST_IA32_DEBUGCTLMSR_HIGH_ENCODE  0x2803ULL
#define VMX_GUEST_IA32_PAT_FULL_ENCODE  0x2804ULL
#define VMX_GUEST_IA32_PAT_HIGH_ENCODE  0x2805ULL
#define VMX_GUEST_IA32_EFER_FULL_ENCODE  0x2806ULL
#define VMX_GUEST_IA32_EFER_HIGH_ENCODE  0x2807ULL
#define VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE  0x2808ULL
#define VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_HIGH_ENCODE  0x2809ULL
#define VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE  0x4002ULL
#define VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE  0x401EULL
#define VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE  0x4000ULL
#define VMX_TPR_THRESHOLD_ENCODE  0x401CULL
#define VMX_PAGEFAULT_ERRORCODE_MASK_ENCODE  0x4006ULL
#define VMX_PAGEFAULT_ERRORCODE_MATCH_ENCODE  0x4008ULL
#define VMX_GUEST_INTERRUPTIBILITY_ENCODE  0x4824ULL
#define VMX_GUEST_SLEEP_STATE_ENCODE  0x4826ULL
#define VMX_GUEST_EPT_POINTER_FULL_ENCODE  0x201AULL
#define VMX_GUEST_EPT_POINTER_HIGH_ENCODE  0x201bULL
#define VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE  0x2400ULL
#define VMX_GUEST_PHYSICAL_ADDRESS_INFO_HIGH_ENCODE  0x2401ULL
#define VMX_VM_ENTRY_INTR_INFO_ENCODE  0x4016ULL
#define VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE  0x4018ULL
#define VMX_VM_ENTRY_INSTRUCTION_LENGTH_ENCODE  0x401AULL
#define VMX_VM_EXIT_CONTROL_ENCODE  0x400CULL
#define VMX_GUEST_PREEMPTION_TIMER_COUNT_ENCODE  0x482EULL
#define VMX_VM_EXIT_MSR_STORE_COUNT_ENCODE  0x400EULL
#define VMX_VM_EXIT_MSR_LOAD_COUNT_ENCODE  0x4010ULL
#define VMX_VM_EXIT_REASON_ENCODE  0x4402ULL
#define VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE  0x4404ULL
#define VMX_VM_EXIT_EXCEPTION_ERRORCODE_ENCODE  0x4406ULL
#define VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE  0x4408ULL
#define VMX_VM_EXIT_IDT_VECTOR_ERRORCODE_ENCODE  0x440AULL
#define VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE  0x440CULL
#define VMX_VM_EXIT_INSTRUCTION_INFO_ENCODE  0x440EULL
#define VMX_TSC_OFFSET_FULL_ENCODE  0x2010ULL
#define VMX_TSC_OFFSET_HIGH_ENCODE  0x2011ULL
#define VMX_VM_EXIT_QUALIFICATION_ENCODE  0x6400ULL
#define VMX_VM_EXIT_IO_RCX_ENCODE  0x6402ULL
#define VMX_VM_EXIT_IO_RSI_ENCODE  0x6404ULL
#define VMX_VM_EXIT_IO_RDI_ENCODE  0x6406ULL
#define VMX_VM_EXIT_IO_RIP_ENCODE  0x6408ULL
#define VMX_VM_EXIT_GUEST_LINEAR_ADDRESS_ENCODE  0x640AULL
#define VMX_GUEST_DR7_ENCODE  0x681AULL
#define VMX_GUEST_RSP_ENCODE  0x681CULL
#define VMX_GUEST_RIP_ENCODE  0x681EULL
#define VMX_GUEST_RFLAGS_ENCODE  0x6820ULL
#define VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE  0x6822ULL
#define VMX_GUEST_IA32_SYSENTER_ESP_ENCODE  0x6824ULL
#define VMX_GUEST_IA32_SYSENTER_EIP_ENCODE  0x6826ULL
#define VMX_GUEST_IA32_SYSENTER_CS_ENCODE  0x482AULL
#define VMX_EPTP_INDEX_ENCODE  0x0004ULL
#define VMX_GUEST_CR0_ENCODE  0x6800ULL
#define VMX_GUEST_CR3_ENCODE  0x6802ULL
#define VMX_GUEST_CR4_ENCODE  0x6804ULL
#define VMX_GUEST_PDPTR0_FULL_ENCODE  0x280AULL
#define VMX_GUEST_PDPTR0_HIGH_ENCODE  0x280bULL
#define VMX_GUEST_PDPTR1_FULL_ENCODE  0x280CULL
#define VMX_GUEST_PDPTR1_HIGH_ENCODE  0x280dULL
#define VMX_GUEST_PDPTR2_FULL_ENCODE  0x280EULL
#define VMX_GUEST_PDPTR2_HIGH_ENCODE  0x280fULL
#define VMX_GUEST_PDPTR3_FULL_ENCODE  0x2810ULL
#define VMX_GUEST_PDPTR3_HIGH_ENCODE  0x2811ULL
#define VMX_CR0_GUEST_HOST_MASK_ENCODE  0x6000ULL
#define VMX_CR4_GUEST_HOST_MASK_ENCODE  0x6002ULL
#define VMX_CR0_READ_SHADOW_ENCODE  0x6004ULL
#define VMX_CR4_READ_SHADOW_ENCODE  0x6006ULL
#define VMX_CR3_TARGET_VALUE_0_ENCODE  0x6008ULL
#define VMX_CR3_TARGET_VALUE_1_ENCODE  0x600AULL
#define VMX_CR3_TARGET_VALUE_2_ENCODE  0x600CULL
#define VMX_CR3_TARGET_VALUE_3_ENCODE  0x600EULL
#define VMX_EOI_EXIT_TABLE_0_FULL_ENCODE  0x201CULL
#define VMX_EOI_EXIT_TABLE_0_HIGH_ENCODE  0x201dULL
#define VMX_EOI_EXIT_TABLE_1_FULL_ENCODE  0x201EULL
#define VMX_EOI_EXIT_TABLE_1_HIGH_ENCODE  0x201fULL
#define VMX_EOI_EXIT_TABLE_2_FULL_ENCODE  0x2020ULL
#define VMX_EOI_EXIT_TABLE_2_HIGH_ENCODE  0x2021ULL
#define VMX_EOI_EXIT_TABLE_3_FULL_ENCODE  0x2022ULL
#define VMX_EOI_EXIT_TABLE_3_HIGH_ENCODE  0x2023ULL
#define VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE  0x2016ULL
#define VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_HIGH_ENCODE  0x2017ULL
#define VMX_GUEST_SMBASE_ENCODE  0x4828ULL
#define VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE  0x0002ULL
#define VMX_EXCEPTION_BITMAP_ENCODE  0x4004ULL
#define VMX_CR3_TARGET_COUNT_ENCODE  0x400AULL
#define VMX_VM_ENTRY_CONTROL_ENCODE  0x4012ULL
#define VMX_VM_ENTRY_MSR_LOAD_COUNT_ENCODE  0x4014ULL
#define VMX_VIRTUAL_APIC_PAGE_ADDRESS_FULL_ENCODE  0x2012ULL
#define VMX_VIRTUAL_APIC_PAGE_ADDRESS_HIGH_ENCODE  0x2013ULL
#define VMX_IO_BITMAP_A_PHYPTR_FULL_ENCODE  0x2000ULL
#define VMX_IO_BITMAP_A_PHYPTR_HIGH_ENCODE  0x2001ULL
#define VMX_IO_BITMAP_B_PHYPTR_FULL_ENCODE  0x2002ULL
#define VMX_IO_BITMAP_B_PHYPTR_HIGH_ENCODE  0x2003ULL
#define VMX_EXIT_MSR_STORE_PHYPTR_FULL_ENCODE  0x2006ULL
#define VMX_EXIT_MSR_STORE_PHYPTR_HIGH_ENCODE  0x2007ULL
#define VMX_EXIT_MSR_LOAD_PHYPTR_FULL_ENCODE  0x2008ULL
#define VMX_EXIT_MSR_LOAD_PHYPTR_HIGH_ENCODE  0x2009ULL
#define VMX_ENTRY_MSR_LOAD_PHYPTR_FULL_ENCODE  0x200AULL
#define VMX_ENTRY_MSR_LOAD_PHYPTR_HIGH_ENCODE  0x200bULL
#define VMX_VIRTUAL_APIC_ACCESS_PAGE_ADDRESS_FULL_ENCODE  0x2014ULL
#define VMX_VIRTUAL_APIC_ACCESS_PAGE_ADDRESS_HIGH_ENCODE  0x2015ULL
#define VMX_MSR_BITMAP_PHYPTR_FULL_ENCODE  0x2004ULL
#define VMX_MSR_BITMAP_PHYPTR_HIGH_ENCODE  0x2005ULL
#define VMX_HOST_RSP_ENCODE  0x6C14ULL
#define VMX_HOST_RIP_ENCODE  0x6C16ULL
#define VMX_HOST_IA32_PAT_FULL_ENCODE  0x2c00ULL
#define VMX_HOST_IA32_PAT_HIGH_ENCODE  0x2c01
#define VMX_HOST_IA32_EFER_FULL_ENCODE  0x2c02
#define VMX_HOST_IA32_EFER_HIGH_ENCODE  0x2c03
#define VMX_HOST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE  0x2c04
#define VMX_HOST_IA32_PERF_GLOBAL_CONTROL_HIGH_ENCODE  0x2c05
#define VMX_HOST_CR0_ENCODE  0x6C00
#define VMX_HOST_CR3_ENCODE  0x6C02
#define VMX_HOST_CR4_ENCODE  0x6C04ULL
#define VMX_HOST_IDTR_BASE_ENCODE  0x6C0E
#define VMX_HOST_GDTR_BASE_ENCODE  0x6C0C
#define VMX_HOST_FS_BASE_ENCODE  0x6C06
#define VMX_HOST_GS_BASE_ENCODE  0x6C08
#define VMX_HOST_TR_BASE_ENCODE  0x6C0A
#define VMX_HOST_IA32_SYSENTER_ESP_ENCODE  0x6C10
#define VMX_HOST_IA32_SYSENTER_EIP_ENCODE  0x6C12
#define VMX_HOST_IA32_SYSENTER_CS_ENCODE  0x4C00
#define VMX_GUEST_INTERRUPT_STATUS_ENCODE  0x0810
#define VMX_GUEST_UINV_ENCODE  0x0814
#define VMX_PML_INDEX_ENCODE  0x0812
#define VMX_VM_FUNCTION_CONTROLS_FULL_ENCODE  0x2018
#define VMX_VM_FUNCTION_CONTROLS_HIGH_ENCODE  0x2019
#define VMX_EPTP_LIST_ADDRESS_FULL_ENCODE  0x2024
#define VMX_EPTP_LIST_ADDRESS_HIGH_ENCODE  0x2025
#define VMX_VMREAD_BITMAP_ADDRESS_FULL_ENCODE  0x2026
#define VMX_VMREAD_BITMAP_ADDRESS_HIGH_ENCODE  0x2027
#define VMX_VMWRITE_BITMAP_ADDRESS_FULL_ENCODE  0x2028
#define VMX_VMWRITE_BITMAP_ADDRESS_HIGH_ENCODE  0x2029
#define VMX_PML_LOG_ADDRESS_FULL_ENCODE  0x200E
#define VMX_PML_LOG_ADDRESS_HIGH_ENCODE  0x200f
#define VMX_XSS_EXIT_CONTROL_FULL_ENCODE  0x202C
#define VMX_XSS_EXIT_CONTROL_HIGH_ENCODE  0x202d
#define VMX_ENCLS_EXIT_CONTROL_FULL_ENCODE  0x202E
#define VMX_ENCLS_EXIT_CONTROL_HIGH_ENCODE  0x202f
#define VMX_RSVD_64_BIT_VMEXIT_DATA_FULL_ENCODE  0x2402
#define VMX_RSVD_64_BIT_VMEXIT_DATA_HIGH_ENCODE  0x2403
#define VMX_ENCLV_EXIT_CONTROL_FULL_ENCODE  0x2036
#define VMX_ENCLV_EXIT_CONTROL_HIGH_ENCODE  0x2037
#define VMX_VIRTUAL_EXCEPTION_INFO_ADDRESS_FULL_ENCODE  0x202A
#define VMX_VIRTUAL_EXCEPTION_INFO_ADDRESS_HIGH_ENCODE  0x202b
#define VMX_GUEST_BNDCFGS_FULL_ENCODE  0x2812
#define VMX_GUEST_BNDCFGS_HIGH_ENCODE  0x2813
#define VMX_SPPTP_FULL_ENCODE  0x2030
#define VMX_SPPTP_HIGH_ENCODE  0x2031
#define VMX_TSC_MULTIPLIER_FULL_ENCODE  0x2032
#define VMX_TSC_MULTIPLIER_HIGH_ENCODE  0x2033
#define VMX_GUEST_RTIT_CTL_FULL_ENCODE  0x2814
#define VMX_GUEST_RTIT_CTL_HIGH_ENCODE  0x2815
#define VMX_VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_FULL_ENCODE  0x2034
#define VMX_VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_HIGH_ENCODE  0x2035
#define VMX_PCONFIG_EXITING_FULL_ENCODE  0x203E
#define VMX_PCONFIG_EXITING_HIGH_ENCODE  0x203f
#define VMX_PASID_LOW_FULL_ENCODE  0x2038
#define VMX_PASID_LOW_HIGH_ENCODE  0x2039
#define VMX_PASID_HIGH_FULL_ENCODE  0x203A
#define VMX_PASID_HIGH_HIGH_ENCODE  0x203b
#define VMX_HOST_IA32_INTERRUPT_SSP_TABLE_ADDR_ENCODE  0x6C1C
#define VMX_GUEST_IA32_S_CET_ENCODE  0x6828
#define VMX_GUEST_SSP_ENCODE  0x682A
#define VMX_GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR_ENCODE  0x682C
#define VMX_HOST_IA32_S_CET_ENCODE  0x6C18
#define VMX_HOST_SSP_ENCODE  0x6C1A
#define VMX_HKID_ENCODE  0x4026
#define VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE  0x203C
#define VMX_GUEST_SHARED_EPT_POINTER_HIGH_ENCODE  0x203D
#define VMX_NO_COMMIT_THRESHOLD_ENCODE  0x4024
#define VMX_GUEST_LBR_CTL_FULL_ENCODE  0x2816
#define VMX_GUEST_PKRS_FULL_ENCODE  0x2818
#define VMX_HLATP_FULL_ENCODE  0x2040
#define VMX_IA32_SPEC_CTRL_MASK 0x204A
#define VMX_IA32_SPEC_CTRL_SHADOW 0x204C