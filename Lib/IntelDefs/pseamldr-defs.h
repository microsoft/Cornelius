//
// Definitions taken from Intel's seam-loader-main-1.5.01.02 source code.
//
// This code is subject to the Intel license below.
//

// Intel Proprietary
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

#pragma once

#define PACKED
#define bool_t bool
#define pseamldr_static_assert(a, b)    C_ASSERT(a)

// VMCS fields
#define VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE  0x2802ULL
#define VMX_VM_EXIT_REASON_ENCODE               0x4402ULL
#define VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE   0x440CULL
#define VMX_GUEST_INTERRUPTIBILITY_ENCODE       0x4824ULL
#define VMX_GUEST_RIP_ENCODE                    0x681EULL
#define VMX_GUEST_RFLAGS_ENCODE                 0x6820ULL
#define VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE    0x6822ULL

// CPUID leaves
#define CPUID_DET_CACHE_PARAMS_LEAF 4
#define CPUID_GET_TOPOLOGY_LEAF 0x1F
#define CPUID_GET_MAX_PA_LEAF 0x80000008

// MSRs
#define IA32_PRED_CMD_MSR_ADDR                           0x49
#define IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR           0x87
#define NON_FAULTING_MSR_ADDR                            0x8B
#define IA32_TME_ACTIVATE_MSR_ADDR                       0x982
#define IA32_SEAMRR_BASE_MSR_ADDR                        0x1400
#define IA32_SEAMRR_MASK_MSR_ADDR                        0x1401
#define IA32_SEAMEXTEND_MSR_ADDR                         0x1402

#define IA32_VMX_BASIC_MSR_ADDR               0x480
#define IA32_VMX_PINBASED_CTLS_MSR_ADDR       0x481
#define IA32_VMX_PROCBASED_CTLS_MSR_ADDR      0x482
#define IA32_VMX_EXIT_CTLS_MSR_ADDR           0x483
#define IA32_VMX_ENTRY_CTLS_MSR_ADDR          0x484
#define IA32_VMX_EPT_VPID_CAP_MSR_ADDR        0x48C
#define IA32_VMX_MISC_MSR_ADDR                0x485
#define IA32_VMX_CR0_FIXED0_MSR_ADDR          0x486
#define IA32_VMX_CR0_FIXED1_MSR_ADDR          0x487
#define IA32_VMX_CR4_FIXED0_MSR_ADDR          0x488
#define IA32_VMX_CR4_FIXED1_MSR_ADDR          0x489
#define IA32_VMX_PROCBASED_CTLS2_MSR_ADDR     0x48B
#define IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR  0x48D
#define IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR 0x48E
#define IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR      0x48F
#define IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR     0x490
#define IA32_VMX_PROCBASED_CTLS3_MSR_ADDR     0x492

//
// pseamldr_api_defs.h
//

#pragma pack(push)
#pragma pack(1)

#define SEAMLDR_INFO_LEAF       0x8000000000000000ULL
#define SEAMLDR_INSTALL_LEAF    0x8000000000000001ULL
#define SEAMLDR_SHUTDOWN_LEAF   0x8000000000000002ULL
#define SEAMLDR_SEAMINFO_LEAF   0x8000000000000003ULL
#define SEAMLDR_CLEANUP_LEAF    0x8000000000000004ULL

#define PSEAMLDR_RECOVERABLE_ERROR              0
#define PSEAMLDR_UNRECOVERABLE_ERROR            1

#define SEAMLDR_SCENARIO_LOAD                   0
#define SEAMLDR_SCENARIO_UPDATE                 1

#define SEAMLDR_PARAMS_MIN_MODULE_PAGES         1

#define SEAMLDR_PARAMS_MAX_MODULE_PAGES_V0      496

#define SEAMLDR_PARAMS_SIZE                     _4KB
#define SEAMLDR_PARAMS_MAX_MODULE_PAGES         SEAMLDR_PARAMS_MAX_MODULE_PAGES_V0

#define SEAM_MODULE_PAGE_SIZE                   _4KB

typedef struct seamldr_params_s
{
    uint32_t version;
    uint32_t scenario;
    uint64_t sigstruct_pa;

    uint8_t  reserved[104 - 1 * sizeof(uint64_t)];
    struct {
        uint64_t pa_start;
    } ext;

    uint64_t num_module_pages;
    uint64_t mod_pages_pa_list[SEAMLDR_PARAMS_MAX_MODULE_PAGES];
} seamldr_params_t;
pseamldr_static_assert(sizeof(seamldr_params_t) == SEAMLDR_PARAMS_SIZE, seamldr_params_t);

typedef union attributes_s
{
    struct
    {
        uint32_t reserved : 31;
        uint32_t is_debug : 1;
    };
    uint32_t raw;
} attributes_t;
pseamldr_static_assert(sizeof(attributes_t) == 4, attributes_t);

typedef struct PACKED tee_tcb_snv_s
{
    union
    {
        struct
        {
            uint8_t seam_minor_svn;
            uint8_t seam_major_svn;
        };
        uint16_t current_seam_svn;
    };

    uint8_t  last_patch_se_svn;
    uint8_t  reserved[13];
} tee_tcb_svn_t;
pseamldr_static_assert(sizeof(tee_tcb_svn_t) == 16, tee_tcb_svn_t);

/**
 * @struct seamextend_t
 *
 * @brief The processor maintains a platform-scoped register called SEAMEXTEND,
 *
 * Which records the attributes of the current SEAM module, and its basic execution controls.
 * P-SEAMLDR can retrieve and update this register using IA32_SEAMEXTEND command MSR.
 *
 */
typedef struct PACKED seamextend_s
{
    uint64_t      valid;
    tee_tcb_svn_t tee_tcb_svn;
    uint8_t       mrseam[48];
    uint8_t       mrsigner[48];
    uint64_t      attributes;
    uint8_t       seam_ready;
    bool_t        system_under_debug;
    uint8_t       p_seamldr_ready;
    uint8_t       reserved[5];
} seamextend_t;
pseamldr_static_assert(sizeof(seamextend_t) == 136, seamextend_t);

typedef union seamldr_info_features0_u
{
    struct
    {
        uint64_t s4_mig_api_supported : 1;  // Bit 0
        uint64_t cleanup_supported    : 1;  // Bit 1
        uint64_t reserved             : 62; // Bit 2-63
    };
    uint64_t raw;
} seamldr_info_features0_t;
pseamldr_static_assert(sizeof(seamldr_info_features0_t) == 8, seamldr_info_features0_t);

typedef struct seamldr_info_s
{
    uint32_t     version;
    attributes_t attributes;
    uint32_t     vendor_id;
    uint32_t     build_date;
    uint16_t     build_num;
    uint16_t     minor;
    uint16_t     major;
    uint16_t     reserved_0;
    uint32_t     acm_x2apic;
    uint32_t     num_remaining_updates;
    seamextend_t seamextend;
    seamldr_info_features0_t features0;
    uint8_t      reserved_2[80];
} seamldr_info_t;
pseamldr_static_assert(sizeof(seamldr_info_t) == 256, seamldr_info_t);

typedef struct handoff_data_header_s
{
    bool_t   valid;
    uint8_t  reserved;
    uint16_t hv;
    uint32_t size;
} handoff_data_header_t;
pseamldr_static_assert(sizeof(handoff_data_header_t) == 8, handoff_data_header_t);

#define NUM_CACHELINES_IN_PAGE 64

#pragma pack(pop)

//
// seam_sigstruct.h
//

#define SIGSTRUCT_MODULUS_SIZE 384
#define SIGSTRUCT_SIGNATURE_SIZE 384
#define SIGSTRUCT_SEAMHASH_SIZE 48

#pragma pack(push,1)

#define SEAM_SIGSTRUCT_KEY_SIZE_DWORDS        0x60
#define SEAM_SIGSTRUCT_MODULUS_SIZE_DWORDS    0x60
#define SEAM_SIGSTRUCT_EXPONENT_SIZE_DWORDS   0x1
#define SEAM_SIGSTRUCT_RSA_EXPONENT           0x10001 // (2^16 + 1)
#define SEAM_SIGSTRUCT_HEADER_TYPE_GENERIC_FW 0x6
#define SEAM_SIGSTRUCT_HEADER_LENGTH_DWORDS   0xE1
#define SEAM_SIGSTRUCT_HEADER_VERSION_MINOR   0x0UL
#define SEAM_SIGSTRUCT_HEADER_VERSION_MAJOR   0x1UL
#define SEAM_SIGSTRUCT_HEADER_VERSION         ((SEAM_SIGSTRUCT_HEADER_VERSION_MAJOR << 16) | \
                                                SEAM_SIGSTRUCT_HEADER_VERSION_MINOR)
#define SEAM_SIGSTRUCT_SIZE_DWORDS            0x200

#define SEAM_SIGSTRUCT_INTEL_MODULE_VENDOR    0x8086
#define SEAM_SIGSTRUCT_MAX_CPUID_TABLE_SIZE   255

typedef union
{
    struct
    {
        uint32_t reserved        : 31;
        uint32_t is_debug_signed : 1;
    };

    uint32_t raw;
} module_type_t;

#define TDX_MODULE_1_0_MAJOR_SVN            0

typedef union seam_svn_u
{
    struct
    {
        uint8_t seam_minor_svn;
        uint8_t seam_major_svn;
    };

    uint16_t raw;
} seam_svn_t;
pseamldr_static_assert(sizeof(seam_svn_t) == 2, seam_svn_t);

#define SEAM_SIGSTRUCT_SIZE            2048
#define SEAM_SIGSTRUCT_HEADER_SIZE     128
#define SEAM_SIGSTRUCT_SIG_OFFSET      SEAM_SIGSTRUCT_HEADER_SIZE
#define SEAM_SIGSTRUCT_SIG_SIZE        (384+4+384)
#define SEAM_SIGSTRUCT_BODY_OFFSET     (SEAM_SIGSTRUCT_SIG_OFFSET + SEAM_SIGSTRUCT_SIG_SIZE)
#define SEAM_SIGSTRUCT_BODY_SIZE       (SEAM_SIGSTRUCT_SIZE - SEAM_SIGSTRUCT_HEADER_SIZE - SEAM_SIGSTRUCT_SIG_SIZE)

#if ((SEAM_SIGSTRUCT_BODY_OFFSET + SEAM_SIGSTRUCT_BODY_SIZE) != SEAM_SIGSTRUCT_SIZE)
#error "Wrong SEAM SIGSTRUCT size constants!!!"
#endif

typedef struct
{
    uint32_t header_type;
    uint32_t header_length;
    uint32_t header_version;
    module_type_t module_type;
    uint32_t module_vendor;
    uint32_t date;
    uint32_t size;
    uint32_t key_size;
    uint32_t modulus_size;
    uint32_t exponent_size;
    uint8_t reserved0[88];

    uint8_t modulus[SIGSTRUCT_MODULUS_SIZE];
    uint32_t exponent;
    uint8_t signature[SIGSTRUCT_SIGNATURE_SIZE];

    uint8_t seamhash[SIGSTRUCT_SEAMHASH_SIZE];
    seam_svn_t seamsvn;
    uint64_t attributes;
    uint32_t rip_offset;
    uint8_t num_stack_pages;
    uint8_t num_tls_pages;
    uint16_t num_keyhole_pages;
    uint16_t num_global_data_pages;
    uint16_t max_tdmrs;
    uint16_t max_rsvd_per_tdmr;
    uint16_t pamt_entry_size_4k;
    uint16_t pamt_entry_size_2m;
    uint16_t pamt_entry_size_1g;
    uint8_t  reserved1[6];
    uint16_t module_hv;
    uint16_t min_update_hv;
    bool_t   no_downgrade;
    uint8_t  reserved2[1];
    uint16_t num_handoff_pages;

    uint32_t gdt_idt_offset;
    uint32_t fault_wrapper_offset;
    uint8_t  reserved3[24];

    uint32_t cpuid_table_size;
    uint32_t cpuid_table[SEAM_SIGSTRUCT_MAX_CPUID_TABLE_SIZE];

} seam_sigstruct_t;

#pragma pack(pop)

pseamldr_static_assert(sizeof(seam_sigstruct_t) == SEAM_SIGSTRUCT_SIZE, seam_sigstruct_t);
pseamldr_static_assert(offsetof(seam_sigstruct_t, modulus) == SEAM_SIGSTRUCT_SIG_OFFSET, seam_sigstruct_t);
pseamldr_static_assert(offsetof(seam_sigstruct_t, seamhash) == SEAM_SIGSTRUCT_BODY_OFFSET, seam_sigstruct_t);

//
// vmcs_defs.h
//

#define VMX_GUEST_RIP_OFFSET  0x01d8 //8
#define VMX_VMCS_REVISION_ID_OFFSET  0x0000 //4
#define VMX_VM_EXECUTION_CONTROL_PROC_BASED_OFFSET  0x0120 //4
#define VMX_VM_EXECUTION_CONTROL_PIN_BASED_OFFSET  0x0128 //4
#define VMX_VM_EXIT_CONTROL_OFFSET  0x015c //4
#define VMX_VM_ENTRY_CONTROL_OFFSET  0x02b8 //4
#define VMX_HOST_CS_SELECTOR_OFFSET  0x00c2 //2
#define VMX_HOST_SS_SELECTOR_OFFSET  0x00c4 //2
#define VMX_HOST_FS_SELECTOR_OFFSET  0x00c8 //2
#define VMX_HOST_GS_SELECTOR_OFFSET  0x00ca //2
#define VMX_HOST_TR_SELECTOR_OFFSET  0x00cc //2
#define VMX_HOST_RSP_OFFSET  0x0300 //8
#define VMX_HOST_RIP_OFFSET  0x0308 //8
#define VMX_HOST_IA32_PAT_FULL_OFFSET  0x0310 //8
#define VMX_HOST_IA32_EFER_FULL_OFFSET  0x0318 //8
#define VMX_HOST_CR0_OFFSET  0x0328 //8
#define VMX_HOST_CR3_OFFSET  0x0330 //8
#define VMX_HOST_CR4_OFFSET  0x0338 //8
#define VMX_HOST_IDTR_BASE_OFFSET  0x0340 //8
#define VMX_HOST_GDTR_BASE_OFFSET  0x0348 //8
#define VMX_HOST_FS_BASE_OFFSET  0x0350 //8
#define VMX_HOST_GS_BASE_OFFSET  0x0358 //8
#define VMX_HOST_IA32_S_CET_OFFSET  0x0458 //8
#define VMX_HOST_SSP_OFFSET  0x0460 //8

//
// x86_defs.h
//

#define MAX_PA                  52ULL

typedef union
{
    struct
    {
        uint32_t rsvd :14; // 0-13
        uint32_t max_num_of_lps_sharing_cache :12; // 14-25
        uint32_t cores_per_socket_minus_one :6;
    };
    uint32_t raw;
} cpu_cache_params_t;
pseamldr_static_assert(sizeof(cpu_cache_params_t) == 4, cpu_cache_params_t);

//
// msr_defs.h
//

#define IA32_CORE_THREAD_COUNT_MSR_ADDR                  0x35

typedef union ia32_seamrr_mask_u {
    struct {
        uint64_t
            rsvd0       : 10,                  // [9:0]
            lock        : 1,                   // [10]
            valid       : 1,                   // [11]
            rsvd1       : 13,                  // [24:12]
            mask        : ((MAX_PA - 1) - 24), // [MAX_PA-1:25]
            rsvd2       : ((63 - MAX_PA) + 1);   // [63:MAX_PA]
    };

    uint64_t raw;
} ia32_seamrr_mask_t;
pseamldr_static_assert(sizeof(ia32_seamrr_mask_t) == 8, ia32_seamrr_mask_t);

typedef union
{
    struct
    {
        uint64_t vmcs_revision_id         : 31; // bits 30:0
        uint64_t rsvd0                    : 1;  // bit 31
        uint64_t vmcs_region_size         : 13; // bits 44:32
        uint64_t rsvd1                    : 3;  // bits 47:45
        uint64_t vmxon_pa_width           : 1;  // bit 48 
        uint64_t dual_monitor             : 1;  // bit 49
        uint64_t vmcs_mt                  : 4;  // bits 53:50
        uint64_t vmexit_info_on_ios       : 1;  // bit 54
        uint64_t ia32_vmx_true_available  : 1;  // bit 55
        uint64_t voe_without_err_code     : 1;  // bit 56
        uint64_t rsvd2                    : 7;  // bits 63:57
    };
    uint64_t raw;
} ia32_vmx_basic_t;
pseamldr_static_assert(sizeof(ia32_vmx_basic_t) == 8, ia32_vmx_basic_t);

typedef union ia32_core_thread_count_u
{
    struct
    {
        uint64_t lps_in_package  : 16;
        uint64_t rsvd            : 48;
    };
    uint64_t raw;
} ia32_core_thread_count_t;