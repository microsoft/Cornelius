//
// Definitions taken from Intel's tdx-module-1.5.01-pc source code.
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
#define tdx_static_assert(a, b)    C_ASSERT(a)

//
// x86_defs.h
//

#define CPUID_MAX_INPUT_VAL_LEAF 0
#define CPUID_VER_INFO_LEAF 1
#define CPUID_EXT_FEATURES_LEAF 7
#define CPUID_PERFMON_LEAF              0xA
#define CPUID_EXT_STATE_ENUM_LEAF       0xD
#define CPUID_TSC_ATTRIBUTES_LEAF       0x15
#define CPUID_KEYLOCKER_ATTRIBUTES_LEAF 0x19
#define CPUID_LBR_CAPABILITIES_LEAF 0x1C
#define CPUID_MIN_LAST_CPU_BASE_LEAF     0x1F
#define CPUID_LAST_BASE_LEAF             0x23
#define CPUID_MAX_EXTENDED_VAL_LEAF 0x80000000

#define NATIVE_TSC_FREQUENCY_MIN       0x2540c

typedef union
{
    struct
    {
        uint32_t level_number : 8;
        uint32_t level_type   : 8;
        uint32_t rsvd         : 16;
    };
    uint32_t raw;
} cpuid_topology_level_t;  //cpuid_04_03_ecx
tdx_static_assert(sizeof(cpuid_topology_level_t) == 4, cpuid_topology_level_t);

typedef enum
{
    LEVEL_TYPE_INVALID = 0,
    LEVEL_TYPE_SMT     = 1,
    LEVEL_TYPE_CORE    = 2,
    LEVEL_TYPE_MODULE  = 3,
    LEVEL_TYPE_TILE    = 4,
    LEVEL_TYPE_DIE     = 5,
    LEVEL_TYPE_MAX     = 6
} cpuid_topology_level_type_e;

//
// msr_defs.h
//

#define IA32_TSC_ADJ_MSR_ADDR                            0x3B
#define IA32_SPEC_CTRL_MSR_ADDR                          0x48
#define IA32_MISC_PACKAGE_CTLS_MSR_ADDR                  0xBC
#define IA32_XAPIC_DISABLE_STATUS_MSR_ADDR               0xBD
#define IA32_CORE_CAPABILITIES                           0xCF
#define IA32_ARCH_CAPABILITIES_MSR_ADDR                  0x10A
#define IA32_MISC_ENABLES_MSR_ADDR                       0x1A0
#define IA32_PERF_CAPABILITIES_MSR_ADDR                  0x345
#define IA32_TME_CAPABILITY_MSR_ADDR                     0x981
#define IA32_DS_AREA_MSR_ADDR                            0x600
#define IA32_WBINVDP_MSR_ADDR                            0x98
#define IA32_WBNOINVDP_MSR_ADDR                          0x99
#define IA32_UARCH_MISC_CTL_MSR_ADDR                     0x1B01
#define MTRR_CAP_MSR_ADDR 0xFE
#define SMRR_BASE_MSR_ADDR 0x1F2
#define SMRR_MASK_MSR_ADDR 0x1F3
#define IA32_XSS_MSR_ADDR                                0xDA0
#define IA32_STAR_MSR_ADDR                               0xC0000081
#define IA32_LSTAR_MSR_ADDR                              0xC0000082
#define IA32_FMASK_MSR_ADDR                              0xC0000084
#define IA32_KERNEL_GS_BASE_MSR_ADDR                     0xC0000102
#define IA32_TSC_AUX_MSR_ADDR                            0xC0000103

typedef union ia32_mtrrcap_u
{
    struct
    {
        uint64_t vcnt       : 8,  // 0-7
                 fix        : 1,  // 8
                 rsvd1      : 1,  // 9
                 wc         : 1,  // 10
                 smrr       : 1,  // 11
                 prmrr      : 1,  // 12
                 smrr2      : 1,  // 13
                 smrr_lock  : 1,  // 14
                 seamrr     : 1,  // 15
                 rsvd2      : 48; // 16-64
    };
    uint64_t raw;
} ia32_mtrrcap_t;

typedef union
{
    struct
    {
        uint64_t rsvd0 :10, // Bits 0-9
                 lock  :1,  // Bit 10
                 vld   :1,  // Bit 11
                 mask  :20, // Bits 12-31
                 rsvd1 :32; // Bits 32-63
    };
    uint64_t raw;
} smrr_mask_t;

typedef union
{
    struct
    {
        uint64_t memtype :8, rsvd0 :4, base :20, rsvd1 :32;
    };
    uint64_t raw;
} smrr_base_t;

typedef union ia32_core_capabilities_u
{
    struct
    {
        uint64_t stlb_qos_supported           : 1;   // Bit 0
        uint64_t rar_supported                : 1;   // Bit 1
        uint64_t fusa_supported               : 1;   // Bit 2
        uint64_t rsm_in_cpl0_only             : 1;   // Bit 3
        uint64_t uc_lock_disable_supported    : 1;   // Bit 4
        uint64_t split_lock_disable_supported : 1;   // Bit 5
        uint64_t snoop_filter_qos_supported   : 1;   // Bit 6
        uint64_t uc_store_throttlin_supported : 1;   // Bit 7
        uint64_t lam_supported                : 1;   // Bit 8
        uint64_t reserved_2                   : 55;  // Bits 63-9
    };
    uint64_t raw;
} ia32_core_capabilities_t;
tdx_static_assert(sizeof(ia32_core_capabilities_t) == 8, ia32_core_capabilities_t);

typedef union ia32_arch_capabilities_u
{
    struct
    {
        uint64_t rdcl_no              : 1;  // Bit 0
        uint64_t irbs_all             : 1;  // Bit 1
        uint64_t rsba                 : 1;  // Bit 2
        uint64_t skip_l1dfl_vmentry   : 1;  // Bit 3
        uint64_t ssb_no               : 1;  // Bit 4
        uint64_t mds_no               : 1;  // Bit 5
        uint64_t if_pschange_mc_no    : 1;  // Bit 6
        uint64_t tsx_ctrl             : 1;  // Bit 7
        uint64_t taa_no               : 1;  // Bit 8
        uint64_t mcu_ctls             : 1;  // Bit 9
        uint64_t misc_package_ctls    : 1;  // Bit 10
        uint64_t energy_filtering_ctl : 1;  // Bit 11
        uint64_t doitm                : 1;  // Bit 12
        uint64_t sbdr_ssdp_no         : 1;  // Bit 13
        uint64_t fbsdp_no             : 1;  // Bit 14
        uint64_t psdp_no              : 1;  // Bit 15
        uint64_t reserved_1           : 1;  // Bit 16
        uint64_t fb_clear             : 1;  // Bit 17
        uint64_t fb_clear_ctrl        : 1;  // Bit 18
        uint64_t rrsba                : 1;  // Bit 19
        uint64_t bhi_no               : 1;  // Bit 20
        uint64_t xapic_disable_status : 1;  // Bit 21
        uint64_t reserved_2           : 1;  // Bit 22
        uint64_t overclocking_status  : 1;  // Bit 23
        uint64_t pbrsb_no             : 1;  // Bit 24
        uint64_t reserved_3           : 39; // BITS 25:63
    };
    uint64_t raw;
} ia32_arch_capabilities_t;
tdx_static_assert(sizeof(ia32_arch_capabilities_t) == 8, ia32_arch_capabilities_t);

typedef union
{
    struct
    {
        uint64_t lbr_format                  : 6, //0-5
                 pebs_trap_indicator         : 1, //6
                 pebs_save_arch_regs         : 1, //7
                 pebs_records_encoding       : 4, //8-11
                 freeze_while_smm_supported  : 1, //12
                 full_write                  : 1, //13
                 rsvd1                       : 1, //14
                 perf_metrics_available      : 1, //15
                 pebs_output_pt_avail        : 1, //16
                 rsvd2                       : 47;//17-63
    };
    uint64_t raw;
} ia32_perf_capabilities_t;

typedef union ia32_misc_package_ctls_u
{
    struct
    {
        uint64_t energy_filtering_enable   : 1;   // Bit 0
        uint64_t reserved                  : 63;  // Bits 63-1
    };
    uint64_t raw;
} ia32_misc_package_ctls_t;

typedef union ia32_msr_intr_pending_u
{
    struct
    {
        uint64_t intr  : 1;   // Bit 0: INTR is pending
        uint64_t nmi   : 1;   // Bit 1: NMI is pending
        uint64_t smi   : 1;   // Bit 2: SMI is pending
        uint64_t other : 61;  // Bits 63:3: Other events are pending
    };
    uint64_t raw;
} ia32_msr_intr_pending_t;

typedef union ia32_xapic_disable_status_u
{
    struct
    {
        uint64_t legacy_xapic_disabled : 1;   // Bit 0
        uint64_t reserved              : 63;  // Bits 63-1
    };
    uint64_t raw;
} ia32_xapic_disable_status_t;

typedef union
{
    struct
    {
        uint32_t not_allowed0;
        uint32_t allowed1;
    };
    uint64_t raw;
} ia32_vmx_allowed_bits_t;

typedef union
{
    struct
    {
        uint64_t lock                            : 1 , //0
                 tme_enable                      : 1,  //1
                 key_select                      : 1,  //2
                 save_key_for_standby            : 1,  //3
                 tme_policy                      : 4,  //4-7
                 sgx_tem_enable                  : 1,  //8
                 rsvd                            : 22, //9-30
                 tme_enc_bypass_enable           : 1,  //31
                 mk_tme_keyid_bits               : 4,  //32-35
                 tdx_reserved_keyid_bits         : 4,  //36-39
                 rsvd1                           : 8,  //40-47
                 algs_aes_xts_128                : 1,  //48
                 algs_aes_xts_128_with_integrity : 1,  //49
                 algs_aes_xts_256                : 1,  //50
                 algs_aes_xts_256_with_integrity : 1,  //51
                 algs_rsvd                       : 12;
    };
    uint64_t raw;
} ia32_tme_activate_t;
tdx_static_assert(sizeof(ia32_tme_activate_t) == 8, ia32_tme_activate_t);

typedef union
{
    struct
    {
        uint64_t aes_xts_128 : 1;                // Bit 0
        uint64_t aes_xts_128_with_integrity : 1; // Bit 1
        uint64_t aes_xts_256 : 1;                // Bit 2
        uint64_t aes_xts_256_with_integrity : 1; // Bit 3
        uint64_t rsvd : 27;                      // Bits 30:4
        uint64_t tme_enc_bypass_supported   : 1; // Bit 31
        uint64_t mk_tme_max_keyid_bits : 4;      // Bits 35:32
        uint64_t mk_tme_max_keys : 15;           // Bits 50:36
        uint64_t nm_encryption_disable : 1;      // Bit 51
        uint64_t rsvd2 : 11;                     // Bits 62:52
        uint64_t implicit_bit_mask : 1;          // Bit 63
    };
    uint64_t raw;
} ia32_tme_capability_t;
tdx_static_assert(sizeof(ia32_tme_capability_t) == 8, ia32_tme_capability_t);

typedef union
{
    struct
    {
        UINT32 num_mktme_kids;
        UINT32 num_tdx_priv_kids;
    };
    UINT64 raw;
} ia32_tme_keyid_partitioning_t;

//
// tdx_api_defs.h
//

#pragma pack(push)
#pragma pack(1)

/**< Enum for SEAMCALL leaves opcodes */
typedef enum seamcall_leaf_opcode_e
{
    TDH_VP_ENTER_LEAF                = 0,
    TDH_MNG_ADDCX_LEAF               = 1,
    TDH_MEM_PAGE_ADD_LEAF            = 2,
    TDH_MEM_SEPT_ADD_LEAF            = 3,
    TDH_VP_ADDCX_LEAF                = 4,
    TDH_MEM_PAGE_RELOCATE            = 5,
    TDH_MEM_PAGE_AUG_LEAF            = 6,
    TDH_MEM_RANGE_BLOCK_LEAF         = 7,
    TDH_MNG_KEY_CONFIG_LEAF          = 8,
    TDH_MNG_CREATE_LEAF              = 9,
    TDH_VP_CREATE_LEAF               = 10,
    TDH_MNG_RD_LEAF                  = 11,
    TDH_MEM_RD_LEAF                  = 12,
    TDH_MNG_WR_LEAF                  = 13,
    TDH_MEM_WR_LEAF                  = 14,
    TDH_MEM_PAGE_DEMOTE_LEAF         = 15,
    TDH_MR_EXTEND_LEAF               = 16,
    TDH_MR_FINALIZE_LEAF             = 17,
    TDH_VP_FLUSH_LEAF                = 18,
    TDH_MNG_VPFLUSHDONE_LEAF         = 19,
    TDH_MNG_KEY_FREEID_LEAF          = 20,
    TDH_MNG_INIT_LEAF                = 21,
    TDH_VP_INIT_LEAF                 = 22,
    TDH_MEM_PAGE_PROMOTE_LEAF        = 23,
    TDH_PHYMEM_PAGE_RDMD_LEAF        = 24,
    TDH_MEM_SEPT_RD_LEAF             = 25,
    TDH_VP_RD_LEAF                   = 26,
    TDH_MNG_KEY_RECLAIMID_LEAF       = 27,
    TDH_PHYMEM_PAGE_RECLAIM_LEAF     = 28,
    TDH_MEM_PAGE_REMOVE_LEAF         = 29,
    TDH_MEM_SEPT_REMOVE_LEAF         = 30,
    TDH_SYS_KEY_CONFIG_LEAF          = 31,
    TDH_SYS_INFO_LEAF                = 32,
    TDH_SYS_INIT_LEAF                = 33,
    TDH_SYS_RD_LEAF                  = 34,
    TDH_SYS_LP_INIT_LEAF             = 35,
    TDH_SYS_TDMR_INIT_LEAF           = 36,
    TDH_SYS_RDALL_LEAF               = 37,
    TDH_MEM_TRACK_LEAF               = 38,
    TDH_MEM_RANGE_UNBLOCK_LEAF       = 39,
    TDH_PHYMEM_CACHE_WB_LEAF         = 40,
    TDH_PHYMEM_PAGE_WBINVD_LEAF      = 41,
    TDH_MEM_SEPT_WR_LEAF             = 42,
    TDH_VP_WR_LEAF                   = 43,
    TDH_SYS_LP_SHUTDOWN_LEAF         = 44,
    TDH_SYS_CONFIG_LEAF              = 45,
    TDH_SERVTD_BIND_LEAF             = 48,
    TDH_SERVTD_PREBIND_LEAF          = 49,
    TDH_SYS_SHUTDOWN_LEAF            = 52,
    TDH_SYS_UPDATE_LEAF              = 53,
    TDH_EXPORT_ABORT_LEAF            = 64,
    TDH_EXPORT_BLOCKW_LEAF           = 65,
    TDH_EXPORT_RESTORE_LEAF          = 66,
    TDH_EXPORT_MEM_LEAF              = 68,
    TDH_EXPORT_PAUSE_LEAF            = 70,
    TDH_EXPORT_TRACK_LEAF            = 71,
    TDH_EXPORT_STATE_IMMUTABLE_LEAF  = 72,
    TDH_EXPORT_STATE_TD_LEAF         = 73,
    TDH_EXPORT_STATE_VP_LEAF         = 74,
    TDH_EXPORT_UNBLOCKW_LEAF         = 75,
    TDH_IMPORT_ABORT_LEAF            = 80,
    TDH_IMPORT_END_LEAF              = 81,
    TDH_IMPORT_COMMIT_LEAF           = 82,
    TDH_IMPORT_MEM_LEAF              = 83,
    TDH_IMPORT_TRACK_LEAF            = 84,
    TDH_IMPORT_STATE_IMMUTABLE_LEAF  = 85,
    TDH_IMPORT_STATE_TD_LEAF         = 86,
    TDH_IMPORT_STATE_VP_LEAF         = 87,
    TDH_MIG_STREAM_CREATE_LEAF       = 96

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    ,TDDEBUGCONFIG_LEAF = 0xFE
#endif

#ifdef DEBUGFEATURE_NON_ARCH_WORKAROUND
    ,TDXMODE_LEAF = 0xFF
#endif
} seamcall_leaf_opcode_t;

typedef enum tdcall_leaf_opcode_e
{
    TDG_VP_VMCALL_LEAF = 0,
    TDG_VP_INFO_LEAF = 1,
    TDG_MR_RTMR_EXTEND_LEAF = 2,
    TDG_VP_VEINFO_GET_LEAF = 3,
    TDG_MR_REPORT_LEAF = 4,
    TDG_VP_CPUIDVE_SET_LEAF = 5,
    TDG_MEM_PAGE_ACCEPT_LEAF = 6,
    TDG_VM_RD_LEAF = 7,
    TDG_VM_WR_LEAF = 8,
    TDG_VP_RD_LEAF = 9,
    TDG_VP_WR_LEAF = 10,
    TDG_SYS_RD_LEAF = 11,
    TDG_SYS_RDALL_LEAF = 12,
    TDG_SERVTD_RD_LEAF = 18,
    TDG_SERVTD_WR_LEAF = 20,
    TDG_MR_VERIFYREPORT_LEAF = 22,
    TDG_MEM_PAGE_ATTR_RD_LEAF = 23,
    TDG_MEM_PAGE_ATTR_WR_LEAF = 24,
    TDG_VP_ENTER_LEAF = 25,
    TDG_VP_INVEPT_LEAF = 26,
    TDG_VP_INVVPID_LEAF = 27
} tdcall_leaf_opcode_t;

typedef union tdx_leaf_and_version_u
{
    struct
    {
        uint64_t leaf            : 16;
        uint64_t version         : 8;
        uint64_t reserved0       : 8;
        uint64_t reserved1       : 32;
    };
    uint64_t raw;
} tdx_leaf_and_version_t;
tdx_static_assert(sizeof(tdx_leaf_and_version_t) == 8, tdx_leaf_and_version_t);

typedef union page_info_api_input_s {
    struct
    {
        uint64_t
            level : 3,  /**< Level */
            reserved_0 : 9,  /**< Must be 0 */
            gpa : 40, /**< GPA of the page */
            reserved_1 : 12; /**< Must be 0 */
    };
    uint64_t raw;
} page_info_api_input_t;

typedef union
{
    struct
    {
        uint32_t rsvd :31, debug_module :1;
    };
    uint32_t raw;
} tdsysinfo_attributes_t;

typedef union md_field_id_u
{
    struct
    {
        union
        {
            struct
            {
                uint32_t field_code : 24;
                uint32_t reserved_0 : 8;
            }; // default field code

            struct
            {
                uint32_t element     : 1;  // 0
                uint32_t subleaf     : 7;  // 1-7
                uint32_t subleaf_na  : 1;  // 8
                uint32_t leaf        : 7;  // 9-15
                uint32_t leaf_bit31  : 1;  // 16
                uint32_t reserved    : 15; // 17-31
            } cpuid_field_code;
        };

        struct
        {
            uint32_t element_size_code      : 2;    // Bits 33:32
            uint32_t last_element_in_field  : 4;    // Bits 37:34
            uint32_t last_field_in_sequence : 9;    // Bits 46:38
            uint32_t reserved_1             : 3;    // Bits 49:47
            uint32_t inc_size               : 1;    // Bit 50
            uint32_t write_mask_valid       : 1;    // Bit 51
            uint32_t context_code           : 3;    // Bits 54:52
            uint32_t reserved_2             : 1;    // Bit 55
            uint32_t class_code             : 6;    // Bits 61:56
            uint32_t reserved_3             : 1;    // Bit 62
            uint32_t non_arch               : 1;    // Bit 63
        };
    };
    uint64_t raw;
} md_field_id_t;
tdx_static_assert(sizeof(md_field_id_t) == 8, md_field_id_t);

#define MAX_NUM_CPUID_CONFIG 12

typedef union
{
    struct
    {
        uint32_t leaf;     //0..31
        uint32_t subleaf;  //32..63
    };
    uint64_t raw;
} cpuid_config_leaf_subleaf_t;

typedef union
{
    struct
    {
        uint32_t eax;
        uint32_t ebx;
        uint32_t ecx;
        uint32_t edx;
    };
    struct
    {
        uint64_t low;
        uint64_t high;
    };
    uint32_t values[4];
} cpuid_config_return_values_t;

typedef struct
{
    cpuid_config_leaf_subleaf_t leaf_subleaf;
    cpuid_config_return_values_t values;
} cpuid_config_t;
tdx_static_assert(sizeof(cpuid_config_t) == 24, cpuid_config_t);

#define SIZE_OF_TDHSYSINFO_STRUCT_IN_BYTES      1024
#define OFFSET_OF_MEMORY_INFO_IN_TDHSYSINFO     32
#define OFFSET_OF_CONTROL_INFO_IN_TDHSYSINFO    48
#define OFFSET_OF_TD_CAPABILITIES_IN_TDHSYSINFO 64

/**
 * @struct td_sys_info_t
 *
 * @brief TDSYSINFO_STRUCT provides enumeration information about the TDX-SEAM module.
 *
 * It is an output of the SEAMCALL(TDSYSINFO) leaf function.
 *
 */
typedef struct PACKED td_sys_info_s
{
    /**
     * TDX Module Info
     */
    tdsysinfo_attributes_t attributes;
    uint32_t vendor_id; /**< 0x8086 for Intel */
    uint32_t build_date;
    uint16_t build_num;
    uint16_t minor_version;
    uint16_t major_version;
    uint8_t  sys_rd;
    uint8_t reserved_0[13]; /**< Must be 0 */

    /**
     * Memory Info
     */
    uint16_t max_tdmrs; /**< The maximum number of TDMRs supported. */
    uint16_t max_reserved_per_tdmr; /**< The maximum number of reserved areas per TDMR. */
    uint16_t pamt_entry_size; /**< The number of bytes that need to be reserved for the three PAMT areas. */
    uint8_t reserved_1[10]; /**< Must be 0 */

    /**
     * Control Struct Info
     */
    uint16_t tdcs_base_size; /**< Base value for the number of bytes required to hold TDCS. */
    uint8_t reserved_2[2]; /**< Must be 0 */
    uint16_t tdvps_base_size; /**< Base value for the number of bytes required to hold TDVPS. */
    /**
     * A value of 1 indicates that additional TDVPS bytes are required to hold extended state,
     * per the TD’s XFAM.
     * The host VMM can calculate the size using CPUID.0D.01.EBX.
     * A value of 0 indicates that TDVPS_BASE_SIZE already includes the maximum supported extended state.
     */
    bool_t tdvps_xfam_dependent_size;
    uint8_t reserved_3[9]; /**< Must be 0 */

    /**
     * TD Capabilities
     */
    uint64_t attributes_fixed0; /**< If bit X is 0 in ATTRIBUTES_FIXED0, it must be 0 in any TD’s ATTRIBUTES. */
    uint64_t attributes_fixed1; /**< If bit X is 1 in ATTRIBUTES_FIXED1, it must be 1 in any TD’s ATTRIBUTES. */
    uint64_t xfam_fixed0; /**< If bit X is 0 in XFAM_FIXED0, it must be 0 in any TD’s XFAM. */
    uint64_t xfam_fixed1; /**< If bit X is 1 in XFAM_FIXED1, it must be 1 in any TD’s XFAM. */

    uint8_t reserved_4[32]; /**< Must be 0 */

    uint32_t num_cpuid_config;
    cpuid_config_t cpuid_config_list[MAX_NUM_CPUID_CONFIG];
    uint8_t reserved_5[892 - (sizeof(cpuid_config_t) * MAX_NUM_CPUID_CONFIG)];
} td_sys_info_t;

tdx_static_assert(offsetof(td_sys_info_t, max_tdmrs) == OFFSET_OF_MEMORY_INFO_IN_TDHSYSINFO, td_sys_info_t);
tdx_static_assert(offsetof(td_sys_info_t, tdcs_base_size) == OFFSET_OF_CONTROL_INFO_IN_TDHSYSINFO, td_sys_info_t);
tdx_static_assert(offsetof(td_sys_info_t, attributes_fixed0) == OFFSET_OF_TD_CAPABILITIES_IN_TDHSYSINFO, td_sys_info_t);
tdx_static_assert(sizeof(td_sys_info_t) == SIZE_OF_TDHSYSINFO_STRUCT_IN_BYTES, td_sys_info_t_incorrect_struct_size);

#define MAX_RESERVED_AREAS 16U

/**
 * @struct tdmr_info_entry_t
 *
 * @brief TDMR_INFO provides information about a TDMR and its associated PAMT
 *
 * An array of TDMR_INFO entries is passed as input to SEAMCALL(TDHSYSCONFIG) leaf function.
 *
 * - The TDMRs must be sorted from the lowest base address to the highest base address,
 *   and must not overlap with each other.
 *
 * - Within each TDMR entry, all reserved areas must be sorted from the lowest offset to the highest offset,
 *   and must not overlap with each other.
 *
 * - All TDMRs and PAMTs must be contained within CMRs.
 *
 * - A PAMT area must not overlap with another PAMT area (associated with any TDMR), and must not
 *   overlap with non-reserved areas of any TDMR. PAMT areas may reside within reserved areas of TDMRs.
 *
 */
typedef struct PACKED tdmr_info_entry_s
{
    uint64_t tdmr_base;    /**< Base address of the TDMR (HKID bits must be 0). 1GB aligned. */
    uint64_t tdmr_size;    /**< Size of the CMR, in bytes. 1GB aligned. */
    uint64_t pamt_1g_base; /**< Base address of the PAMT_1G range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_1g_size; /**< Size of the PAMT_1G range associated with the above TDMR. 4K aligned. */
    uint64_t pamt_2m_base; /**< Base address of the PAMT_2M range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_2m_size; /**< Size of the PAMT_2M range associated with the above TDMR. 4K aligned. */
    uint64_t pamt_4k_base; /**< Base address of the PAMT_4K range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_4k_size; /**< Size of the PAMT_4K range associated with the above TDMR. 4K aligned. */

    struct
    {
        uint64_t offset; /**< Offset of reserved range 0 within the TDMR. 4K aligned. */
        uint64_t size;   /**< Size of reserved range 0 within the TDMR. A size of 0 indicates a null entry. 4K aligned. */
    } rsvd_areas[MAX_RESERVED_AREAS];

} tdmr_info_entry_t;

#define PAMT_ENTRY_SIZE_IN_BYTES        16

#define SIZE_OF_SHA384_BLOCK_IN_QWORD 16
#define SIZE_OF_SHA384_BLOCK_IN_DWORD (SIZE_OF_SHA384_BLOCK_IN_QWORD<<1)
#define SIZE_OF_SHA384_BLOCK_IN_BYTES (SIZE_OF_SHA384_BLOCK_IN_DWORD<<2)
#define SIZE_OF_SHA384_STATE_IN_QWORD 8
#define SIZE_OF_SHA384_STATE_IN_DWORD (SIZE_OF_SHA384_STATE_IN_QWORD<<1)
#define SIZE_OF_SHA384_STATE_IN_BYTES (SIZE_OF_SHA384_STATE_IN_DWORD<<2)
#define SIZE_OF_SHA384_HASH_IN_QWORDS 6
#define SIZE_OF_SHA384_HASH_IN_BYTES (SIZE_OF_SHA384_HASH_IN_QWORDS << 3)

#define HASH_METHOD_BUFFER_SIZE       64
#define SIZE_OF_SHA384_CTX_BUFFER     256

typedef struct hash_method_s
{
    uint8_t hash_method_buffer[HASH_METHOD_BUFFER_SIZE];
    bool_t is_initialized;
} hash_method_t;

typedef union measurement_u
{
    uint64_t qwords[SIZE_OF_SHA384_HASH_IN_QWORDS];
    uint8_t  bytes[SIZE_OF_SHA384_HASH_IN_BYTES];
} measurement_t;
tdx_static_assert(sizeof(measurement_t) == SIZE_OF_SHA384_HASH_IN_BYTES, measurement_t);

/**
 * @struct td_param_attributes_t
 *
 * @brief TD attributes.
 *
 * The value set in this field must comply with ATTRIBUTES_FIXED0 and ATTRIBUTES_FIXED1 enumerated by TDSYSINFO
 */
typedef union td_param_attributes_s {
    struct
    {
        uint64_t debug           : 1;   // Bit 0
        uint64_t reserved_tud    : 7;   // Bits 7:1
        uint64_t reserved_sec    : 20;  // Bits 28:8
        uint64_t sept_ve_disable : 1;   // Bit  28 - disable #VE on pending page access
        uint64_t migratable      : 1;   // Bit 29
        uint64_t pks             : 1;   // Bit 30
        uint64_t kl              : 1;   // Bit 31
        uint64_t reserved_other  : 31;  // Bits 62:32
        uint64_t perfmon         : 1;   // Bit 63
    };
    uint64_t raw;
} td_param_attributes_t;
tdx_static_assert(sizeof(td_param_attributes_t) == 8, td_param_attributes_t);

/**
 * @struct eptp_controls_t
 *
 * @brief Control bits of EPTP, copied to each TD VMCS on TDHVPINIT
 */
typedef union eptp_controls_s {
    struct
    {
        uint64_t ept_ps_mt          : 3;   // Bits 0-2
        uint64_t ept_pwl            : 3;   // 1 less than the EPT page-walk length
        uint64_t enable_ad_bits     : 1;
        uint64_t enable_sss_control : 1;
        uint64_t reserved_0         : 4;
        uint64_t base_pa            : 40; // Root Secure-EPT page address
        uint64_t reserved_1         : 12;
    };
    uint64_t raw;
} eptp_controls_t;
tdx_static_assert(sizeof(eptp_controls_t) == 8, eptp_controls_t);

/**
 * @struct exec_controls_t
 *
 * @brief Non-measured TD-scope execution controls.
 *
 * Most fields are copied to each TD VMCS TSC-offset execution control on TDHVPINIT.
 */
typedef union exec_controls_s {
    struct
    {
        uint64_t
        gpaw                : 1,  /**< TD-scope Guest Physical Address Width execution control. */
        reserved            : 63; /**< Must be 0. */
    };
    uint64_t raw;
} exec_controls_t;
tdx_static_assert(sizeof(exec_controls_t) == 8, exec_controls_t);

#define SIZE_OF_TD_PARAMS_IN_BYTES     1024
#define TD_PARAMS_ALIGN_IN_BYTES       1024
#define SIZE_OF_SHA384_HASH_IN_QWORDS  6
#define SIZE_OF_SHA256_HASH_IN_QWORDS  4

#define TD_PARAMS_RESERVED0_SIZE       4

#define TD_PARAMS_RESERVED1_SIZE       38

#define TD_PARAMS_RESERVED2_SIZE       24

#define TD_PARAMS_RESERVED3_SIZE       (768 - (sizeof(cpuid_config_return_values_t) * MAX_NUM_CPUID_CONFIG))

/**
 * @struct td_params_t
 *
 * @brief TD_PARAMS is provided as an input to TDHMNGINIT, and some of its fields are included in the TD report.
 *
 * The format of this structure is valid for a specific MAJOR_VERSION of the TDX-SEAM module,
 * as reported by TDSYSINFO.
 */
typedef struct PACKED td_params_s
{
    td_param_attributes_t        attributes;
    /**
     * Extended Features Available Mask.
     * Indicates the extended state features allowed for the TD.
     * XFAM’s format is the same as XCR0 and IA32_XSS MSR
     */
    uint64_t                     xfam;
    uint16_t                     max_vcpus; /**< Maximum number of VCPUs */
    uint8_t                      num_l2_vms;

    struct
    {
        uint8_t  ia32_arch_cap : 1;   // Bit 0
        uint8_t  reserved_0    : 7;   // Bits 7:1
    } msr_config_ctls;

    uint8_t                      reserved_0[TD_PARAMS_RESERVED0_SIZE]; /**< Must be 0 */
    eptp_controls_t              eptp_controls;
    exec_controls_t              exec_controls;


    uint16_t                     tsc_frequency;

    uint8_t                      reserved_1[TD_PARAMS_RESERVED1_SIZE]; /**< Must be 0 */

    /**
     * Software defined ID for additional configuration for the SW in the TD
     */
    measurement_t                mr_config_id;
    /**
     * Software defined ID for TD’s owner
     */
    measurement_t                mr_owner;
    /**
     * Software defined ID for TD’s owner configuration
     */
    measurement_t                mr_owner_config;

    uint64_t                     ia32_arch_capabilities_config;

    uint8_t                      reserved_2[TD_PARAMS_RESERVED2_SIZE]; /**< Must be 0 */

    /**
     * CPUID leaves/sub-leaves configuration.
     * The number and order of entries must be equal to
     * the number and order of configurable CPUID leaves/sub-leaves reported by TDSYSINFO.
     * Note that the leaf and sub-leaf numbers are implicit.
     * Only bits that have been reported as 1 by TDSYSINFO may be set to 1.
     */
    cpuid_config_return_values_t cpuid_config_vals[MAX_NUM_CPUID_CONFIG];

    uint8_t                      reserved_3[TD_PARAMS_RESERVED3_SIZE];
} td_params_t;
tdx_static_assert(sizeof(td_params_t) == SIZE_OF_TD_PARAMS_IN_BYTES, td_params_t);

typedef union vcpu_and_flags_u
{
    struct
    {
        uint64_t reserved_0               : 12;  // Bits 11:0
        uint64_t tdvpra_hpa_51_12         : 40;  // Bits 51:12
        uint64_t host_recoverability_hint : 1;   // Bit 52
        uint64_t resume_l1                : 1;   // Bit 53
        uint64_t reserved_1               : 10;  // Bits 63:54
    };
    uint64_t raw;
} vcpu_and_flags_t;
tdx_static_assert(sizeof(vcpu_and_flags_t) == 8, vcpu_and_flags_t);

#pragma pack(pop)

//
// tdvps_fields_lookup.h
//

// Class codes
#define MD_TDVPS_VMCS_CLASS_CODE 0ULL
#define MD_TDVPS_MANAGEMENT_CLASS_CODE 32ULL
#define MD_TDVPS_EPT_VIOLATION_LOG_CLASS_CODE 34ULL
#define MD_TDVPS_MSR_BITMAPS_SHADOW_1_CLASS_CODE 38ULL
#define MD_TDVPS_MSR_BITMAPS_2_CLASS_CODE 45ULL
#define MD_TDVPS_VMCS_2_CLASS_CODE 44ULL
#define MD_TDVPS_MSR_BITMAPS_SHADOW_3_CLASS_CODE 54ULL
#define MD_TDVPS_GUEST_STATE_CLASS_CODE 17ULL
#define MD_TDVPS_GUEST_EXT_STATE_CLASS_CODE 18ULL
#define MD_TDVPS_MSR_BITMAPS_SHADOW_2_CLASS_CODE 46ULL
#define MD_TDVPS_CPUID_CONTROL_CLASS_CODE 33ULL
#define MD_TDVPS_VMCS_3_CLASS_CODE 52ULL
#define MD_TDVPS_MSR_BITMAPS_3_CLASS_CODE 53ULL
#define MD_TDVPS_GUEST_GPR_STATE_CLASS_CODE 16ULL
#define MD_TDVPS_VMCS_1_CLASS_CODE 36ULL
#define MD_TDVPS_GUEST_MSR_STATE_CLASS_CODE 19ULL
#define MD_TDVPS_VAPIC_CLASS_CODE 1ULL
#define MD_TDVPS_VE_INFO_CLASS_CODE 2ULL
#define MD_TDVPS_MSR_BITMAPS_1_CLASS_CODE 37ULL
#define MD_TDVPS_RESERVED_CLASS_CODE 0xFFFFFFFFFFFFFFFF

//
// vmcs_defs.h
//

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
#define VMX_HOST_ES_SELECTOR_ENCODE  0x0C00ULL
#define VMX_HOST_CS_SELECTOR_ENCODE  0x0C02ULL
#define VMX_HOST_SS_SELECTOR_ENCODE  0x0C04ULL
#define VMX_HOST_DS_SELECTOR_ENCODE  0x0C06ULL
#define VMX_HOST_FS_SELECTOR_ENCODE  0x0C08ULL
#define VMX_HOST_GS_SELECTOR_ENCODE  0x0C0AULL
#define VMX_HOST_TR_SELECTOR_ENCODE  0x0C0CULL

#define VMX_HOST_RSP_ENCODE  0x6C14ULL
#define VMX_HOST_RIP_ENCODE  0x6C16ULL

#define VMX_HOST_IA32_PAT_FULL_ENCODE  0x2c00ULL
#define VMX_HOST_IA32_EFER_FULL_ENCODE  0x2c02

#define VMX_HOST_IA32_S_CET_ENCODE  0x6C18
#define VMX_HOST_SSP_ENCODE  0x6C1A

typedef union ia32_vmx_misc_u
{
    struct
    {
        uint64_t vmx_preempt_timer_tsc_factor   : 5;   // Bits 4:0
        uint64_t unrestricted_guest             : 1;   // bit 5
        uint64_t activity_hlt                   : 1;   // bit 6
        uint64_t activity_shutdown              : 1;   // bit 7
        uint64_t activity_wait_for_sipi         : 1;   // bit 8
        uint64_t reserved                       : 5;   // bits 13:9
        uint64_t pt_in_vmx                      : 1;   // bit 14
        uint64_t ia32_smbase                    : 1;   // bit 15
        uint64_t max_cr3_targets                : 9;   // bits 24:16
        uint64_t max_msr_list_size              : 3;   // bits 27:25
        uint64_t ia32_smm_monitor_ctl           : 1;   // bit 28
        uint64_t vmwrite_any_vmcs_field         : 1;   // bit 29
        uint64_t voe_with_0_instr_length        : 1;   // bit 30
        uint64_t reserved_1                     : 1;   // bit 31
        uint64_t mseg_rev_id                    : 32;  // bits 63:32
    };
    uint64_t raw;
} ia32_vmx_misc_t;
tdx_static_assert(sizeof(ia32_vmx_misc_t) == 8, ia32_vmx_misc_t);

typedef enum {
    VMEXIT_REASON_EXCEPTION_OR_NMI                       = 0,
    VMEXIT_REASON_INTERRUPT                              = 1,
    VMEXIT_REASON_TRIPLE_FAULT                           = 2,
    VMEXIT_REASON_INIT_EVENT                             = 3,
    VMEXIT_REASON_SIPI_EVENT                             = 4,
    VMEXIT_REASON_SMI_IO_EVENT                           = 5,
    VMEXIT_REASON_SMI_OTHER_EVENT                        = 6,
    VMEXIT_REASON_INTERRUPT_WINDOW                       = 7,
    VMEXIT_REASON_NMI_WINDOW                             = 8,
    VMEXIT_REASON_TASK_SWITCH                            = 9,
    VMEXIT_REASON_CPUID_INSTRUCTION                      = 10,
    VMEXIT_REASON_GETSEC_INSTRUCTION                     = 11,
    VMEXIT_REASON_HLT_INSTRUCTION                        = 12,
    VMEXIT_REASON_INVD_INSTRUCTION                       = 13,
    VMEXIT_REASON_INVLPG_INSTRUCTION                     = 14,
    VMEXIT_REASON_RDPMC_INSTRUCTION                      = 15,
    VMEXIT_REASON_RDTSC_INSTRUCTION                      = 16,
    VMEXIT_REASON_RSM_INSTRUCTION                        = 17,
    VMEXIT_REASON_VMCALL_INSTRUCTION                     = 18,
    VMEXIT_REASON_VMCLEAR_INSTRUCTION                    = 19,
    VMEXIT_REASON_VMLAUNCH_INSTRUCTION                   = 20,
    VMEXIT_REASON_VMPTRLD_INSTRUCTION                    = 21,
    VMEXIT_REASON_VMPTRST_INSTRUCTION                    = 22,
    VMEXIT_REASON_VMREAD_INSTRUCTION                     = 23,
    VMEXIT_REASON_VMRESUME_INSTRUCTION                   = 24,
    VMEXIT_REASON_VMWRITE_INSTRUCTION                    = 25,
    VMEXIT_REASON_VMXOFF_INSTRUCTION                     = 26,
    VMEXIT_REASON_VMXON_INSTRUCTION                      = 27,
    VMEXIT_REASON_CR_ACCESS                              = 28,
    VMEXIT_REASON_DR_ACCESS                              = 29,
    VMEXIT_REASON_IO_INSTRUCTION                         = 30,
    VMEXIT_REASON_MSR_READ                               = 31,
    VMEXIT_REASON_MSR_WRITE                              = 32,
    VMEXIT_REASON_FAILED_VMENTER_GS                      = 33,
    VMEXIT_REASON_FAILED_VMENTER_MSR                     = 34,
    VMEXIT_REASON_VMEXIT_FAILURE                         = 35,
    VMEXIT_REASON_MWAIT_INSTRUCTION                      = 36,
    VMEXIT_REASON_MTF                                    = 37,
    VMEXIT_REASON_MONITOR_INSTRUCTION                    = 39,
    VMEXIT_REASON_PAUSE_INSTRUCTION                      = 40,
    VMEXIT_REASON_FAILED_VMENTER_MC                      = 41,
    VMEXIT_REASON_C_STATE_SMI                            = 42,
    VMEXIT_REASON_TPR_BELOW_THRESHOLD                    = 43,
    VMEXIT_REASON_APIC_ACCESS                            = 44,
    VMEXIT_REASON_VIRTUALIZED_EOI                        = 45,
    VMEXIT_REASON_GDTR_IDTR_ACCESS                       = 46,
    VMEXIT_REASON_LDTR_TR_ACCESS                         = 47,
    VMEXIT_REASON_EPT_VIOLATION                          = 48,
    VMEXIT_REASON_EPT_MISCONFIGURATION                   = 49,
    VMEXIT_REASON_INVLEPT                                = 50,
    VMEXIT_REASON_RDTSCP                                 = 51,
    VMEXIT_REASON_PREEMPTION_TIMER_EXPIRED               = 52,
    VMEXIT_REASON_INVLVPID                               = 53,
    VMEXIT_REASON_WBINVD_INSTRUCTION                     = 54,
    VMEXIT_REASON_XSETBV_INSTRUCTION                     = 55,
    VMEXIT_REASON_APIC_WRITE                             = 56,
    VMEXIT_REASON_RDRAND_INSTRUCTION                     = 57,
    VMEXIT_REASON_INVPCID_INSTRUCTION                    = 58,
    VMEXIT_REASON_VMFUNC_INSTRUCTION                     = 59,
    VMEXIT_REASON_ENCLS_INSTRUCTION                      = 60,
    VMEXIT_REASON_RDSEED_INSTRUCTION                     = 61,
    VMEXIT_REASON_EPT_PML_FULL                           = 62,
    VMEXIT_REASON_XSAVES_INSTRUCTION                     = 63,
    VMEXIT_REASON_XRSTORS_INSTRUCTION                    = 64,
    VMEXIT_REASON_PCONFIG                                = 65,
    VMEXIT_REASON_SPP_INDUCED                            = 66,
    VMEXIT_REASON_UMWAIT                                 = 67,
    VMEXIT_REASON_TPAUSE                                 = 68,
    VMEXIT_REASON_LOADIWK_INSTRUCTION                    = 69,
    VMEXIT_REASON_ENCLV_INSTRUCTION                      = 70,
    VMEXIT_REASON_SGX_CONFLICT                           = 71,
    VMEXIT_REASON_ENQCMD_PASID_TRANSLATION_FAILURE       = 72,
    VMEXIT_REASON_ENQCMDS_PASID_TRANSLATION_FAILURE      = 73,
    VMEXIT_REASON_BUS_LOCK                               = 74,
    VMEXIT_REASON_NOTIFICATION                           = 75,
    VMEXIT_REASON_SEAMCALL                               = 76,
    VMEXIT_REASON_TDCALL                                 = 77
} vm_exit_basic_reason_e;

//
// td_control_structures.h
//

#define TDX_XFAM_FIXED1 0x00000003ULL

#define VIRT_TSC_FREQUENCY_MIN         4           // 100MHz

//
// mktme.h
//

typedef union
{
    uint64_t  qwords[2];
    uint32_t  dwords[4];
    uint8_t   bytes[16];
} uint128_t;

// keyid_ctrl command types
#define MKTME_KEYID_SET_KEY_DIRECT 0
#define MKTME_KEYID_SET_KEY_RANDOM 1
#define MKTME_KEYID_CLEAR_KEY      2
#define MKTME_KEYID_NO_ENCRYPT     3

typedef union
{
    struct
    {
        uint32_t
            command  : 8,
            enc_algo : 16,
            rsvd     : 8;
    };
    uint32_t raw;
} mktme_keyid_ctrl_t;

#define MKTME_KP_RESERVED1_SIZE (64 - sizeof(uint16_t) - sizeof(mktme_keyid_ctrl_t))
#define MKTME_KP_KEY_FIELD_SIZE (64)
#define MKTME_KP_RESERVED2_SIZE (256 - 64 - MKTME_KP_KEY_FIELD_SIZE*2)

#pragma pack(push)
#pragma pack(1)

typedef struct PACKED mktme_key_program_s {
    uint16_t            keyid;
    mktme_keyid_ctrl_t  keyid_ctrl;
    uint8_t             rsvd[MKTME_KP_RESERVED1_SIZE];
    //64 bytes
    union
    {
        uint128_t key; //16Bytes
        uint8_t key_field_1[MKTME_KP_KEY_FIELD_SIZE];
    };
    union
    {
        uint128_t tweak_key; //16Bytes
        uint8_t key_field_2[MKTME_KP_KEY_FIELD_SIZE];
    };
    uint8_t rsvd2[MKTME_KP_RESERVED2_SIZE];
} mktme_key_program_t;
tdx_static_assert(sizeof(mktme_key_program_t) == 256, mktme_key_program_t);

#pragma pack(pop)