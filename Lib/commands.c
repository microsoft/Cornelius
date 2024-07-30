// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "common.h"

UINT64
SeamcallPseamldr_Info(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 Gpa, seamldr_info_t *PseamldrInfo)
{
    seamldr_info_t *InfoBuffer;
    VCPU_STATE *VmmState;

    MapGpa(Vm, Gpa, PAGE_SIZE);

    InfoBuffer = (seamldr_info_t *)GPA_TO_HVA(Vm, Gpa);
    memset(InfoBuffer, 0, PAGE_SIZE);

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->Rax = SEAMLDR_INFO_LEAF;
    VmmState->Rcx = Gpa;

    if (RunVCPU(Vm, VcpuNum, VcpuModePseamldr) != VcpuActionSeamRet) {
        exit(-1);
    }
    if (VmmState->Rax != 0) {
        return VmmState->Rax;
    }

    memcpy(PseamldrInfo, InfoBuffer, sizeof(seamldr_info_t));

    UnmapGpa(Vm, Gpa, PAGE_SIZE);
    return 0;
}

UINT64
SeamcallPseamldr_Install(CORNELIUS_VM *Vm, UINT32 VcpuNum, PUINT8 TdxBuffer, SIZE_T TdxSize)
{
    const UINT64 SeamldrParamsPa = 0x1000;
    const UINT64 SeamSigstructPa = 0x2000;
    const UINT64 TdxBufferPa = 0x3000;
    seamldr_params_t *SeamldrParamsHva;
    seam_sigstruct_t *SeamSigstructHva;
    VCPU_STATE *VmmState;
    HRESULT hRes;
    SIZE_T i;

    //
    // Map the TDX module in the PA space.
    //

    if (TdxSize % PAGE_SIZE != 0) {
        FATAL("TdxSize % PAGE_SIZE != 0");
    }
    if (TdxBufferPa + TdxSize > Vm->VmConfig.SeamrrBase) {
        FATAL("TdxBufferPa + TdxSize > Vm->VmConfig.SeamrrBase");
    }

    hRes = WHvMapGpaRange(Vm->Partition,
                          (PVOID)TdxBuffer,
                          TdxBufferPa,
                          TdxSize,
                          WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    FAIL_IF_ERROR(hRes);

    //
    // Allocate, map and build the SeamSigstruct structure.
    //

    C_ASSERT(sizeof(seam_sigstruct_t) <= PAGE_SIZE);

    MapGpa(Vm, SeamSigstructPa, PAGE_SIZE);

    SeamSigstructHva = (seam_sigstruct_t *)GPA_TO_HVA(Vm, SeamSigstructPa);
    memset(SeamSigstructHva, 0, PAGE_SIZE);

    SeamSigstructHva->header_type = SEAM_SIGSTRUCT_HEADER_TYPE_GENERIC_FW;
    SeamSigstructHva->header_length = SEAM_SIGSTRUCT_HEADER_LENGTH_DWORDS;
    SeamSigstructHva->header_version = SEAM_SIGSTRUCT_HEADER_VERSION;
    memset(&SeamSigstructHva->module_type, 0, sizeof(SeamSigstructHva->module_type));
    SeamSigstructHva->module_vendor = SEAM_SIGSTRUCT_INTEL_MODULE_VENDOR;
    SeamSigstructHva->date = 0;
    SeamSigstructHva->size = SEAM_SIGSTRUCT_SIZE_DWORDS;
    SeamSigstructHva->key_size = SEAM_SIGSTRUCT_KEY_SIZE_DWORDS;
    SeamSigstructHva->modulus_size = SEAM_SIGSTRUCT_MODULUS_SIZE_DWORDS;
    SeamSigstructHva->exponent_size = SEAM_SIGSTRUCT_EXPONENT_SIZE_DWORDS;
    memset(&SeamSigstructHva->modulus, 0xFF, sizeof(SeamSigstructHva->modulus));
    SeamSigstructHva->exponent = SEAM_SIGSTRUCT_RSA_EXPONENT;
    memset(&SeamSigstructHva->signature, 0, sizeof(SeamSigstructHva->signature));
    memset(&SeamSigstructHva->seamhash, 0, sizeof(SeamSigstructHva->seamhash));
    SeamSigstructHva->seamsvn.seam_major_svn = TDX_MODULE_1_0_MAJOR_SVN + 1;
    SeamSigstructHva->seamsvn.seam_minor_svn = 0;
    SeamSigstructHva->attributes = 0;
    SeamSigstructHva->rip_offset = (UINT32)GetElfEntryPoint(TdxBuffer, TdxSize);

    // Not sure which values Intel sets here. Set "sane" values.
    SeamSigstructHva->num_stack_pages = 4;
    SeamSigstructHva->num_tls_pages = 4;
    SeamSigstructHva->num_keyhole_pages = 32;
    SeamSigstructHva->num_global_data_pages = 32;

    SeamSigstructHva->max_tdmrs = 0;
    SeamSigstructHva->max_rsvd_per_tdmr = 0;
    SeamSigstructHva->pamt_entry_size_4k = 0;
    SeamSigstructHva->pamt_entry_size_2m = 0;
    SeamSigstructHva->pamt_entry_size_1g = 0;
    SeamSigstructHva->module_hv = 0;
    SeamSigstructHva->min_update_hv = 0;
    SeamSigstructHva->no_downgrade = FALSE;
    SeamSigstructHva->num_handoff_pages = 100;
    SeamSigstructHva->gdt_idt_offset = (UINT32)GetElfSymbolOffset(TdxBuffer, TdxSize, "tdx_idt_and_gdt_tables");
    SeamSigstructHva->fault_wrapper_offset = (UINT32)GetElfSymbolOffset(TdxBuffer, TdxSize, "tdx_fault_wrapper");
    SeamSigstructHva->cpuid_table_size = 1;
    SeamSigstructHva->cpuid_table[0] = 0; // p_sysinfo_table->socket_cpuid_table is full of zeroes, so keep it to zero here, to match

    //
    // Allocate, map and build the SeamldrParams structure.
    //

    MapGpa(Vm, SeamldrParamsPa, PAGE_SIZE);

    SeamldrParamsHva = (seamldr_params_t *)GPA_TO_HVA(Vm, SeamldrParamsPa);
    memset(SeamldrParamsHva, 0, PAGE_SIZE);

    SeamldrParamsHva->version = 0;
    SeamldrParamsHva->scenario = SEAMLDR_SCENARIO_LOAD;
    SeamldrParamsHva->sigstruct_pa = SeamSigstructPa;
    SeamldrParamsHva->num_module_pages = TdxSize / PAGE_SIZE;

    // If the TDX module is too big, and it has ASAN, then use the extended fields
    // for the additional PAs.
    if (SeamldrParamsHva->num_module_pages > SEAMLDR_PARAMS_MAX_MODULE_PAGES) {
        if (!Vm->VmConfig.HasSanitizers) {
            FATAL("SeamldrParamsHva->num_module_pages > SEAMLDR_PARAMS_MAX_MODULE_PAGES");
        }
        for (i = 0; i < SEAMLDR_PARAMS_MAX_MODULE_PAGES; i++) {
            SeamldrParamsHva->mod_pages_pa_list[i] = TdxBufferPa + i * PAGE_SIZE;
        }
        SeamldrParamsHva->ext.pa_start = TdxBufferPa + SEAMLDR_PARAMS_MAX_MODULE_PAGES * PAGE_SIZE;
    } else {
        for (i = 0; i < SeamldrParamsHva->num_module_pages; i++) {
            SeamldrParamsHva->mod_pages_pa_list[i] = TdxBufferPa + i * PAGE_SIZE;
        }
    }

    //
    // Invoke SEAMCALL.
    //

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->Rax = SEAMLDR_INSTALL_LEAF;
    VmmState->Rcx = SeamldrParamsPa;

    if (RunVCPU(Vm, VcpuNum, VcpuModePseamldr) != VcpuActionSeamRet) {
        exit(-1);
    }

    //
    // Unmap and free the buffers.
    //

    hRes = WHvUnmapGpaRange(Vm->Partition, TdxBufferPa, TdxSize);
    FAIL_IF_ERROR(hRes);

    UnmapGpa(Vm, SeamSigstructPa, PAGE_SIZE);
    UnmapGpa(Vm, SeamldrParamsPa, PAGE_SIZE);

    return VmmState->Rax;
}

BOOLEAN
SeamcallTdx_TdhSysInfo(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    const UINT64 InfoPa = 0x1000;
    td_sys_info_t *InfoHva;
    VCPU_STATE *VmmState;

    MapGpa(Vm, InfoPa, 2 * PAGE_SIZE);

    InfoHva = (td_sys_info_t *)GPA_TO_HVA(Vm, InfoPa);
    memset(InfoHva, 0, 2 * PAGE_SIZE);

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_SYS_INFO_LEAF;
    VmmState->Rcx = InfoPa;
    VmmState->Rdx = PAGE_SIZE;
    VmmState->R8 = InfoPa + PAGE_SIZE;
    VmmState->R9 = 0xFFFF;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }
    if (VmmState->Rax != 0) {
        exit(-1);
    }

    printf("td_sys_info_t::vendor_id = 0x%lx\n", InfoHva->vendor_id);

    UnmapGpa(Vm, InfoPa, 2 * PAGE_SIZE);

    return TRUE;
}

UINT64
SeamcallTdx_TdhSysInit(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    VCPU_STATE *VmmState;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_SYS_INIT_LEAF;
    VmmState->Rcx = 0;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhSysLpInit(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    VCPU_STATE *VmmState;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_SYS_LP_INIT_LEAF;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhSysConfig(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    const UINT64 ArrayGpa = 0x1000;
    const UINT64 TdmrInfoEntriesGpa = 0x2000;
    PUINT64 Array;
    tdmr_info_entry_t *TdmrInfoEntry;
    VCPU_STATE *VmmState;

    MapGpa(Vm, ArrayGpa, PAGE_SIZE);

    Array = (PUINT64)GPA_TO_HVA(Vm, ArrayGpa);
    Array[0] = TdmrInfoEntriesGpa;

    //
    // Create one TDMR, covering CMR[0]. The PAMTs go first, and then we have two reserved
    // areas, one to skip the beginning, one to skip the end.
    //

    MapGpa(Vm, TdmrInfoEntriesGpa, PAGE_SIZE);

    TdmrInfoEntry = (tdmr_info_entry_t *)GPA_TO_HVA(Vm, TdmrInfoEntriesGpa);
    memset (TdmrInfoEntry, 0, sizeof (*TdmrInfoEntry));

    TdmrInfoEntry->tdmr_base = 0;
    TdmrInfoEntry->tdmr_size = _1GB;

    TdmrInfoEntry->pamt_1g_base = Vm->VmConfig.Cmrs[0].Base;
    TdmrInfoEntry->pamt_1g_size = ALIGN_UP_BY(TdmrInfoEntry->tdmr_size / _1GB * PAMT_ENTRY_SIZE_IN_BYTES, _4KB);

    TdmrInfoEntry->pamt_2m_base = TdmrInfoEntry->pamt_1g_base + TdmrInfoEntry->pamt_1g_size;
    TdmrInfoEntry->pamt_2m_size = ALIGN_UP_BY(TdmrInfoEntry->tdmr_size / _2MB * PAMT_ENTRY_SIZE_IN_BYTES, _4KB);

    TdmrInfoEntry->pamt_4k_base = TdmrInfoEntry->pamt_2m_base + TdmrInfoEntry->pamt_2m_size;
    TdmrInfoEntry->pamt_4k_size = ALIGN_UP_BY(TdmrInfoEntry->tdmr_size / _4KB * PAMT_ENTRY_SIZE_IN_BYTES, _4KB);

    TdmrInfoEntry->rsvd_areas[0].offset = 0;
    TdmrInfoEntry->rsvd_areas[0].size = TdmrInfoEntry->pamt_4k_base + TdmrInfoEntry->pamt_4k_size;

    TdmrInfoEntry->rsvd_areas[1].offset = Vm->VmConfig.Cmrs[0].Base + Vm->VmConfig.Cmrs[0].Size;
    TdmrInfoEntry->rsvd_areas[1].size = TdmrInfoEntry->tdmr_size - TdmrInfoEntry->rsvd_areas[1].offset;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_SYS_CONFIG_LEAF;
    VmmState->Rcx = ArrayGpa;
    VmmState->Rdx = 1;
    VmmState->R8 = (1ULL << Vm->VmConfig.KeyidBits) - 1;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    if (VmmState->Rax == 0) {
        Vm->CmrsAvail[0].Start = TdmrInfoEntry->rsvd_areas[0].size;
        Vm->CmrsAvail[0].End = Vm->VmConfig.Cmrs[0].Base + Vm->VmConfig.Cmrs[0].Size;
    }

    UnmapGpa(Vm, ArrayGpa, PAGE_SIZE);
    UnmapGpa(Vm, TdmrInfoEntriesGpa, PAGE_SIZE);

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhSysKeyConfig(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    VCPU_STATE *VmmState;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_SYS_KEY_CONFIG_LEAF;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }
    if (VmmState->Rax != 0) {
        exit(-1);
    }

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhSysTdmrInit(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    VCPU_STATE *VmmState;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rdx = 0;

    while (TRUE) {
        VmmState->Rax = TDH_SYS_TDMR_INIT_LEAF;
        VmmState->Rcx = VmmState->Rdx;

        if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
            exit(-1);
        }
        if (VmmState->Rax != 0) {
            return VmmState->Rax;
        }
        if (VmmState->Rdx != 0) {
            break;
        }
    }

    return 0;
}

UINT64
SeamcallTdx_TdhMngCreate(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm)
{
    VCPU_STATE *VmmState;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_MNG_CREATE_LEAF;
    VmmState->Rcx = TdVm->TdrPa;
    VmmState->Rdx = TDX_PRIV_HKID(Vm, 0);

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhMngKeyConfig(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm)
{
    VCPU_STATE *VmmState;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_MNG_KEY_CONFIG_LEAF;
    VmmState->Rcx = TdVm->TdrPa;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhMngAddcx(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm)
{
    VCPU_STATE *VmmState;
    SIZE_T i;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;

#define MAX_NUM_TDCS_PAGES  9
    for (i = 0; i < MAX_NUM_TDCS_PAGES; i++) {
        VmmState->Rax = TDH_MNG_ADDCX_LEAF;
        VmmState->Rcx = AllocatePaFromCmrsAvail(Vm); // TDCX PA
        VmmState->Rdx = TdVm->TdrPa;

        if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
            exit(-1);
        }
        if (VmmState->Rax != 0) {
            return VmmState->Rax;
        }
    }

    return 0;
}

UINT64
SeamcallTdx_TdhMngInit(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm)
{
    const UINT64 ParamsGpa = 0x1000;
    td_params_t *ParamsHva;
    VCPU_STATE *VmmState;

    MapGpa(Vm, ParamsGpa, PAGE_SIZE);

    ParamsHva = (td_params_t *)GPA_TO_HVA(Vm, ParamsGpa);
    memset(ParamsHva, 0, PAGE_SIZE);

    ParamsHva->attributes.debug = 1;
    ParamsHva->xfam = TDX_XFAM_FIXED1 |
                      __BIT(11) | // CET User State
                      __BIT(12);  // CET Supervisor state
    ParamsHva->max_vcpus = TdVm->NumberOfVcpus;
    ParamsHva->eptp_controls.ept_ps_mt = 6;
    ParamsHva->eptp_controls.ept_pwl = 4 - 1;
    ParamsHva->tsc_frequency = VIRT_TSC_FREQUENCY_MIN;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_MNG_INIT_LEAF;
    VmmState->Rcx = TdVm->TdrPa;
    VmmState->Rdx = ParamsGpa;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    UnmapGpa(Vm, ParamsGpa, PAGE_SIZE);

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhVpCreate(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu)
{
    VCPU_STATE *VmmState;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_VP_CREATE_LEAF;
    VmmState->Rcx = TdVm->Vcpus[TdVcpu].TdvprPa;
    VmmState->Rdx = TdVm->TdrPa;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhVpAddcx(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu)
{
    VCPU_STATE *VmmState;
    SIZE_T i;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;

#define MAX_TDVPS_PAGES 15
    for (i = 0; i < MAX_TDVPS_PAGES - 1; i++) {
        VmmState->Rax = TDH_VP_ADDCX_LEAF;
        VmmState->Rcx = AllocatePaFromCmrsAvail(Vm); // TDCX PA
        VmmState->Rdx = TdVm->Vcpus[TdVcpu].TdvprPa;

        if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
            exit(-1);
        }
        if (VmmState->Rax != 0) {
            return VmmState->Rax;
        }
    }

    return 0;
}

UINT64
SeamcallTdx_TdhVpInit(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu)
{
    VCPU_STATE *VmmState;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_VP_INIT_LEAF;
    VmmState->Rcx = TdVm->Vcpus[TdVcpu].TdvprPa;
    VmmState->Rdx = 0;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhVpWr(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu, md_field_id_t Identifier, UINT64 Value, UINT64 Mask)
{
    VCPU_STATE *VmmState;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_VP_WR_LEAF;
    VmmState->Rcx = TdVm->Vcpus[TdVcpu].TdvprPa;
    VmmState->Rdx = Identifier.raw;
    VmmState->R8 = Value;
    VmmState->R9 = Mask;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhVpRd(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu, md_field_id_t Identifier, UINT64 *Value)
{
    VCPU_STATE *VmmState;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_VP_RD_LEAF;
    VmmState->Rcx = TdVm->Vcpus[TdVcpu].TdvprPa;
    VmmState->Rdx = Identifier.raw;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    *Value = VmmState->R8;

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhVpEnter(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu)
{
    VCPU_STATE *VmmState;
    vcpu_and_flags_t VcpuAndFlags;
    enum VcpuAction Action;

    VcpuAndFlags.raw = 0;
    VcpuAndFlags.tdvpra_hpa_51_12 = TdVm->Vcpus[TdVcpu].TdvprPa >> 12ULL;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_VP_ENTER_LEAF;
    VmmState->Rcx = VcpuAndFlags.raw;

    Action = RunVCPU(Vm, VcpuNum, VcpuModeTdxModule);

    if (Action == VcpuActionSeamRet) {
        return VmmState->Rax;
    } else if (Action == VcpuActionVmlaunch || Action == VcpuActionVmresume) {
        return 0;
    }

    // Unexpected
    exit(-1);
}

UINT64
SeamcallTdx_TdhMrFinalize(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm)
{
    VCPU_STATE *VmmState;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_MR_FINALIZE_LEAF;
    VmmState->Rcx = TdVm->TdrPa;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhMemSeptAdd(CORNELIUS_VM* Vm, UINT32 VcpuNum, TD_VM* TdVm, UINT64 Pa, UINT64 Gpa, UINT8 Level)
{
    VCPU_STATE* VmmState = GetVcpuState(Vm, VcpuNum);
    page_info_api_input_t PageInfo = { 0 };

    PageInfo.level = Level;
    PageInfo.gpa = Gpa >> 12;

    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_MEM_SEPT_ADD_LEAF;
    VmmState->Rcx = PageInfo.raw;
    VmmState->Rdx = TdVm->TdrPa;
    VmmState->R8 = Pa;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    return VmmState->Rax;
}

UINT64
SeamcallTdx_TdhMemPageAug(CORNELIUS_VM* Vm, UINT32 VcpuNum, TD_VM* TdVm, UINT64 Pa, UINT64 Gpa, UINT8 Level)
{
    VCPU_STATE* VmmState;
    page_info_api_input_t PageInfo = { 0 };

    PageInfo.level = Level;
    PageInfo.gpa = Gpa >> 12;

    VmmState = GetVcpuState(Vm, VcpuNum);
    VmmState->ExitReason = VMEXIT_REASON_SEAMCALL;
    VmmState->InstructionLength = 4;
    VmmState->Rax = TDH_MEM_PAGE_AUG_LEAF;
    VmmState->Rcx = PageInfo.raw;
    VmmState->Rdx = TdVm->TdrPa;
    VmmState->R8 = Pa;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdxModule) != VcpuActionSeamRet) {
        exit(-1);
    }

    return VmmState->Rax;
}

UINT64
Tdcall_TdgMemPageAccept(CORNELIUS_VM* Vm, UINT32 VcpuNum, UINT64 Gpa, UINT8 Level)
{
    VCPU_STATE* TdgState;
    page_info_api_input_t PageInfo = { 0 };

    PageInfo.level = Level;
    PageInfo.gpa = Gpa >> 12;

    TdgState = GetVcpuState(Vm, VcpuNum);
    TdgState->ExitReason = VMEXIT_REASON_TDCALL;
    TdgState->InstructionLength = 4;
    TdgState->Rax = TDG_MEM_PAGE_ACCEPT_LEAF;
    TdgState->Rcx = PageInfo.raw;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdGuest) != VcpuActionVmresume) {
        exit(-1);
    }

    return TdgState->Rax;
}

VOID
Tdcall_TdgVpVmcall(CORNELIUS_VM* Vm, UINT32 VcpuNum, UINT64 Control)
{
    VCPU_STATE* TdgState;

    TdgState = GetVcpuState(Vm, VcpuNum);
    TdgState->ExitReason = VMEXIT_REASON_TDCALL;
    TdgState->InstructionLength = 4;
    TdgState->Rax = TDG_VP_VMCALL_LEAF;
    TdgState->Rcx = Control;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdGuest) != VcpuActionSeamRet) {
        exit(-1);
    }
}
