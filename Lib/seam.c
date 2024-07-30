// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "common.h"

const UINT64 TdVmcsFields[NUM_TD_VMCS_FIELDS] = {
    VMX_GUEST_ES_SELECTOR_ENCODE,
    VMX_GUEST_ES_ARBYTE_ENCODE,
    VMX_GUEST_ES_LIMIT_ENCODE,
    VMX_GUEST_ES_BASE_ENCODE,
    VMX_GUEST_CS_SELECTOR_ENCODE,
    VMX_GUEST_CS_ARBYTE_ENCODE,
    VMX_GUEST_CS_LIMIT_ENCODE,
    VMX_GUEST_CS_BASE_ENCODE,
    VMX_GUEST_SS_SELECTOR_ENCODE,
    VMX_GUEST_SS_ARBYTE_ENCODE,
    VMX_GUEST_SS_LIMIT_ENCODE,
    VMX_GUEST_SS_BASE_ENCODE,
    VMX_GUEST_DS_SELECTOR_ENCODE,
    VMX_GUEST_DS_ARBYTE_ENCODE,
    VMX_GUEST_DS_LIMIT_ENCODE,
    VMX_GUEST_DS_BASE_ENCODE,
    VMX_GUEST_LDTR_SELECTOR_ENCODE,
    VMX_GUEST_LDTR_ARBYTE_ENCODE,
    VMX_GUEST_LDTR_LIMIT_ENCODE,
    VMX_GUEST_LDTR_BASE_ENCODE,
    VMX_GUEST_TR_SELECTOR_ENCODE,
    VMX_GUEST_TR_ARBYTE_ENCODE,
    VMX_GUEST_TR_LIMIT_ENCODE,
    VMX_GUEST_TR_BASE_ENCODE,
    VMX_GUEST_FS_SELECTOR_ENCODE,
    VMX_GUEST_FS_ARBYTE_ENCODE,
    VMX_GUEST_FS_LIMIT_ENCODE,
    VMX_GUEST_FS_BASE_ENCODE,
    VMX_GUEST_GS_SELECTOR_ENCODE,
    VMX_GUEST_GS_ARBYTE_ENCODE,
    VMX_GUEST_GS_LIMIT_ENCODE,
    VMX_GUEST_GS_BASE_ENCODE,
    VMX_NOTIFY_WINDOW_ENCODE,
    VMX_GUEST_GDTR_LIMIT_ENCODE,
    VMX_GUEST_GDTR_BASE_ENCODE,
    VMX_RSVD_32_BIT_GUEST_STATE_ENCODE,
    VMX_GUEST_IDTR_LIMIT_ENCODE,
    VMX_GUEST_IDTR_BASE_ENCODE,
    VMX_HOST_ES_SELECTOR_ENCODE,
    VMX_HOST_CS_SELECTOR_ENCODE,
    VMX_HOST_SS_SELECTOR_ENCODE,
    VMX_HOST_DS_SELECTOR_ENCODE,
    VMX_HOST_FS_SELECTOR_ENCODE,
    VMX_HOST_GS_SELECTOR_ENCODE,
    VMX_HOST_TR_SELECTOR_ENCODE,
    VMX_GUEST_VPID_ENCODE,
    VMX_OSV_CVP_FULL_ENCODE,
    VMX_VM_INSTRUCTION_ERRORCODE_ENCODE,
    VMX_PAUSE_LOOP_EXITING_GAP_ENCODE,
    VMX_PAUSE_LOOP_EXITING_WINDOW_ENCODE,
    VMX_GUEST_SAVED_WORKING_VMCS_POINTER_FULL_ENCODE,
    VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE,
    VMX_GUEST_IA32_PAT_FULL_ENCODE,
    VMX_GUEST_IA32_EFER_FULL_ENCODE,
    VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE,
    VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE,
    VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE,
    VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE,
    VMX_TPR_THRESHOLD_ENCODE,
    VMX_PAGEFAULT_ERRORCODE_MASK_ENCODE,
    VMX_PAGEFAULT_ERRORCODE_MATCH_ENCODE,
    VMX_GUEST_INTERRUPTIBILITY_ENCODE,
    VMX_GUEST_SLEEP_STATE_ENCODE,
    VMX_GUEST_EPT_POINTER_FULL_ENCODE,
    VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE,
    VMX_VM_ENTRY_INTR_INFO_ENCODE,
    VMX_VM_ENTRY_EXCEPTION_ERRORCODE_ENCODE,
    VMX_VM_ENTRY_INSTRUCTION_LENGTH_ENCODE,
    VMX_VM_EXIT_CONTROL_ENCODE,
    VMX_GUEST_PREEMPTION_TIMER_COUNT_ENCODE,
    VMX_VM_EXIT_MSR_STORE_COUNT_ENCODE,
    VMX_VM_EXIT_MSR_LOAD_COUNT_ENCODE,
    VMX_VM_EXIT_REASON_ENCODE,
    VMX_VM_EXIT_INTERRUPTION_INFO_ENCODE,
    VMX_VM_EXIT_EXCEPTION_ERRORCODE_ENCODE,
    VMX_VM_EXIT_IDT_VECTOR_FIELD_ENCODE,
    VMX_VM_EXIT_IDT_VECTOR_ERRORCODE_ENCODE,
    VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE,
    VMX_VM_EXIT_INSTRUCTION_INFO_ENCODE,
    VMX_TSC_OFFSET_FULL_ENCODE,
    VMX_VM_EXIT_QUALIFICATION_ENCODE,
    VMX_VM_EXIT_IO_RCX_ENCODE,
    VMX_VM_EXIT_IO_RSI_ENCODE,
    VMX_VM_EXIT_IO_RDI_ENCODE,
    VMX_VM_EXIT_IO_RIP_ENCODE,
    VMX_VM_EXIT_GUEST_LINEAR_ADDRESS_ENCODE,
    VMX_GUEST_DR7_ENCODE,
    VMX_GUEST_RSP_ENCODE,
    VMX_GUEST_RIP_ENCODE,
    VMX_GUEST_RFLAGS_ENCODE,
    VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE,
    VMX_GUEST_IA32_SYSENTER_ESP_ENCODE,
    VMX_GUEST_IA32_SYSENTER_EIP_ENCODE,
    VMX_GUEST_IA32_SYSENTER_CS_ENCODE,
    VMX_EPTP_INDEX_ENCODE,
    VMX_GUEST_CR0_ENCODE,
    VMX_GUEST_CR3_ENCODE,
    VMX_GUEST_CR4_ENCODE,
    VMX_GUEST_PDPTR0_FULL_ENCODE,
    VMX_GUEST_PDPTR1_FULL_ENCODE,
    VMX_GUEST_PDPTR2_FULL_ENCODE,
    VMX_GUEST_PDPTR3_FULL_ENCODE,
    VMX_CR0_GUEST_HOST_MASK_ENCODE,
    VMX_CR4_GUEST_HOST_MASK_ENCODE,
    VMX_CR0_READ_SHADOW_ENCODE,
    VMX_CR4_READ_SHADOW_ENCODE,
    VMX_CR3_TARGET_VALUE_0_ENCODE,
    VMX_CR3_TARGET_VALUE_1_ENCODE,
    VMX_CR3_TARGET_VALUE_2_ENCODE,
    VMX_CR3_TARGET_VALUE_3_ENCODE,
    VMX_EOI_EXIT_TABLE_0_FULL_ENCODE,
    VMX_EOI_EXIT_TABLE_1_FULL_ENCODE,
    VMX_EOI_EXIT_TABLE_2_FULL_ENCODE,
    VMX_EOI_EXIT_TABLE_3_FULL_ENCODE,
    VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE,
    VMX_GUEST_SMBASE_ENCODE,
    VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE,
    VMX_EXCEPTION_BITMAP_ENCODE,
    VMX_CR3_TARGET_COUNT_ENCODE,
    VMX_VM_ENTRY_CONTROL_ENCODE,
    VMX_VM_ENTRY_MSR_LOAD_COUNT_ENCODE,
    VMX_VIRTUAL_APIC_PAGE_ADDRESS_FULL_ENCODE,
    VMX_IO_BITMAP_A_PHYPTR_FULL_ENCODE,
    VMX_IO_BITMAP_B_PHYPTR_FULL_ENCODE,
    VMX_EXIT_MSR_STORE_PHYPTR_FULL_ENCODE,
    VMX_EXIT_MSR_LOAD_PHYPTR_FULL_ENCODE,
    VMX_ENTRY_MSR_LOAD_PHYPTR_FULL_ENCODE,
    VMX_VIRTUAL_APIC_ACCESS_PAGE_ADDRESS_FULL_ENCODE,
    VMX_MSR_BITMAP_PHYPTR_FULL_ENCODE,
    VMX_HOST_RSP_ENCODE,
    VMX_HOST_RIP_ENCODE,
    VMX_HOST_IA32_PAT_FULL_ENCODE,
    VMX_HOST_IA32_EFER_FULL_ENCODE,
    VMX_HOST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE,
    VMX_HOST_CR0_ENCODE,
    VMX_HOST_CR3_ENCODE,
    VMX_HOST_CR4_ENCODE,
    VMX_HOST_IDTR_BASE_ENCODE,
    VMX_HOST_GDTR_BASE_ENCODE,
    VMX_HOST_FS_BASE_ENCODE,
    VMX_HOST_GS_BASE_ENCODE,
    VMX_HOST_TR_BASE_ENCODE,
    VMX_HOST_IA32_SYSENTER_ESP_ENCODE,
    VMX_HOST_IA32_SYSENTER_EIP_ENCODE,
    VMX_HOST_IA32_SYSENTER_CS_ENCODE,
    VMX_GUEST_INTERRUPT_STATUS_ENCODE,
    VMX_GUEST_UINV_ENCODE,
    VMX_PML_INDEX_ENCODE,
    VMX_VM_FUNCTION_CONTROLS_FULL_ENCODE,
    VMX_EPTP_LIST_ADDRESS_FULL_ENCODE,
    VMX_VMREAD_BITMAP_ADDRESS_FULL_ENCODE,
    VMX_VMWRITE_BITMAP_ADDRESS_FULL_ENCODE,
    VMX_PML_LOG_ADDRESS_FULL_ENCODE,
    VMX_XSS_EXIT_CONTROL_FULL_ENCODE,
    VMX_ENCLS_EXIT_CONTROL_FULL_ENCODE,
    VMX_RSVD_64_BIT_VMEXIT_DATA_FULL_ENCODE,
    VMX_ENCLV_EXIT_CONTROL_FULL_ENCODE,
    VMX_VIRTUAL_EXCEPTION_INFO_ADDRESS_FULL_ENCODE,
    VMX_GUEST_BNDCFGS_FULL_ENCODE,
    VMX_SPPTP_FULL_ENCODE,
    VMX_TSC_MULTIPLIER_FULL_ENCODE,
    VMX_GUEST_RTIT_CTL_FULL_ENCODE,
    VMX_VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_FULL_ENCODE,
    VMX_PCONFIG_EXITING_FULL_ENCODE,
    VMX_PASID_LOW_FULL_ENCODE,
    VMX_PASID_HIGH_FULL_ENCODE,
    VMX_HOST_IA32_INTERRUPT_SSP_TABLE_ADDR_ENCODE,
    VMX_GUEST_IA32_S_CET_ENCODE,
    VMX_GUEST_SSP_ENCODE,
    VMX_GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR_ENCODE,
    VMX_HOST_IA32_S_CET_ENCODE,
    VMX_HOST_SSP_ENCODE,
    VMX_HKID_ENCODE,
    VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE,
    VMX_NO_COMMIT_THRESHOLD_ENCODE,
    VMX_GUEST_LBR_CTL_FULL_ENCODE,
    VMX_GUEST_PKRS_FULL_ENCODE,
    VMX_HLATP_FULL_ENCODE,
    VMX_IA32_SPEC_CTRL_MASK,
    VMX_IA32_SPEC_CTRL_SHADOW
};

VOID
InitializeSeamRr(CORNELIUS_VM *Vm)
{
    PUINT8 ElfAddr;
    SIZE_T PSeamldrSize;
    UINT64 CodeRgnPa;
    UINT64 CodeRgnVa;
    SIZE_T CodeRgnSize;
    UINT64 StackRgnPa;
    UINT64 StackRgnVa;
    SIZE_T StackRgnSize;

    UINT64 KeyholeRgnVa;
    UINT64 KeyholeEditRgnVa;
    SIZE_T KeyholeRgnSize;
    UINT64 PrevPdePage;
    UINT64 PdePage;
    SIZE_T i;
    UINT64 CurrentKeyholeEditRgnVa;

    UINT64 DataRgnPa;
    UINT64 DataRgnVa;
    SIZE_T DataRgnSize;
    UINT64 CSysInfoTablePa;
    UINT64 CSysInfoTableVa;
    UINT64 ModuleRgnPa;
    UINT64 ModuleRgnVa;

    //
    // Initialize the SEAM physical range: perform all the operations done by the
    // NP-SEAMLDR in SeamldrAcm() to set up the environment for the P-SEAMLDR.
    //

    // PseamldrBase + 1 * _4KB == VMCS
    // PseamldrBase + 2 * _4KB == L4 page
    // PseamldrBase + 3+ * _4KB == Page tables
    // DATA
    // STACK+SHADOW (shadow is on the right side)
    // CODE
    // PSysInfoTable

    // Initialize PSysInfoTable.
    if (Vm->VmConfig.PSeamldrRange.Size < sizeof(P_SYS_INFO_TABLE_t)) {
        FATAL("P-SEAMLDR range too small to contain PSysInfoTable");
    }
    Vm->PSysInfoTable = (P_SYS_INFO_TABLE_t*)(Vm->SeamrrVa + Vm->VmConfig.SeamrrSize - sizeof(P_SYS_INFO_TABLE_t));
    Vm->PSysInfoTable->Version = P_SYS_INFO_TABLE_VERSION;
    Vm->PSysInfoTable->TotNumLps = Vm->NumberOfVcpus;
    Vm->PSysInfoTable->TotNumSockets = 1;
    Vm->PSysInfoTable->PSeamldrRange.Base = Vm->VmConfig.PSeamldrRange.Base;
    Vm->PSysInfoTable->PSeamldrRange.Size = Vm->VmConfig.PSeamldrRange.Size;
    memcpy(Vm->PSysInfoTable->Cmr,
           Vm->VmConfig.Cmrs,
           Vm->VmConfig.NumberOfCmrs * sizeof(Vm->VmConfig.Cmrs[0]));

    // Sanitize the ELF size.
    if (Vm->VmConfig.PSeamldrElfSize % PAGE_SIZE != 0) {
        FATAL("ELF file not aligned to PAGE_SIZE");
    }

    PSeamldrSize =
        PAGE_SIZE + // VMCS
        Vm->VmConfig.DataRegionSize + // DataRgn
        Vm->VmConfig.StackRegionSize + // StackRgn
        Vm->VmConfig.PSeamldrElfSize + // CodeRgn
        sizeof(P_SYS_INFO_TABLE_t); // PSysInfoTable

    if (PSeamldrSize > Vm->VmConfig.PSeamldrRange.Size) {
        FATAL("the P-SEAMLDR range is too small to contain everything");
    }

    // Copy the ELF file into the P-SEAMLDR range.
    ElfAddr = Vm->SeamrrVa + Vm->VmConfig.SeamrrSize - sizeof(P_SYS_INFO_TABLE_t) - Vm->VmConfig.PSeamldrElfSize;
    memcpy(ElfAddr, Vm->VmConfig.PSeamldrElfBytes, Vm->VmConfig.PSeamldrElfSize);

    // Initialize the allocator range.
    Vm->AllocatorPa = Vm->VmConfig.PSeamldrRange.Base + PAGE_SIZE;
    Vm->AllocatorPaEnd = Vm->AllocatorPa + (Vm->VmConfig.PSeamldrRange.Size - (PSeamldrSize - PAGE_SIZE));

    // Map the CodeRgn.
    CodeRgnVa = C_CODE_RGN_BASE;
    CodeRgnPa = Vm->VmConfig.SeamrrBase + Vm->VmConfig.SeamrrSize - sizeof(P_SYS_INFO_TABLE_t) - Vm->VmConfig.PSeamldrElfSize;
    CodeRgnSize = Vm->VmConfig.PSeamldrElfSize;
    if (!MapRange(Vm, CodeRgnVa, CodeRgnPa, CodeRgnSize, MapTypeCode)) {
        FATAL("failed to map the CodeRgn");
    }

    // Relocate the ELF file at the CodeRgn.
    if (!RelocateElf(ElfAddr, Vm->VmConfig.PSeamldrElfSize, CodeRgnVa)) {
        FATAL("RelocateElf failed");
    }

    // Map the StackRgn.
    StackRgnVa = C_STACK_RGN_BASE;
    StackRgnPa = CodeRgnPa - Vm->VmConfig.StackRegionSize;
    StackRgnSize = Vm->VmConfig.StackRegionSize;
    if (!MapRange(Vm, StackRgnVa, StackRgnPa, StackRgnSize - PAGE_SIZE, MapTypeData)) {
        FATAL("failed to map the StackRgn");
    }
    if (!MapRange(Vm, StackRgnVa + StackRgnSize - PAGE_SIZE, StackRgnPa + StackRgnSize - PAGE_SIZE, PAGE_SIZE, MapTypeShadowStack)) {
        FATAL("failed to map the StackRgn");
    }

    // Map the KeyholeRgn and KeyholeEditRgn.
    KeyholeRgnVa = C_KEYHOLE_RGN_BASE;
    KeyholeEditRgnVa = C_KEYHOLE_EDIT_REGION_BASE;
    KeyholeRgnSize = Vm->VmConfig.KeyholeRegionSize;
    PrevPdePage = (UINT64) - 1;
    CurrentKeyholeEditRgnVa = KeyholeEditRgnVa;
    for (i = 0; i < KeyholeRgnSize; i += PAGE_SIZE) {
        if (!MapPage(Vm, KeyholeRgnVa + i, 0, MapTypeKeyHole, &PdePage)) {
            FATAL("KeyholeRgn map failed");
        }
        if (PdePage != PrevPdePage) {
            if (!MapPage(Vm, CurrentKeyholeEditRgnVa, PdePage, MapTypeDataUser, NULL)) {
                FATAL("KeyholeEditRgn map failed");
            }
            PrevPdePage = PdePage;
            CurrentKeyholeEditRgnVa += PAGE_SIZE;
        }
    }

    // Map the DataRgn.
    DataRgnVa = C_DATA_RGN_BASE;
    DataRgnPa = StackRgnPa - Vm->VmConfig.DataRegionSize;
    DataRgnSize = Vm->VmConfig.DataRegionSize;
    if (!MapRange(Vm, DataRgnVa, DataRgnPa, DataRgnSize, MapTypeData)) {
        FATAL("failed to map the DataRgn");
    }

    // Map the CSysInfoTable.
    CSysInfoTableVa = C_SYS_INFO_TABLE_BASE;
    CSysInfoTablePa = Vm->VmConfig.SeamrrBase + Vm->VmConfig.SeamrrSize - sizeof(P_SYS_INFO_TABLE_t);
    if (!MapRange(Vm, CSysInfoTableVa, CSysInfoTablePa, PAGE_SIZE, MapTypeData)) {
        FATAL("failed to map the DataRgn");
    }

    // Map the ModuleRgn.
    // XXX: should be 2MB *large pages*, not normal pages
    ModuleRgnVa = C_MODULE_RGN_BASE;
    ModuleRgnPa = Vm->VmConfig.SeamrrBase;
    if (!MapRange(Vm, ModuleRgnVa, ModuleRgnPa, Vm->VmConfig.SeamrrSize, MapTypeData)) {
        FATAL("failed to map the DataRgn");
    }

    // SetupSysInfoTable().
    Vm->PSysInfoTable->CodeRgn.Base = CodeRgnVa;
    Vm->PSysInfoTable->CodeRgn.Size = CodeRgnSize;
    Vm->PSysInfoTable->DataRgn.Base = DataRgnVa;
    Vm->PSysInfoTable->DataRgn.Size = DataRgnSize;
    Vm->PSysInfoTable->StackRgn.Base = StackRgnVa;
    Vm->PSysInfoTable->StackRgn.Size = StackRgnSize;
    Vm->PSysInfoTable->KeyholeRgn.Base = KeyholeRgnVa;
    Vm->PSysInfoTable->KeyholeRgn.Size = KeyholeRgnSize;
    Vm->PSysInfoTable->KeyholeEditRgn.Base = KeyholeEditRgnVa;
    Vm->PSysInfoTable->KeyholeEditRgn.Size = Vm->VmConfig.KeyholeEditRegionSize;
    Vm->PSysInfoTable->ModuleRgnBase = ModuleRgnVa;

    // XXX: we never bothered with that, should we?
    // Vm->PSysInfoTable->AcmX2ApicId = GetX2ApicId();
    // Vm->PSysInfoTable->AcmX2ApicIdValid = SYS_INFO_TABLE_X2APICID_VALID;

    // Remember for later
    Vm->CSysInfoTableVa = CSysInfoTableVa;
    Vm->BootRip = Vm->PSysInfoTable->CodeRgn.Base + Vm->VmConfig.EntryPointOffset;
    Vm->BootRsp = Vm->PSysInfoTable->StackRgn.Base + Vm->PSysInfoTable->StackRgn.Size - PAGE_SIZE;
    Vm->BootSsp = Vm->BootRsp + PAGE_SIZE;
    Vm->VmcsHva = (PUINT8)Vm->SeamrrVa + _4KB;

    if (Vm->VmConfig.HasSanitizers) {
        InitializeAsan(Vm);
        InitializeSancov(Vm);
    }
}

static VOID
InitializeSegment(WHV_REGISTER_VALUE *RegisterValue, UINT64 Base, UINT32 Limit, UINT8 Selector, UINT8 SegmentType, BOOLEAN NonSystemSegment)
{
    RegisterValue->Segment.Base = Base;
    RegisterValue->Segment.Limit = Limit;
    RegisterValue->Segment.Selector = Selector; 
    RegisterValue->Segment.SegmentType = SegmentType;
    RegisterValue->Segment.NonSystemSegment = NonSystemSegment;
    RegisterValue->Segment.DescriptorPrivilegeLevel = 0;
    RegisterValue->Segment.Present = 1;
    RegisterValue->Segment.Reserved = 0;
    RegisterValue->Segment.Available = 1;
    RegisterValue->Segment.Long = 1;
    RegisterValue->Segment.Default = 0;
    RegisterValue->Segment.Granularity = 1;
}

VOID
InitializeSeamldrState(CORNELIUS_VM *Vm)
{
    memset(Vm->SeamldrState.RegisterValues, 0, sizeof(Vm->SeamldrState.RegisterValues));

    //
    // CR0.
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_CR0] = WHvX64RegisterCr0;
    Vm->SeamldrState.RegisterValues[SEAM_STATE_CR0].Reg64 = CR0_PE | CR0_ET | CR0_NE | CR0_WP | CR0_PG;

    //
    // CR3.
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_CR3] = WHvX64RegisterCr3;
    Vm->SeamldrState.RegisterValues[SEAM_STATE_CR3].Reg64 = Vm->BootCr3;

    //
    // CR4.
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_CR4] = WHvX64RegisterCr4;
    Vm->SeamldrState.RegisterValues[SEAM_STATE_CR4].Reg64 = CR4_DE | CR4_PAE | CR4_PGE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_FSGSBASE | CR4_OSXSAVE | CR4_SMEP | CR4_SMAP | CR4_CET;

    //
    // ES: 3 = Memory Read Write Accessed
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_ES] = WHvX64RegisterEs;
    InitializeSegment(&Vm->SeamldrState.RegisterValues[SEAM_STATE_ES], 0, 0xFFFFFFFF, 0, 3, TRUE);

    //
    // CS: 11 = Memory Execute Read Accessed
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_CS] = WHvX64RegisterCs;
    InitializeSegment(&Vm->SeamldrState.RegisterValues[SEAM_STATE_CS], 0, 0xFFFFFFFF, 0x8U, 11, TRUE);

    //
    // SS: 3 = Memory Read Write Accessed
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_SS] = WHvX64RegisterSs;
    InitializeSegment(&Vm->SeamldrState.RegisterValues[SEAM_STATE_SS], 0, 0xFFFFFFFF, 0x10U, 3, TRUE);

    //
    // ES: 3 = Memory Read Write Accessed
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_DS] = WHvX64RegisterDs;
    InitializeSegment(&Vm->SeamldrState.RegisterValues[SEAM_STATE_DS], 0, 0xFFFFFFFF, 0, 3, TRUE);

    //
    // FS: 3 = Memory Read Write Accessed
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_FS] = WHvX64RegisterFs;
    InitializeSegment(&Vm->SeamldrState.RegisterValues[SEAM_STATE_FS], Vm->CSysInfoTableVa, 0xFFFFFFFF, 0x18U, 3, TRUE);

    //
    // GS: 3 = Memory Read Write Accessed
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_GS] = WHvX64RegisterGs;
    InitializeSegment(&Vm->SeamldrState.RegisterValues[SEAM_STATE_GS], Vm->PSysInfoTable->DataRgn.Base, 0xFFFFFFFF, 0x18U, 3, TRUE);

    //
    // TR
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_TR] = WHvX64RegisterTr;
    InitializeSegment(&Vm->SeamldrState.RegisterValues[SEAM_STATE_TR], 0, 0xFFFFFFFF, 0x20U, 11, FALSE);

    //
    // IDTR
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_IDTR] = WHvX64RegisterIdtr;

    //
    // GDTR
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_GDTR] = WHvX64RegisterGdtr;

    //
    // MSRs: PAT, SCET, EFER
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_PAT] = WHvX64RegisterPat;
    Vm->SeamldrState.RegisterValues[SEAM_STATE_PAT].Reg64 = 0x0006060606060606ULL; 

    Vm->SeamldrState.RegisterNames[SEAM_STATE_SCET] = WHvX64RegisterSCet;
    Vm->SeamldrState.RegisterValues[SEAM_STATE_SCET].Reg64 = IA32_CR_S_CET_SH_STK_EN_MASK | IA32_CR_S_CET_ENDBR_EN_MASK | IA32_CR_S_CET_NO_TRACK_EN_MASK; 

    Vm->SeamldrState.RegisterNames[SEAM_STATE_EFER] = WHvX64RegisterEfer;
    Vm->SeamldrState.RegisterValues[SEAM_STATE_EFER].Reg64 = EFER_LME | EFER_LMA | EFER_NXE;

    //
    // GPRs: RIP, RSP, SSP, RFLAGS
    //

    Vm->SeamldrState.RegisterNames[SEAM_STATE_RIP] = WHvX64RegisterRip;
    Vm->SeamldrState.RegisterValues[SEAM_STATE_RIP].Reg64 = Vm->BootRip;

    Vm->SeamldrState.RegisterNames[SEAM_STATE_RSP] = WHvX64RegisterRsp;
    Vm->SeamldrState.RegisterValues[SEAM_STATE_RSP].Reg64 = Vm->BootRsp;

    Vm->SeamldrState.RegisterNames[SEAM_STATE_SSP] = WHvX64RegisterSsp;
    Vm->SeamldrState.RegisterValues[SEAM_STATE_SSP].Reg64 = Vm->BootSsp;

    Vm->SeamldrState.RegisterNames[SEAM_STATE_RFLAGS] = WHvX64RegisterRflags;
    Vm->SeamldrState.RegisterValues[SEAM_STATE_RFLAGS].Reg64 = 0x00000202;
}

VOID
InstallSeamldrState(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    HRESULT hRes;

    hRes = WHvSetVirtualProcessorRegisters(Vm->Partition,
        VcpuNum,
        Vm->SeamldrState.RegisterNames,
        NUM_SEAM_REGS,
        Vm->SeamldrState.RegisterValues);
    FAIL_IF_ERROR(hRes);
}

VOID
InitializeVcpuState(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    GetVcpuState(Vm, VcpuNum)->Xcr0 = 0b11;
}

VOID
InitializeTdxState(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    SEAM_STATE *TdxState;

    TdxState = GetTdxState(Vm, VcpuNum);

    memset(TdxState->RegisterValues, 0, sizeof(TdxState->RegisterValues));

    TdxState->RegisterNames[SEAM_STATE_CR0] = WHvX64RegisterCr0;
    TdxState->RegisterNames[SEAM_STATE_CR3] = WHvX64RegisterCr3;
    TdxState->RegisterNames[SEAM_STATE_CR4] = WHvX64RegisterCr4;
    TdxState->RegisterNames[SEAM_STATE_ES] = WHvX64RegisterEs;
    TdxState->RegisterNames[SEAM_STATE_CS] = WHvX64RegisterCs;
    TdxState->RegisterNames[SEAM_STATE_SS] = WHvX64RegisterSs;
    TdxState->RegisterNames[SEAM_STATE_DS] = WHvX64RegisterDs;
    TdxState->RegisterNames[SEAM_STATE_FS] = WHvX64RegisterFs;
    TdxState->RegisterNames[SEAM_STATE_GS] = WHvX64RegisterGs;
    TdxState->RegisterNames[SEAM_STATE_TR] = WHvX64RegisterTr;
    TdxState->RegisterNames[SEAM_STATE_IDTR] = WHvX64RegisterIdtr;
    TdxState->RegisterNames[SEAM_STATE_GDTR] = WHvX64RegisterGdtr;
    TdxState->RegisterNames[SEAM_STATE_PAT] = WHvX64RegisterPat;
    TdxState->RegisterNames[SEAM_STATE_SCET] = WHvX64RegisterSCet;
    TdxState->RegisterNames[SEAM_STATE_EFER] = WHvX64RegisterEfer;
    TdxState->RegisterNames[SEAM_STATE_RIP] = WHvX64RegisterRip;
    TdxState->RegisterNames[SEAM_STATE_RSP] = WHvX64RegisterRsp;
    TdxState->RegisterNames[SEAM_STATE_SSP] = WHvX64RegisterSsp;
    TdxState->RegisterNames[SEAM_STATE_RFLAGS] = WHvX64RegisterRflags;

    //
    // Initialize the segments to default values, as several of their fields do not
    // have corresponding VMCS encoding.
    //

    // ES: 3 = Memory Read Write Accessed
    InitializeSegment(&TdxState->RegisterValues[SEAM_STATE_ES], 0, 0xFFFFFFFF, 0, 3, TRUE);

    // CS: 11 = Memory Execute Read Accessed
    InitializeSegment(&TdxState->RegisterValues[SEAM_STATE_CS], 0, 0xFFFFFFFF, 0x8U, 11, TRUE);

    // SS: 3 = Memory Read Write Accessed
    InitializeSegment(&TdxState->RegisterValues[SEAM_STATE_SS], 0, 0xFFFFFFFF, 0x10U, 3, TRUE);

    // DS: 3 = Memory Read Write Accessed
    InitializeSegment(&TdxState->RegisterValues[SEAM_STATE_DS], 0, 0xFFFFFFFF, 0, 3, TRUE);

    // FS: 3 = Memory Read Write Accessed
    InitializeSegment(&TdxState->RegisterValues[SEAM_STATE_FS], 0, 0xFFFFFFFF, 0x18U, 3, TRUE);

    // GS: 3 = Memory Read Write Accessed
    InitializeSegment(&TdxState->RegisterValues[SEAM_STATE_GS], 0, 0xFFFFFFFF, 0x18U, 3, TRUE);

    // TR
    InitializeSegment(&TdxState->RegisterValues[SEAM_STATE_TR], 0, 0xFFFFFFFF, 0x20U, 11, FALSE);

    // IDTR
    TdxState->RegisterValues[SEAM_STATE_IDTR].Table.Limit = 0xFFFF;

    // GDTR
    TdxState->RegisterValues[SEAM_STATE_GDTR].Table.Limit = 0xFFFF;

    //
    // RFLAGS needs to have the MBO and Interrupt bits set.
    //

    TdxState->RegisterValues[SEAM_STATE_RFLAGS].Reg64 = 0x00000202;
}

VOID
InstallTdxState(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    WHV_REGISTER_VALUE RegisterValues[NUM_SEAM_REGS];
    VCPU_STATE *VcpuState = GetVcpuState(Vm, VcpuNum);
    enum VmcsType VmcsType;
    HRESULT hRes;

    //
    // The TDX state to install will differ depending on whether the current VMCS
    // is a TD guest VMCS.
    //

    VmcsType = GetCurrentVmcsType(Vm, VcpuNum);

    if (VmcsType == VmcsTypeTdGuest) {
        memcpy(RegisterValues,
               GetTdxState(Vm, VcpuNum)->RegisterValues,
               sizeof(RegisterValues));

        //
        // Here, we should install all the VMX_HOST_* fields into the VCPU. However,
        // as part of InvariantsOnVMLAUNCH() we already ensure that most of these
        // fields aren't changed by the VMCS, so we only need to install the registers
        // that *are* changed.
        //

        TdVmcsRead64(Vm, VcpuNum, VMX_HOST_RIP_ENCODE, &RegisterValues[SEAM_STATE_RIP].Reg64);

        hRes = WHvSetVirtualProcessorRegisters(Vm->Partition,
            VcpuNum,
            GetTdxState(Vm, VcpuNum)->RegisterNames,
            NUM_SEAM_REGS,
            RegisterValues);
        FAIL_IF_ERROR(hRes);

        //
        // Write the VRs to the TD VMCS.
        //

        TdVmcsWrite64(Vm, VcpuNum, VMX_VM_EXIT_REASON_ENCODE, VcpuState->ExitReason);
        TdVmcsWrite64(Vm, VcpuNum, VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE, VcpuState->InstructionLength);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_INTERRUPTIBILITY_ENCODE, VcpuState->GuestInterruptibility);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE, VcpuState->PendingDebugException);

        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_CR0_ENCODE, VcpuState->Cr0);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_CR3_ENCODE, VcpuState->Cr3);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_CR4_ENCODE, VcpuState->Cr4);

        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, VcpuState->DebugCtlMsr);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_IA32_PAT_FULL_ENCODE, VcpuState->Pat);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_IA32_EFER_FULL_ENCODE, VcpuState->Efer);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE, VcpuState->PerfGlobalCtrl);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_IA32_SYSENTER_ESP_ENCODE, VcpuState->SysenterEsp);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_IA32_SYSENTER_EIP_ENCODE, VcpuState->SysenterEip);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_IA32_SYSENTER_CS_ENCODE, VcpuState->SysenterCs);

        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_RSP_ENCODE, VcpuState->Rsp);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_RIP_ENCODE, VcpuState->Rip);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_RFLAGS_ENCODE, VcpuState->Rflags);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_SSP_ENCODE, VcpuState->Ssp);
        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_DR7_ENCODE, VcpuState->Dr7);

        TdVmcsWrite64(Vm, VcpuNum, VMX_GUEST_CS_ARBYTE_ENCODE, VcpuState->Cs.Attributes);
    } else if (VmcsType == VmcsTypeTdxModule) {
        hRes = WHvSetVirtualProcessorRegisters(Vm->Partition,
            VcpuNum,
            GetTdxState(Vm, VcpuNum)->RegisterNames,
            NUM_SEAM_REGS,
            GetTdxState(Vm, VcpuNum)->RegisterValues);
        FAIL_IF_ERROR(hRes);
    } else {
        FATAL("Wrong VMCS type in InstallTdxState");
    }
}

VOID
PseamldrTransferVmcsSet64(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 Offset, UINT64 Value)
{
    PUINT8 VmcsHva;

    VmcsHva = Vm->VmcsHva + VcpuNum * _4KB;

    *((PUINT64)(VmcsHva + Offset)) = Value;
}

static UINT64
TransferVmcsGet64(PUINT8 VmcsHva, UINT64 Offset)
{
    return *((PUINT64)(VmcsHva + Offset));
}

static UINT16
TransferVmcsGet16(PUINT8 VmcsHva, UINT64 Offset)
{
    return *((PUINT16)(VmcsHva + Offset));
}

VOID
SyncTdxStateWithVmcs(CORNELIUS_VM *Vm)
{
    PUINT8 VmcsHva;
    SEAM_STATE *TdxState;
    BOOLEAN StateChanged;
    UINT32 i;

    //
    // When the P-SEAMLDR executes, it may modify the transfer VMCS of the TDX module.
    // Synchronize the TDX state here.
    //

    for (i = 0; i < Vm->NumberOfVcpus; i++) {
        VmcsHva = Vm->VmcsHva + i * _4KB;
        StateChanged = FALSE;

        TdxState = GetTdxState(Vm, i);

        if (TdxState->RegisterValues[SEAM_STATE_CR0].Reg64 != TransferVmcsGet64(VmcsHva, VMX_HOST_CR0_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_CR0].Reg64 = TransferVmcsGet64(VmcsHva, VMX_HOST_CR0_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_CR3].Reg64 != TransferVmcsGet64(VmcsHva, VMX_HOST_CR3_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_CR3].Reg64 = TransferVmcsGet64(VmcsHva, VMX_HOST_CR3_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_CR4].Reg64 != (TransferVmcsGet64(VmcsHva, VMX_HOST_CR4_OFFSET) & ~CR4_VMXE)) {
            TdxState->RegisterValues[SEAM_STATE_CR4].Reg64 = (TransferVmcsGet64(VmcsHva, VMX_HOST_CR4_OFFSET) & ~CR4_VMXE);
            StateChanged = TRUE;
        }

        //
        // No ES.
        //

        if (TdxState->RegisterValues[SEAM_STATE_CS].Segment.Selector != TransferVmcsGet16(VmcsHva, VMX_HOST_CS_SELECTOR_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_CS].Segment.Selector = TransferVmcsGet16(VmcsHva, VMX_HOST_CS_SELECTOR_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_SS].Segment.Selector != TransferVmcsGet16(VmcsHva, VMX_HOST_SS_SELECTOR_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_SS].Segment.Selector = TransferVmcsGet16(VmcsHva, VMX_HOST_SS_SELECTOR_OFFSET);
            StateChanged = TRUE;
        }

        //
        // No DS.
        //

        if (TdxState->RegisterValues[SEAM_STATE_FS].Segment.Selector != TransferVmcsGet16(VmcsHva, VMX_HOST_FS_SELECTOR_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_FS].Segment.Selector = TransferVmcsGet16(VmcsHva, VMX_HOST_FS_SELECTOR_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_FS].Segment.Base != TransferVmcsGet64(VmcsHva, VMX_HOST_FS_BASE_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_FS].Segment.Base = TransferVmcsGet64(VmcsHva, VMX_HOST_FS_BASE_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_GS].Segment.Selector != TransferVmcsGet16(VmcsHva, VMX_HOST_GS_SELECTOR_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_GS].Segment.Selector = TransferVmcsGet16(VmcsHva, VMX_HOST_GS_SELECTOR_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_GS].Segment.Base != TransferVmcsGet64(VmcsHva, VMX_HOST_GS_BASE_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_GS].Segment.Base = TransferVmcsGet64(VmcsHva, VMX_HOST_GS_BASE_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_TR].Segment.Selector != TransferVmcsGet16(VmcsHva, VMX_HOST_TR_SELECTOR_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_TR].Segment.Selector = TransferVmcsGet16(VmcsHva, VMX_HOST_TR_SELECTOR_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_IDTR].Table.Base != TransferVmcsGet64(VmcsHva, VMX_HOST_IDTR_BASE_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_IDTR].Table.Base = TransferVmcsGet64(VmcsHva, VMX_HOST_IDTR_BASE_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_GDTR].Table.Base != TransferVmcsGet64(VmcsHva, VMX_HOST_GDTR_BASE_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_GDTR].Table.Base = TransferVmcsGet64(VmcsHva, VMX_HOST_GDTR_BASE_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_PAT].Reg64 != TransferVmcsGet64(VmcsHva, VMX_HOST_IA32_PAT_FULL_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_PAT].Reg64 = TransferVmcsGet64(VmcsHva, VMX_HOST_IA32_PAT_FULL_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_SCET].Reg64 != TransferVmcsGet64(VmcsHva, VMX_HOST_IA32_S_CET_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_SCET].Reg64 = TransferVmcsGet64(VmcsHva, VMX_HOST_IA32_S_CET_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_EFER].Reg64 != TransferVmcsGet64(VmcsHva, VMX_HOST_IA32_EFER_FULL_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_EFER].Reg64 = TransferVmcsGet64(VmcsHva, VMX_HOST_IA32_EFER_FULL_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_RIP].Reg64 != TransferVmcsGet64(VmcsHva, VMX_HOST_RIP_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_RIP].Reg64 = TransferVmcsGet64(VmcsHva, VMX_HOST_RIP_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_RSP].Reg64 != TransferVmcsGet64(VmcsHva, VMX_HOST_RSP_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_RSP].Reg64 = TransferVmcsGet64(VmcsHva, VMX_HOST_RSP_OFFSET);
            StateChanged = TRUE;
        }

        if (TdxState->RegisterValues[SEAM_STATE_SSP].Reg64 != TransferVmcsGet64(VmcsHva, VMX_HOST_SSP_OFFSET)) {
            TdxState->RegisterValues[SEAM_STATE_SSP].Reg64 = TransferVmcsGet64(VmcsHva, VMX_HOST_SSP_OFFSET);
            StateChanged = TRUE;
        }

        if (StateChanged) {
            LogVcpuOk(Vm, 0, "TDX state changed by transfer VMCS on VCPU%u\n", i);
        }
    }
}

#define NUM_VCPU_REGS   38
static const WHV_REGISTER_NAME VcpuRegisterNames[NUM_VCPU_REGS] = {
    WHvX64RegisterRax,
    WHvX64RegisterRcx,
    WHvX64RegisterRdx,
    WHvX64RegisterRbx,
    WHvX64RegisterRbp,
    WHvX64RegisterRsi,
    WHvX64RegisterRdi,
    WHvX64RegisterR8,
    WHvX64RegisterR9,
    WHvX64RegisterR10,
    WHvX64RegisterR11,
    WHvX64RegisterR12,
    WHvX64RegisterR13,
    WHvX64RegisterR14,
    WHvX64RegisterR15,
    WHvX64RegisterXmm0,
    WHvX64RegisterXmm1,
    WHvX64RegisterXmm2,
    WHvX64RegisterXmm3,
    WHvX64RegisterXmm4,
    WHvX64RegisterXmm5,
    WHvX64RegisterXmm6,
    WHvX64RegisterXmm7,
    WHvX64RegisterXmm8,
    WHvX64RegisterXmm9,
    WHvX64RegisterXmm10,
    WHvX64RegisterXmm11,
    WHvX64RegisterXmm12,
    WHvX64RegisterXmm13,
    WHvX64RegisterXmm14,
    WHvX64RegisterXmm15,
    WHvX64RegisterXCr0,
    WHvX64RegisterKernelGsBase,
    WHvX64RegisterPl0Ssp,
    WHvX64RegisterPl1Ssp,
    WHvX64RegisterPl2Ssp,
    WHvX64RegisterPl3Ssp,
    WHvX64RegisterXss
};

VOID
SyncVcpuStateWithContext(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    WHV_REGISTER_VALUE RegisterValues[NUM_VCPU_REGS];
    HRESULT hRes;

    memset(RegisterValues, 0, sizeof(RegisterValues));

    hRes = WHvGetVirtualProcessorRegisters(Vm->Partition, VcpuNum,
        VcpuRegisterNames, NUM_VCPU_REGS, RegisterValues);
    FAIL_IF_ERROR(hRes);

    GetVcpuState(Vm, VcpuNum)->Rax = RegisterValues[0].Reg64;
    GetVcpuState(Vm, VcpuNum)->Rcx = RegisterValues[1].Reg64;
    GetVcpuState(Vm, VcpuNum)->Rdx = RegisterValues[2].Reg64;
    GetVcpuState(Vm, VcpuNum)->Rbx = RegisterValues[3].Reg64;
    GetVcpuState(Vm, VcpuNum)->Rbp = RegisterValues[4].Reg64;
    GetVcpuState(Vm, VcpuNum)->Rsi = RegisterValues[5].Reg64;
    GetVcpuState(Vm, VcpuNum)->Rdi = RegisterValues[6].Reg64;
    GetVcpuState(Vm, VcpuNum)->R8 = RegisterValues[7].Reg64;
    GetVcpuState(Vm, VcpuNum)->R9 = RegisterValues[8].Reg64;
    GetVcpuState(Vm, VcpuNum)->R10 = RegisterValues[9].Reg64;
    GetVcpuState(Vm, VcpuNum)->R11 = RegisterValues[10].Reg64;
    GetVcpuState(Vm, VcpuNum)->R12 = RegisterValues[11].Reg64;
    GetVcpuState(Vm, VcpuNum)->R13 = RegisterValues[12].Reg64;
    GetVcpuState(Vm, VcpuNum)->R14 = RegisterValues[13].Reg64;
    GetVcpuState(Vm, VcpuNum)->R15 = RegisterValues[14].Reg64;
    GetVcpuState(Vm, VcpuNum)->Xmm0 = RegisterValues[15].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm1 = RegisterValues[16].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm2 = RegisterValues[17].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm3 = RegisterValues[18].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm4 = RegisterValues[19].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm5 = RegisterValues[20].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm6 = RegisterValues[21].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm7 = RegisterValues[22].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm8 = RegisterValues[23].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm9 = RegisterValues[24].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm10 = RegisterValues[25].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm11 = RegisterValues[26].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm12 = RegisterValues[27].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm13 = RegisterValues[28].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm14 = RegisterValues[29].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xmm15 = RegisterValues[30].Reg128;
    GetVcpuState(Vm, VcpuNum)->Xcr0 = RegisterValues[31].Reg64;
    GetVcpuState(Vm, VcpuNum)->Pl0Ssp = RegisterValues[33].Reg64;
    GetVcpuState(Vm, VcpuNum)->Pl1Ssp = RegisterValues[34].Reg64;
    GetVcpuState(Vm, VcpuNum)->Pl2Ssp = RegisterValues[35].Reg64;
    GetVcpuState(Vm, VcpuNum)->Pl3Ssp = RegisterValues[36].Reg64;

    //
    // N.B.: not synchronizing Star, Lstar, Fmask, KernelGsBase, Xss,
    // as these are already synchronized via EmulateWRMSR().
    //
}

VOID
SyncVcpuStateWithTdVmcs(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    VCPU_STATE *VcpuState;
    UINT64 Value;

    //
    // On VMLAUNCH, a new VMCS is loaded, with guest fields that may be different
    // from the previous ones. Synchronize these fields.
    //
    // Note: only the VRs in VCPU_STATE need to be synchronized.
    //

    VcpuState = GetVcpuState(Vm, VcpuNum);

    TdVmcsRead64(Vm, VcpuNum, VMX_VM_EXIT_REASON_ENCODE, &VcpuState->ExitReason);
    TdVmcsRead64(Vm, VcpuNum, VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE, &VcpuState->InstructionLength);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_INTERRUPTIBILITY_ENCODE, &VcpuState->GuestInterruptibility);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE, &VcpuState->PendingDebugException);

    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_CR0_ENCODE, &VcpuState->Cr0);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_CR3_ENCODE, &VcpuState->Cr3);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_CR4_ENCODE, &VcpuState->Cr4);

    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE, &VcpuState->DebugCtlMsr);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_IA32_PAT_FULL_ENCODE, &VcpuState->Pat);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_IA32_EFER_FULL_ENCODE, &VcpuState->Efer);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE, &VcpuState->PerfGlobalCtrl);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_IA32_SYSENTER_ESP_ENCODE, &VcpuState->SysenterEsp);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_IA32_SYSENTER_EIP_ENCODE, &VcpuState->SysenterEip);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_IA32_SYSENTER_CS_ENCODE, &VcpuState->SysenterCs);

    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_RSP_ENCODE, &VcpuState->Rsp);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_RIP_ENCODE, &VcpuState->Rip);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_RFLAGS_ENCODE, &VcpuState->Rflags);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_SSP_ENCODE, &VcpuState->Ssp);
    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_DR7_ENCODE, &VcpuState->Dr7);

    TdVmcsRead64(Vm, VcpuNum, VMX_GUEST_CS_ARBYTE_ENCODE, &Value);
    VcpuState->Cs.Attributes = (UINT16)Value;
}

VOID
SetPseamldrRangeActive(CORNELIUS_VM *Vm, BOOLEAN Active)
{
    if (Vm->IsPseamldrRangeActive == Active) {
        return;
    }

    if (Active) {
        MapGpaExecutable(Vm, Vm->VmConfig.PSeamldrRange.Base, Vm->VmConfig.PSeamldrRange.Size);
    } else {
        UnmapGpa(Vm, Vm->VmConfig.PSeamldrRange.Base, Vm->VmConfig.PSeamldrRange.Size);
    }

    Vm->IsPseamldrRangeActive = Active;
}

VCPU_STATE *
GetVcpuState(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    return &Vm->Vcpus[VcpuNum].VcpuState;
}

SEAM_STATE *
GetTdxState(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    return &Vm->Vcpus[VcpuNum].TdxState;
}

BOOLEAN
IsVcpuSeamldr(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    return Vm->Vcpus[VcpuNum].IsSeamldr;
}

VOID
InstallVcpuState(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    WHV_REGISTER_VALUE RegisterValues[NUM_VCPU_REGS];
    HRESULT hRes;

    //
    // Here we only install the RRs from VCPU_STATE.
    //

    memset(RegisterValues, 0, sizeof(RegisterValues));

    RegisterValues[0].Reg64 = GetVcpuState(Vm, VcpuNum)->Rax;
    RegisterValues[1].Reg64 = GetVcpuState(Vm, VcpuNum)->Rcx;
    RegisterValues[2].Reg64 = GetVcpuState(Vm, VcpuNum)->Rdx;
    RegisterValues[3].Reg64 = GetVcpuState(Vm, VcpuNum)->Rbx;
    RegisterValues[4].Reg64 = GetVcpuState(Vm, VcpuNum)->Rbp;
    RegisterValues[5].Reg64 = GetVcpuState(Vm, VcpuNum)->Rsi;
    RegisterValues[6].Reg64 = GetVcpuState(Vm, VcpuNum)->Rdi;
    RegisterValues[7].Reg64 = GetVcpuState(Vm, VcpuNum)->R8;
    RegisterValues[8].Reg64 = GetVcpuState(Vm, VcpuNum)->R9;
    RegisterValues[9].Reg64 = GetVcpuState(Vm, VcpuNum)->R10;
    RegisterValues[10].Reg64 = GetVcpuState(Vm, VcpuNum)->R11;
    RegisterValues[11].Reg64 = GetVcpuState(Vm, VcpuNum)->R12;
    RegisterValues[12].Reg64 = GetVcpuState(Vm, VcpuNum)->R13;
    RegisterValues[13].Reg64 = GetVcpuState(Vm, VcpuNum)->R14;
    RegisterValues[14].Reg64 = GetVcpuState(Vm, VcpuNum)->R15;
    RegisterValues[15].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm0;
    RegisterValues[16].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm1;
    RegisterValues[17].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm2;
    RegisterValues[18].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm3;
    RegisterValues[19].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm4;
    RegisterValues[20].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm5;
    RegisterValues[21].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm6;
    RegisterValues[22].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm7;
    RegisterValues[23].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm8;
    RegisterValues[24].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm9;
    RegisterValues[25].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm10;
    RegisterValues[26].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm11;
    RegisterValues[27].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm12;
    RegisterValues[28].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm13;
    RegisterValues[29].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm14;
    RegisterValues[30].Reg128 = GetVcpuState(Vm, VcpuNum)->Xmm15;
    RegisterValues[31].Reg64 = GetVcpuState(Vm, VcpuNum)->Xcr0;
    RegisterValues[32].Reg64 = GetVcpuState(Vm, VcpuNum)->KernelGsBase;
    RegisterValues[33].Reg64 = GetVcpuState(Vm, VcpuNum)->Pl0Ssp;
    RegisterValues[34].Reg64 = GetVcpuState(Vm, VcpuNum)->Pl1Ssp;
    RegisterValues[35].Reg64 = GetVcpuState(Vm, VcpuNum)->Pl2Ssp;
    RegisterValues[36].Reg64 = GetVcpuState(Vm, VcpuNum)->Pl3Ssp;
    RegisterValues[37].Reg64 = GetVcpuState(Vm, VcpuNum)->Xss;

    hRes = WHvSetVirtualProcessorRegisters(Vm->Partition, VcpuNum,
        VcpuRegisterNames, NUM_VCPU_REGS, RegisterValues);
    FAIL_IF_ERROR(hRes);
}

UINT64
GetPseamldrEntryVmcsPtr(CORNELIUS_VM *Vm)
{
    return Vm->VmConfig.PSeamldrRange.Base + _4KB;
}

static UINT64
GetTdxEntryVmcsPtr(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    return (UINT64)Vm->VmConfig.SeamrrBase + _4KB + (SIZE_T)VcpuNum * _4KB;
}

UINT64
GetEntryVmcsPtr(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    if (IsVcpuSeamldr(Vm, VcpuNum)) {
        return GetPseamldrEntryVmcsPtr(Vm);
    } else {
        return GetTdxEntryVmcsPtr(Vm, VcpuNum);
    }
}

enum VcpuAction
SetEntryVmcsPtr(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    UINT64 VmcsPtr;

    if (IsVcpuSeamldr(Vm, VcpuNum)) {
        VmcsPtr = GetPseamldrEntryVmcsPtr(Vm);
    } else {
        VmcsPtr = GetTdxEntryVmcsPtr(Vm, VcpuNum);
    }

    SetVmcsPtr(Vm, VcpuNum, VmcsPtr);

    return VmcsCache(Vm, VcpuNum, VmcsPtr);
}

UINT64
GetVmcsPtr(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    if (IsVcpuSeamldr(Vm, VcpuNum)) {
        return Vm->SeamldrState.VmcsPtr;
    } else {
        return GetTdxState(Vm, VcpuNum)->VmcsPtr;
    }
}

VOID
SetVmcsPtr(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsPtr)
{
    if (IsVcpuSeamldr(Vm, VcpuNum)) {
        Vm->SeamldrState.VmcsPtr = VmcsPtr;
    } else {
        GetTdxState(Vm, VcpuNum)->VmcsPtr = VmcsPtr;
    }
}

enum VmcsType
GetCurrentVmcsType(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    if (IsVcpuSeamldr(Vm, VcpuNum)) {
        return VmcsTypePseamldr;
    } else if (GetTdxState(Vm, VcpuNum)->VmcsPtr == GetTdxEntryVmcsPtr(Vm, VcpuNum)) {
        return VmcsTypeTdxModule;
    } else if (GetTdxState(Vm, VcpuNum)->VmcsPtr == VMCS_INVALID_PTR) {
        return VmcsTypeInvalid;
    } else {
        return VmcsTypeTdGuest;
    }
}

VOID
PseamldrLock(CORNELIUS_VM *Vm)
{
    if (WaitForSingleObject(Vm->PseamldrLock, INFINITE) != WAIT_OBJECT_0) {
        FATAL("PseamldrLock failed");
    }
}

VOID
PseamldrUnlock(CORNELIUS_VM *Vm)
{
    ReleaseMutex(Vm->PseamldrLock);
}

UINT64
AllocatePaFromCmrsAvail(CORNELIUS_VM *Vm)
{
    UINT64 Pa;
    SIZE_T i;

    //
    // Allocate a physical page from an available CMR.
    //

    for (i = 0; i < Vm->VmConfig.NumberOfCmrs; i++) {
        if (Vm->CmrsAvail[i].Start == Vm->CmrsAvail[i].End) {
            continue;
        }
        Pa = Vm->CmrsAvail[i].Start;
        Vm->CmrsAvail[i].Start += PAGE_SIZE;
        return Pa;
    }

    FATAL("Out of available CMRs");
}

VOID
MapCmrsInKeyidSpace(CORNELIUS_VM *Vm, UINT16 Keyid)
{
    SIZE_T i;

    for (i = 0; i < Vm->VmConfig.NumberOfCmrs; i++) {
        MapGpa(Vm, Vm->VmConfig.Cmrs[i].Base + (SIZE_T)Keyid * CORNELIUS_KEYSPACE_SIZE,
            Vm->VmConfig.Cmrs[i].Size);
    }
}

TD_VM *
CreateTdVm(CORNELIUS_VM *Vm, UINT16 NumberOfVcpus)
{
    TD_VM *TdVm;
    UINT16 i;

    TdVm = malloc(offsetof(TD_VM, Vcpus[NumberOfVcpus]));
    if (TdVm == NULL) {
        return NULL;
    }
    memset(TdVm, 0, offsetof(TD_VM, Vcpus[NumberOfVcpus]));

    TdVm->TdrPa = AllocatePaFromCmrsAvail(Vm);
    TdVm->NumberOfVcpus = NumberOfVcpus;

    for (i = 0; i < NumberOfVcpus; i++) {
        TdVm->Vcpus[i].TdvprPa = AllocatePaFromCmrsAvail(Vm);
    }

    return TdVm;
}

BOOLEAN
TdVmcsWrite64(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsField, UINT64 Value)
{
    TD_VMCS *VmcsHva;
    UINT64 VmcsPtr;
    SIZE_T i;

    if (GetCurrentVmcsType(Vm, VcpuNum) != VmcsTypeTdGuest) {
        FATAL("GetCurrentVmcsType(Vm, VcpuNum) != VmcsTypeTdGuest");
    }

    VmcsPtr = GetVmcsPtr(Vm, VcpuNum);
    VmcsHva = (TD_VMCS *)GPA_TO_HVA(Vm, VmcsPtr);

    for (i = 0; i < NUM_TD_VMCS_FIELDS; i++) {
        if (TdVmcsFields[i] == VmcsField) {
            VmcsHva->Fields[i] = Value;
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN
TdVmcsRead64(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsField, PUINT64 Value)
{
    TD_VMCS *VmcsHva;
    UINT64 VmcsPtr;
    SIZE_T i;

    if (GetCurrentVmcsType(Vm, VcpuNum) != VmcsTypeTdGuest) {
        FATAL("GetCurrentVmcsType(Vm, VcpuNum) != VmcsTypeTdGuest");
    }

    VmcsPtr = GetVmcsPtr(Vm, VcpuNum);
    VmcsHva = (TD_VMCS *)GPA_TO_HVA(Vm, VmcsPtr);

    for (i = 0; i < NUM_TD_VMCS_FIELDS; i++) {
        if (TdVmcsFields[i] == VmcsField) {
            *Value = VmcsHva->Fields[i];
            return TRUE;
        }
    }

    return FALSE;
}

enum VcpuAction
VmcsCache(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsPtr)
{
    CORNELIUS_VCPU *Vcpu = &Vm->Vcpus[VcpuNum];
    TD_VMCS *VmcsHva;
    INT Candidate;
    INT i;

    Candidate = -1;

    for (i = 0; i < VMCS_CACHE_SIZE; i++) {
        if (Vcpu->VmcsCache[i] == VmcsPtr) {
            return VcpuActionKeepRunning;
        }
        if (Vcpu->VmcsCache[i] == 0) {
            Candidate = i;
        }
    }

    if (Candidate == -1) {
        FATAL("VMCS_CACHE_SIZE is too small");
    }

    if (!InvariantsOnVmcsCache(Vm, VcpuNum, VmcsPtr)) {
        return VcpuActionInvariantViolated;
    }

    Vcpu->VmcsCache[Candidate] = VmcsPtr;

    VmcsHva = (TD_VMCS *)GPA_TO_HVA(Vm, VmcsPtr);
    VmcsHva->CachedOnCpu = TRUE;

    //
    // Unmap the VMCS, to catch any attempt to directly access it.
    //
    // Note: the P-SEAMLDR transfer VMCS is legally accessed at init time,
    // so don't unmap it.
    //

    if (VmcsPtr != GetPseamldrEntryVmcsPtr(Vm)) {
        UnmapGpa(Vm, VmcsPtr, PAGE_SIZE);
    }

    return VcpuActionKeepRunning;
}

VOID
VmcsUncache(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsPtr)
{
    CORNELIUS_VCPU *Vcpu = &Vm->Vcpus[VcpuNum];
    TD_VMCS *VmcsHva;
    INT i;

    for (i = 0; i < VMCS_CACHE_SIZE; i++) {
        if (Vcpu->VmcsCache[i] == VmcsPtr) {
            Vcpu->VmcsCache[i] = 0;

            VmcsHva = (TD_VMCS *)GPA_TO_HVA(Vm, VmcsPtr);
            VmcsHva->CachedOnCpu = FALSE;

            if (VmcsPtr != GetPseamldrEntryVmcsPtr(Vm)) {
                MapGpa(Vm, VmcsPtr, PAGE_SIZE);
            }
            return;
        }
    }
}

BOOLEAN
IsGpaInPseamldrRange(CORNELIUS_VM *Vm, UINT64 Gpa)
{
    return (Gpa >= Vm->VmConfig.PSeamldrRange.Base &&
            Gpa < Vm->VmConfig.PSeamldrRange.Base + Vm->VmConfig.PSeamldrRange.Size);
}

enum VcpuAction
MsrSeamExtend(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 MsrValue)
{
    seamextend_t *SeamExtendHva;
    BOOLEAN CopyOut;

    CopyOut = (MsrValue & 1) != 0;
    MsrValue &= ~1;

    if (!IsVcpuSeamldr(Vm, VcpuNum)) {
        LogVcpuErr(Vm, VcpuNum, "SEAMEXTEND not in P-SEAMLDR mode at RIP = 0x%llx\n",
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        return VcpuActionEmulationError;
    }

    if (MsrValue % 256 != 0) {
        LogVcpuErr(Vm, VcpuNum, "Unaligned SEAMEXTEND value 0x%llx at RIP = 0x%llx\n",
            MsrValue,
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        return VcpuActionEmulationError;
    }

    if (!IsGpaInPseamldrRange(Vm, MsrValue)) {
        LogVcpuErr(Vm, VcpuNum, "SEAMEXTEND value 0x%llx not in P-SEAMLDR range at RIP = 0x%llx\n",
            MsrValue,
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        return VcpuActionEmulationError;
    }

    SeamExtendHva = (seamextend_t *)GPA_TO_HVA(Vm, MsrValue);

    if (CopyOut) {
        SeamExtendHva->seam_ready = Vm->SeamReady;
    } else {
        Vm->SeamReady = SeamExtendHva->seam_ready;
    }

    return VcpuActionKeepRunning;
}