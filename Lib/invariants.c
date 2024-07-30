// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "common.h"

BOOLEAN
InvariantsOnCPUID(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT32 Leaf)
{
    //
    // Invariants:
    //  - If Leaf > 2, the IA32_MISC_ENABLE.LimitCpuidMaxval bit must not
    //    be set when CPUID executes.
    //

    if ((Leaf > 2) && (GetVcpuState(Vm, VcpuNum)->MiscEnable & __BIT(22))) {
        LogVcpuErr(Vm, VcpuNum, "CPUID executed with IA32_MISC_ENABLE.LimitCpuidMaxval set at RIP = 0x%llx\n",
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
IsTdxPrivateKeyid(CORNELIUS_VM *Vm, UINT16 Keyid)
{
    UINT16 FirstTdxKeyid;
    UINT16 NumKeyids;

    NumKeyids = (1ULL << Vm->VmConfig.KeyidBits);
    FirstTdxKeyid = NumKeyids - (UINT16)Vm->VmConfig.NumPrivKeyids + 1;

    if (Keyid >= FirstTdxKeyid && Keyid < NumKeyids) {
        return TRUE;
    }

    return FALSE;
}

BOOLEAN
InvariantsOnPCONFIG(CORNELIUS_VM *Vm, UINT32 VcpuNum, mktme_key_program_t *MktmeKeyProgram)
{
    //
    // Invariants:
    //  - The command must be SET_KEY_RANDOM.
    //  - The keyid must be a private TDX keyid.
    //  - The keyid must not alreay be active.
    //

    if (MktmeKeyProgram->keyid_ctrl.command != MKTME_KEYID_SET_KEY_RANDOM) {
        LogVcpuErr(Vm, VcpuNum, "PCONFIG not SET_KEY_RANDOM at RIP = 0x%llx\n",
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        return FALSE;
    }

    if (!IsTdxPrivateKeyid(Vm, MktmeKeyProgram->keyid)) {
        LogVcpuErr(Vm, VcpuNum, "PCONFIG KeyId %u is incorrect at RIP = 0x%llx\n",
            MktmeKeyProgram->keyid,
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        return FALSE;
    }

    if (Vm->KeyidActive & (1ULL << (UINT64)MktmeKeyProgram->keyid)) {
        LogVcpuErr(Vm, VcpuNum, "PCONFIG on already active KeyId %u at RIP = 0x%llx\n",
            MktmeKeyProgram->keyid,
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
InvariantsOnVMPTRLD(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsPtr)
{
    UINT64 RealGpa;
    UINT16 Keyid;
    SIZE_T i;

    //
    // Invariants: on VMPTRLD the new VMCS must be either
    //  - Inside the SEAM range with Keyid=0, or
    //  - Inside a CMR with a private Keyid.
    //

    if (VmcsPtr == GetEntryVmcsPtr(Vm, VcpuNum)) {
        return TRUE;
    }

    Keyid = REAL_HKID_FROM_GPA(Vm, VmcsPtr);

    if (!IsTdxPrivateKeyid(Vm, Keyid)) {
        LogVcpuErr(Vm, VcpuNum, "VMPTRLD KeyId %u is incorrect at RIP = 0x%llx\n",
            Keyid,
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        return FALSE;
    }

    if ((Vm->KeyidActive & (1UL << Keyid)) == 0) {
        LogVcpuErr(Vm, VcpuNum, "VMPTRLD KeyId %u not activated at RIP = 0x%llx\n",
            Keyid,
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        return FALSE;
    }

    RealGpa = GPA_WITHOUT_REAL_HKID(Vm, VmcsPtr);

    for (i = 0; i < Vm->VmConfig.NumberOfCmrs; i++) {
        if (RealGpa >= Vm->VmConfig.Cmrs[i].Base &&
            RealGpa < Vm->VmConfig.Cmrs[i].Base + Vm->VmConfig.Cmrs[i].Size) {
            return TRUE;
        }
    }

    LogVcpuErr(Vm, VcpuNum, "VMPTRLD VMCS 0x%llx outside of CMR at RIP = 0x%llx\n",
        RealGpa,
        GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
    return FALSE;
}

BOOLEAN
InvariantsOnVMLAUNCH(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    BOOLEAN PerfGlobalCtlrEntryLoad;
    BOOLEAN PerfGlobalCtlrExitLoad;
    BOOLEAN PerfGlobalCtlrExitSave;
    TD_VMCS *VmcsHva;
    UINT64 VmcsPtr;
    SIZE_T i;

    PerfGlobalCtlrEntryLoad = 0;
    PerfGlobalCtlrExitLoad = 0;
    PerfGlobalCtlrExitSave = 0;

    //
    // Invariants when the TDX module does a VMLAUNCH:
    //
    // - The host fields of the TD VMCS must be identical to the current TDX
    //   module state.
    // - The CR4 mask/shadow must force CR4.MCE to 1.
    // - Several VMCS control fields must set several bits to 1.
    // - The PerfGlobalCtrl EntryLoad/ExitLoad/ExitSave values must be the same.
    //

    if (GetCurrentVmcsType(Vm, VcpuNum) != VmcsTypeTdGuest) {
        FATAL("GetCurrentVmcsType(Vm, VcpuNum) != VmcsTypeTdGuest");
    }

    VmcsPtr = GetVmcsPtr(Vm, VcpuNum);
    VmcsHva = (TD_VMCS *)GPA_TO_HVA(Vm, VmcsPtr);

    for (i = 0; i < NUM_TD_VMCS_FIELDS; i++) {
        switch (TdVmcsFields[i]) {
        case VMX_HOST_IA32_PERF_GLOBAL_CONTROL_FULL_ENCODE:
        case VMX_HOST_IA32_SYSENTER_ESP_ENCODE:
        case VMX_HOST_IA32_SYSENTER_EIP_ENCODE:
        case VMX_HOST_IA32_SYSENTER_CS_ENCODE:
        case VMX_HOST_IA32_INTERRUPT_SSP_TABLE_ADDR_ENCODE:
            if (VmcsHva->Fields[i] != 0) {
                LogVcpuErr(Vm, VcpuNum, "TD VMCS field %llx non-zero at RIP = 0x%llx\n",
                    TdVmcsFields[i],
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;

        case VMX_HOST_CR0_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_CR0].Reg64 != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed CR0 at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_CR3_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_CR3].Reg64 != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed CR3 at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_CR4_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_CR4].Reg64 != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed CR4 at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_ES_SELECTOR_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_ES].Segment.Selector != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed ES.SEL at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_CS_SELECTOR_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_CS].Segment.Selector != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed CS.SEL at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_SS_SELECTOR_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_SS].Segment.Selector != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed SS.SEL at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_DS_SELECTOR_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_DS].Segment.Selector != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed DS.SEL at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_FS_SELECTOR_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_FS].Segment.Selector != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed FS.SEL at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_GS_SELECTOR_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_GS].Segment.Selector != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed GS.SEL at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_TR_SELECTOR_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_TR].Segment.Selector != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed TR.SEL at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_IA32_PAT_FULL_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_PAT].Reg64 != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed PAT at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_IA32_S_CET_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_SCET].Reg64 != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed SCET at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_IA32_EFER_FULL_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_EFER].Reg64 != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed EFER at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_RSP_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_RSP].Reg64 != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed RSP at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_SSP_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_SSP].Reg64 != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed SSP at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_FS_BASE_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_FS].Segment.Base != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed FS.BASE at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_GS_BASE_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_GS].Segment.Base != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed GS.BASE at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_TR_BASE_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_TR].Segment.Base != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed TR.BASE at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_IDTR_BASE_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_IDTR].Table.Base != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed IDT.BASE at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_HOST_GDTR_BASE_ENCODE:
            if (GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_GDTR].Table.Base != VmcsHva->Fields[i]) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE changed GDT.BASE at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;

        case VMX_CR4_GUEST_HOST_MASK_ENCODE:
            if ((VmcsHva->Fields[i] & CR4_MCE) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set CR4.MCE mask to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;
        case VMX_CR4_READ_SHADOW_ENCODE:
            if ((VmcsHva->Fields[i] & CR4_MCE) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set CR4.MCE shadow to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;

        case VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE:
            if ((VmcsHva->Fields[i] & __BIT(24)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set PROC_BASED_CTLS.IoExiting to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            if ((VmcsHva->Fields[i] & __BIT(28)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set PROC_BASED_CTLS.UseMsrBitmaps to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            if ((VmcsHva->Fields[i] & __BIT(31)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set PROC_BASED_CTLS.ActivateCtls2 to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;

        case VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE:
            if ((VmcsHva->Fields[i] & __BIT(1)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set PROC_BASED_CTLS2.EnableEpt to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;

        case VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE:
            if ((VmcsHva->Fields[i] & __BIT(0)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set PIN_BASED_CTLS.IntExiting to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            break;

        case VMX_VM_ENTRY_CONTROL_ENCODE:
            if ((VmcsHva->Fields[i] & __BIT(2)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set ENTRY_CTLS.LoadDebugControls to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            if ((VmcsHva->Fields[i] & __BIT(14)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set ENTRY_CTLS.LoadPat to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            if ((VmcsHva->Fields[i] & __BIT(15)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set ENTRY_CTLS.LoadEfer to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            if ((VmcsHva->Fields[i] & __BIT(20)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set ENTRY_CTLS.LoadCet to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }

            PerfGlobalCtlrEntryLoad = (VmcsHva->Fields[i] & __BIT(13)) != 0;
            break;

        case VMX_VM_EXIT_CONTROL_ENCODE:
            if ((VmcsHva->Fields[i] & __BIT(2)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set EXIT_CTLS.LoadDebugControls to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            if ((VmcsHva->Fields[i] & __BIT(9)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set EXIT_CTLS.HostLongMode to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            if ((VmcsHva->Fields[i] & __BIT(18)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set EXIT_CTLS.SavePat to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            if ((VmcsHva->Fields[i] & __BIT(19)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set EXIT_CTLS.LoadPat to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            if ((VmcsHva->Fields[i] & __BIT(20)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set EXIT_CTLS.SaveEfer to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            if ((VmcsHva->Fields[i] & __BIT(21)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set EXIT_CTLS.LoadEfer to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }
            if ((VmcsHva->Fields[i] & __BIT(28)) == 0) {
                LogVcpuErr(Vm, VcpuNum, "VMWRITE set EXIT_CTLS.LoadCet to zero at RIP = 0x%llx\n",
                    GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                return FALSE;
            }

            PerfGlobalCtlrExitLoad = (VmcsHva->Fields[i] & __BIT(12)) != 0;
            PerfGlobalCtlrExitSave = (VmcsHva->Fields[i] & __BIT(30)) != 0;
            break;

        default:
            break;
        }
    }

    if (PerfGlobalCtlrEntryLoad != PerfGlobalCtlrExitLoad ||
        PerfGlobalCtlrExitLoad != PerfGlobalCtlrExitSave) {
        LogVcpuErr(Vm, VcpuNum, "PerfGlobalCtrl is not properly context-switched at RIP = 0x%llx\n",
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
InvariantsOnVmcsCache(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsPtr)
{
    TD_VMCS *VmcsHva;

    //
    // Invariants: when the TDX module caches a new VMCS, that VMCS must not be
    // cached on any CPU.
    //

    VmcsHva = (TD_VMCS *)GPA_TO_HVA(Vm, VmcsPtr);

    if (VmcsHva->CachedOnCpu) {
        LogVcpuErr(Vm, VcpuNum, "VMCS 0x%llx already cached elsewhere at RIP = 0x%llx\n",
            VmcsPtr,
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        return FALSE;
    }

    return TRUE;
}