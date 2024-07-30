// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "common.h"

typedef union {
    struct {
        UINT8 Rm : 3;
        UINT8 Reg : 3;
        UINT8 Mod : 2;
    };
    UINT8 Raw;
} REGMODRM;

typedef union {
    struct {
        UINT8 B : 1;
        UINT8 X : 1;
        UINT8 R : 1;
        UINT8 W : 1;
        UINT8 Rsvd : 4;
    };
    UINT8 Raw;
} REXPREFIX;

static inline BOOLEAN
IsRexPrefix(UINT8 Byte)
{
    return (Byte >= 0x40 && Byte <= 0x4F);
}

static VOID
AdvanceRip(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    SetRegister64(Vm, VcpuNum, WHvX64RegisterRip, ExitContext->VpContext.Rip +
        ExitContext->VpContext.InstructionLength);
}

static VOID
AdvanceRipBy(CORNELIUS_VM* Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT* ExitContext, UINT64 Offset)
{
    SetRegister64(Vm, VcpuNum, WHvX64RegisterRip, ExitContext->VpContext.Rip +
        Offset);
}

static VOID
VmSucceed(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    UINT64 Rflags;

    Rflags = GetRegister64(Vm, VcpuNum, WHvX64RegisterRflags);

    Rflags &= ~(
        (1 << 0) |    // CF
        (1 << 2) |    // PF
        (1 << 4) |    // AF
        (1 << 6) |    // ZF
        (1 << 7) |    // SF
        (1 << 11)     // OF
    );

    SetRegister64(Vm, VcpuNum, WHvX64RegisterRflags, Rflags);

    return;
}

static enum VcpuAction
EmulateVMREAD(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    WHV_REGISTER_NAME SrcGpr;
    WHV_REGISTER_NAME DstGpr;
    UINT64 AdvanceBy;
    enum VmcsType VmcsType;
    UINT64 VmcsField;
    PUINT8 DstHva;
    UINT64 DstGva;
    UINT64 DstPa;
    UINT32 DstOffset;

    VmcsType = GetCurrentVmcsType(Vm, VcpuNum);

    if (VmcsType == VmcsTypeInvalid) {
        LogVcpuErr(Vm, VcpuNum, "VMREAD on invalid VMCS pointer at RIP = 0x%llx\n",
            ExitContext->VpContext.Rip);
        return VcpuActionEmulationError;
    }

    //
    // XXX: properly decode the instruction here
    //

    // 0F 78 03          vmread  qword ptr [rbx], rax
    if (ExitContext->VpException.InstructionByteCount >= 3 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0F\x78\x03", 3)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterRbx;
        DstOffset = 0;
        AdvanceBy = 3;
    }
    // 0f 78 01             	vmread %rax,(%rcx)
    else if (ExitContext->VpException.InstructionByteCount >= 3 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0F\x78\x01", 3)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterRcx;
        DstOffset = 0;
        AdvanceBy = 3;
    }
    // 0f 78 04 24          	vmread %rax,(%rsp)
    else if (ExitContext->VpException.InstructionByteCount >= 4 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0F\x78\x04\x24", 4)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterRsp;
        DstOffset = 0;
        AdvanceBy = 4;
    }
    // 0f 78 84 24 NN NN NN NN	vmread %rax,NN(%rsp)
    else if (ExitContext->VpException.InstructionByteCount >= 8 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0F\x78\x84\x24", 4)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterRsp;
        DstOffset = *((PUINT32)&ExitContext->VpException.InstructionBytes[4]);
        AdvanceBy = 8;
    }
    // 0f 78 44 24 NN           vmread %rax,NN(%rsp)
    else if (ExitContext->VpException.InstructionByteCount >= 5 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0F\x78\x44\x24", 4)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterRsp;
        DstOffset = ExitContext->VpException.InstructionBytes[4];
        AdvanceBy = 5;
    }
    // 0f 78 5c 24 NN           vmread %rbx,NN(%rsp)
    else if (ExitContext->VpException.InstructionByteCount >= 5 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0F\x78\x5c\x24", 4)) {
        SrcGpr = WHvX64RegisterRbx;
        DstGpr = WHvX64RegisterRsp;
        DstOffset = ExitContext->VpException.InstructionBytes[4];
        AdvanceBy = 5;
    }
    // 0f 78 47 NN          	vmread %rax,NN(%rdi)
    else if (ExitContext->VpException.InstructionByteCount >= 4 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0F\x78\x47", 3)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterRdi;
        DstOffset = ExitContext->VpException.InstructionBytes[3];
        AdvanceBy = 4;
    }
    // 0f 78 43 NN          	vmread %rax,NN(%rbx)
    else if (ExitContext->VpException.InstructionByteCount >= 4 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0F\x78\x43", 3)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterRbx;
        DstOffset = ExitContext->VpException.InstructionBytes[3];
        AdvanceBy = 4;
    }
    // 0f 78 83 NN NN NN NN 	vmread %rax,0x88(%rbx)
    else if (ExitContext->VpException.InstructionByteCount >= 4 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0F\x78\x83", 3)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterRbx;
        DstOffset = *((PUINT32)&ExitContext->VpException.InstructionBytes[3]);
        AdvanceBy = 7;
    }
    // 41 0f 78 04 24       	vmread %rax,(%r12)
    else if (ExitContext->VpException.InstructionByteCount >= 5 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x41\x0F\x78\x04\x24", 5)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterR12;
        DstOffset = 0;
        AdvanceBy = 5;
    }
    // 41 0f 78 45 NN       	vmread %rax,NN(%r13)
    else if (ExitContext->VpException.InstructionByteCount >= 5 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x41\x0F\x78\x45", 4)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterR13;
        DstOffset = ExitContext->VpException.InstructionBytes[4];
        AdvanceBy = 5;
    }
    // 41 0f 78 06          	vmread %rax,(%r14)
    else if (ExitContext->VpException.InstructionByteCount >= 4 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x41\x0F\x78\x06", 4)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterR14;
        DstOffset = 0;
        AdvanceBy = 4;
    }
    // 41 0f 78 46 NN       	vmread %rax,NN(%r14)
    else if (ExitContext->VpException.InstructionByteCount >= 5 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x41\x0F\x78\x46", 4)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterR14;
        DstOffset = ExitContext->VpException.InstructionBytes[4];
        AdvanceBy = 5;
    }
    // 41 0f 78 07          	vmread %rax,(%r15)
    else if (ExitContext->VpException.InstructionByteCount >= 4 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x41\x0F\x78\x07", 4)) {
        SrcGpr = WHvX64RegisterRax;
        DstGpr = WHvX64RegisterR15;
        DstOffset = 0;
        AdvanceBy = 4;
    }
    // 45 0f 78 7e NN       	vmread %r15,NN(%r14)
    else if (ExitContext->VpException.InstructionByteCount >= 5 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x45\x0F\x78\x7e", 4)) {
        SrcGpr = WHvX64RegisterR15;
        DstGpr = WHvX64RegisterR14;
        DstOffset = ExitContext->VpException.InstructionBytes[4];
        AdvanceBy = 5;
    }
    // 45 0f 78 be NN NN NN NN 	vmread %r15,NN(%r14)
    else if (ExitContext->VpException.InstructionByteCount >= 8 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x45\x0F\x78\xbe", 4)) {
        SrcGpr = WHvX64RegisterR15;
        DstGpr = WHvX64RegisterR14;
        DstOffset = *((PUINT32)&ExitContext->VpException.InstructionBytes[4]);
        AdvanceBy = 8;
    }
    // 44 0f 78 bc 24 NN NN NN NN 	vmread %r15,NN(%rsp)
    else if (ExitContext->VpException.InstructionByteCount >= 9 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x44\x0F\x78\xbc\x24", 4)) {
        SrcGpr = WHvX64RegisterR15;
        DstGpr = WHvX64RegisterRsp;
        DstOffset = *((PUINT32)&ExitContext->VpException.InstructionBytes[5]);
        AdvanceBy = 9;
    }
    // 0f 78 9c 24 NN NN NN NN 	vmread %rbx,NN(%rsp)
    else if (ExitContext->VpException.InstructionByteCount >= 8 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0F\x78\x9c\x24", 4)) {
        SrcGpr = WHvX64RegisterRbx;
        DstGpr = WHvX64RegisterRsp;
        DstOffset = *((PUINT32)&ExitContext->VpException.InstructionBytes[4]);
        AdvanceBy = 8;
    }
    else {
        LogVcpuErr(Vm, VcpuNum, "Unrecognized VMREAD at RIP = 0x%llx\n",
            ExitContext->VpContext.Rip);
        return VcpuActionEmulationError;
    }

    DstGva = GetRegister64(Vm, VcpuNum, DstGpr);
    if (!GvaToPa(Vm, VcpuNum, DstGva, &DstPa)) {
        return VcpuActionEmulationError;
    }
    if (!PaToHva(Vm, DstPa, (PVOID *)&DstHva)) {
        return VcpuActionEmulationError;
    }
    DstHva += DstOffset;

    VmcsField = GetRegister64(Vm, VcpuNum, SrcGpr);

    if (VmcsType == VmcsTypePseamldr || VmcsType == VmcsTypeTdxModule) {
        //
        // VMREAD for the P-SEAMLDR and the TDX module.
        //
        switch (VmcsField) {
        case VMX_VM_EXIT_REASON_ENCODE:
            *((PUINT64)DstHva) = GetVcpuState(Vm, VcpuNum)->ExitReason;
            goto Done;
        case VMX_VM_EXIT_INSTRUCTION_LENGTH_ENCODE:
            *((PUINT64)DstHva) = GetVcpuState(Vm, VcpuNum)->InstructionLength;
            goto Done;
        case VMX_GUEST_INTERRUPTIBILITY_ENCODE:
            *((PUINT64)DstHva) = GetVcpuState(Vm, VcpuNum)->GuestInterruptibility;
            goto Done;
        case VMX_GUEST_RIP_ENCODE:
            *((PUINT64)DstHva) = GetVcpuState(Vm, VcpuNum)->Rip;
            goto Done;
        case VMX_GUEST_RFLAGS_ENCODE:
            *((PUINT64)DstHva) = GetVcpuState(Vm, VcpuNum)->Rflags;
            goto Done;
        case VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE:
            *((PUINT64)DstHva) = GetVcpuState(Vm, VcpuNum)->PendingDebugException;
            goto Done;
        case VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE:
            *((PUINT64)DstHva) = GetVcpuState(Vm, VcpuNum)->DebugCtlMsr;
            goto Done;
        default:
            break;
        }
    }

    if (VmcsType == VmcsTypePseamldr) {
        //
        // VMREAD for the P-SEAMLDR.
        //
        LogVcpuErr(Vm, VcpuNum, "VMCS field 0x%llx not recognized in P-SEAMLDR mode\n", VmcsField);
        return VcpuActionEmulationError;
    } else if (VmcsType == VmcsTypeTdxModule) {
        //
        // VMREAD for the TDX module.
        //
        switch (VmcsField) {
        case VMX_HOST_CR0_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_CR0].Reg64;
            break;
        case VMX_HOST_CR3_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_CR3].Reg64;
            break;
        case VMX_HOST_CR4_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_CR4].Reg64;
            break;
        case VMX_HOST_CS_SELECTOR_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_CS].Segment.Selector;
            break;
        case VMX_HOST_SS_SELECTOR_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_SS].Segment.Selector;
            break;
        case VMX_HOST_FS_SELECTOR_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_FS].Segment.Selector;
            break;
        case VMX_HOST_GS_SELECTOR_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_GS].Segment.Selector;
            break;
        case VMX_HOST_TR_SELECTOR_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_TR].Segment.Selector;
            break;
        case VMX_HOST_IA32_S_CET_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_SCET].Reg64;
            break;
        case VMX_HOST_IA32_PAT_FULL_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_PAT].Reg64;
            break;
        case VMX_HOST_IA32_EFER_FULL_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_EFER].Reg64;
            break;
        case VMX_HOST_FS_BASE_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_FS].Segment.Base;
            break;
        case VMX_HOST_GS_BASE_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_GS].Segment.Base;
            break;
        case VMX_HOST_IDTR_BASE_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_IDTR].Table.Base;
            break;
        case VMX_HOST_GDTR_BASE_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_GDTR].Table.Base;
            break;
        case VMX_HOST_RSP_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_RSP].Reg64;
            break;
        case VMX_HOST_SSP_ENCODE:
            *((PUINT64)DstHva) = GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_SSP].Reg64;
            break;
        default:
            LogVcpuErr(Vm, VcpuNum, "Unrecognized VMREAD on field 0x%llx at RIP = 0x%llx\n",
                VmcsField,
                ExitContext->VpContext.Rip);
            return VcpuActionEmulationError;
        }
    } else {
        //
        // VMREAD for a TD guest.
        //
        if (!TdVmcsRead64(Vm, VcpuNum, VmcsField, (PUINT64)DstHva)) {
            LogVcpuErr(Vm, VcpuNum, "Unrecognized VMREAD on TD guest field 0x%llx at RIP = 0x%llx\n",
                VmcsField,
                ExitContext->VpContext.Rip);
            return VcpuActionEmulationError;
        }
    }

Done:
    VmSucceed(Vm, VcpuNum);
    AdvanceRipBy(Vm, VcpuNum, ExitContext, AdvanceBy);
    return VcpuActionKeepRunning;
}

static enum VcpuAction
EmulateVMWRITE(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    WHV_REGISTER_NAME SrcGpr;
    WHV_REGISTER_NAME DstGpr;
    enum VmcsType VmcsType;
    UINT64 VmcsField;
    UINT64 Value;
    UINT8* InstructionBytes = ExitContext->VpException.InstructionBytes;
    UINT8 RexSize = 0;
    REXPREFIX RexPrefix = { 0 };
    REGMODRM RegModRM;

    VmcsType = GetCurrentVmcsType(Vm, VcpuNum);

    if (VmcsType == VmcsTypeInvalid) {
        LogVcpuErr(Vm, VcpuNum, "VMWRITE on invalid VMCS pointer at RIP = 0x%llx\n",
            ExitContext->VpContext.Rip);
        return VcpuActionEmulationError;
    }

    if (IsRexPrefix(InstructionBytes[0])) {
        RexSize = 1;
        RexPrefix.Raw = InstructionBytes[0];
    }

    RegModRM.Raw = InstructionBytes[RexSize + 2];

    if (RegModRM.Mod != 3) {
        // VMWRITE with memory reference.
        LogVcpuErr(Vm, VcpuNum, "Unrecognized VMWRITE at RIP = 0x%llx\n",
            ExitContext->VpContext.Rip);
        return VcpuActionEmulationError;
    }

    SrcGpr = RegModRM.Reg;
    DstGpr = RegModRM.Rm;

    if (RexSize) {
        if (RexPrefix.B) {
            DstGpr += 8;
        }
        if (RexPrefix.R) {
            SrcGpr += 8;
        }
    }

    VmcsField = GetRegister64(Vm, VcpuNum, SrcGpr);
    Value = GetRegister64(Vm, VcpuNum, DstGpr);

    if (VmcsType != VmcsTypeTdGuest) {
        //
        // VMWRITE for the P-SEAMLDR or the TDX module.
        //
        switch (VmcsField) {
        case VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE:
            GetVcpuState(Vm, VcpuNum)->DebugCtlMsr = Value;
            break;
        case VMX_GUEST_DR7_ENCODE:
            GetVcpuState(Vm, VcpuNum)->Dr7 = Value;
            break;
        case VMX_HOST_FS_BASE_ENCODE:
            if (IsVcpuSeamldr(Vm, VcpuNum)) {
                Vm->SeamldrState.RegisterValues[SEAM_STATE_FS].Segment.Base = Value;
            } else {
                // Also need to update the transfer VMCS stored in the P-SEAMLDR memory.
                GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_FS].Segment.Base = Value;
                PseamldrTransferVmcsSet64(Vm, VcpuNum, VMX_HOST_FS_BASE_OFFSET,
                    GetTdxState(Vm, VcpuNum)->RegisterValues[SEAM_STATE_FS].Segment.Base);
            }
            break;
        case VMX_GUEST_INTERRUPTIBILITY_ENCODE:
            GetVcpuState(Vm, VcpuNum)->GuestInterruptibility = Value;
            break;
        case VMX_GUEST_RIP_ENCODE:
            GetVcpuState(Vm, VcpuNum)->Rip = Value;
            break;
        case VMX_GUEST_PND_DEBUG_EXCEPTION_ENCODE:
            GetVcpuState(Vm, VcpuNum)->PendingDebugException = Value;
            break;
        default:
            LogVcpuErr(Vm, VcpuNum, "Unrecognized VMWRITE on field 0x%llx at RIP = 0x%llx, Value = 0x%llx\n",
                VmcsField,
                ExitContext->VpContext.Rip,
                Value);
            return VcpuActionEmulationError;
        }
    } else {
        //
        // VMWRITE for a TD guest.
        //
        if (!TdVmcsWrite64(Vm, VcpuNum, VmcsField, Value)) {
            LogVcpuErr(Vm, VcpuNum, "Unrecognized VMWRITE on TD guest field 0x%llx at RIP = 0x%llx, Value = 0x%llx\n",
                VmcsField,
                ExitContext->VpContext.Rip,
                Value);
            return VcpuActionEmulationError;
        }
    }

    VmSucceed(Vm, VcpuNum);
    AdvanceRipBy(Vm, VcpuNum, ExitContext, (SIZE_T)RexSize + 3);
    return VcpuActionKeepRunning;
}

static enum VcpuAction
EmulateVMPTRLD(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    enum VcpuAction Action;
    WHV_REGISTER_NAME Gpr;
    UINT32 GprOffset;
    UINT64 Gva;
    UINT64 Pa;
    PUINT8 Hva;
    UINT64 VmcsPtr;
    UINT64 AdvanceBy;

    // 0f c7 74 24 NN      	vmptrld NN(%rsp)
    if (ExitContext->VpException.InstructionByteCount >= 5 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0f\xc7\x74\x24", 4)) {
        Gpr = WHvX64RegisterRsp;
        GprOffset = ExitContext->VpException.InstructionBytes[4];
        AdvanceBy = 5;
    }
    // 0f c7 b4 24 NN NN NN NN 	vmptrld NN(%rsp)
    else if (ExitContext->VpException.InstructionByteCount >= 8 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0f\xc7\xb4\x24", 4)) {
        Gpr = WHvX64RegisterRsp;
        GprOffset = *((PUINT32)&ExitContext->VpException.InstructionBytes[4]);
        AdvanceBy = 8;
    }
    else {
        LogVcpuErr(Vm, VcpuNum, "Unrecognized VMPTRLD at RIP = 0x%llx\n",
            ExitContext->VpContext.Rip);
        return VcpuActionEmulationError;
    }

    Gva = GetRegister64(Vm, VcpuNum, Gpr);
    if (!GvaToPa(Vm, VcpuNum, Gva, &Pa)) {
        return VcpuActionEmulationError;
    }
    if (!PaToHva(Vm, Pa, (PVOID *)&Hva)) {
        return VcpuActionEmulationError;
    }
    Hva += GprOffset;

    VmcsPtr = *((PUINT64)Hva);

    if (!InvariantsOnVMPTRLD(Vm, VcpuNum, VmcsPtr)) {
        return VcpuActionInvariantViolated;
    }

    Action = VmcsCache(Vm, VcpuNum, VmcsPtr);
    if (Action != VcpuActionKeepRunning) {
        return Action;
    }

    SetVmcsPtr(Vm, VcpuNum, VmcsPtr);

    VmSucceed(Vm, VcpuNum);
    AdvanceRipBy(Vm, VcpuNum, ExitContext, AdvanceBy);
    return VcpuActionKeepRunning;
}

static enum VcpuAction
EmulateVMCLEAR(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    WHV_REGISTER_NAME Gpr;
    UINT64 AdvanceBy;
    UINT32 GprOffset;
    UINT64 Gva;
    UINT64 Pa;
    PUINT8 Hva;
    UINT64 VmcsPtr;

    // 66 0f c7 74 24 NN    	vmclear NN(%rsp)
    if (ExitContext->VpException.InstructionByteCount >= 6 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x0f\xc7\x74\x24", 5)) {
        Gpr = WHvX64RegisterRsp;
        GprOffset = ExitContext->VpException.InstructionBytes[5];
        AdvanceBy = 6;
    }
    // 66 0f c7 b4 24 NN NN NN NN 	vmclear NN(%rsp)
    else if (ExitContext->VpException.InstructionByteCount >= 9 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x0f\xc7\xb4\x24", 5)) {
        Gpr = WHvX64RegisterRsp;
        GprOffset = *((PUINT32)&ExitContext->VpException.InstructionBytes[5]);
        AdvanceBy = 9;
    }
    // 66 0f c7 34 24       	vmclear (%rsp)
    else if (ExitContext->VpException.InstructionByteCount >= 5 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x0f\xc7\x34\x24", 5)) {
        Gpr = WHvX64RegisterRsp;
        GprOffset = 0;
        AdvanceBy = 5;
    }
    else {
        LogVcpuErr(Vm, VcpuNum, "Unrecognized VMCLEAR at RIP = 0x%llx\n",
            ExitContext->VpContext.Rip);
        return VcpuActionEmulationError;
    }

    Gva = GetRegister64(Vm, VcpuNum, Gpr);
    if (!GvaToPa(Vm, VcpuNum, Gva, &Pa)) {
        return VcpuActionEmulationError;
    }
    if (!PaToHva(Vm, Pa, (PVOID *)&Hva)) {
        return VcpuActionEmulationError;
    }
    Hva += GprOffset;

    VmcsPtr = *((PUINT64)Hva);

    VmcsUncache(Vm, VcpuNum, VmcsPtr);

    if (VmcsPtr == GetVmcsPtr(Vm, VcpuNum)) {
        SetVmcsPtr(Vm, VcpuNum, VMCS_INVALID_PTR);
    }

    VmSucceed(Vm, VcpuNum);
    AdvanceRipBy(Vm, VcpuNum, ExitContext, AdvanceBy);
    return VcpuActionKeepRunning;
}

static enum VcpuAction
EmulateVMLAUNCH(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    if (!InvariantsOnVMLAUNCH(Vm, VcpuNum)) {
        return VcpuActionInvariantViolated;
    }

    VmSucceed(Vm, VcpuNum);
    AdvanceRipBy(Vm, VcpuNum, ExitContext, 3);
    return VcpuActionVmlaunch;
}

static enum VcpuAction
EmulateVMRESUME(CORNELIUS_VM* Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT* ExitContext)
{
    if (!InvariantsOnVMLAUNCH(Vm, VcpuNum)) {
        return VcpuActionInvariantViolated;
    }

    VmSucceed(Vm, VcpuNum);
    AdvanceRipBy(Vm, VcpuNum, ExitContext, 3);
    return VcpuActionVmresume;
}

static enum VcpuAction
EmulateUD2(CORNELIUS_VM *Vm, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    UNREFERENCED_PARAMETER(Vm);
    UNREFERENCED_PARAMETER(ExitContext);
    return VcpuActionSeamPanic;
}

enum VcpuAction
EmulateCPUID(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    UINT32 Leaf;

    Leaf = ExitContext->CpuidAccess.Rax & 0xFFFFFFFF;

    if (!InvariantsOnCPUID(Vm, VcpuNum, Leaf)) {
        return VcpuActionInvariantViolated;
    }

    switch (Leaf) {
    case CPUID_MAX_INPUT_VAL_LEAF:
        if (ExitContext->CpuidAccess.DefaultResultRax < CPUID_MIN_LAST_CPU_BASE_LEAF) {
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, CPUID_MIN_LAST_CPU_BASE_LEAF);
        } else {
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
        }
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
        break;
    case CPUID_VER_INFO_LEAF:
        // Hyper-V does not set certain bits. Set them manually.
        ExitContext->CpuidAccess.DefaultResultRcx |=
            CPUID_0_01_ECX_DTES64 |
            CPUID_0_01_ECX_DS_CPL |
            CPUID_0_01_ECX_PDCM |
            CPUID_0_01_ECX_X2APIC |
            CPUID_0_01_ECX_TSC_DEADLINE;
        ExitContext->CpuidAccess.DefaultResultRdx |=
            CPUID_0_01_EDX_DS |
            CPUID_0_01_EDX_HTT; // HV-DISCREPANCY: VpsPerSocket

        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
        break;
    case 3: // Serial number
    case CPUID_MAX_EXTENDED_VAL_LEAF:
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
        break;
    case CPUID_GET_MAX_PA_LEAF:
        ExitContext->CpuidAccess.DefaultResultRax &= ~0xFFULL;
        ExitContext->CpuidAccess.DefaultResultRax |= 52;
        ExitContext->CpuidAccess.DefaultResultRbx |= CPUID_8_08_EBX_WBNOINVD;

        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
        break;
    case CPUID_GET_TOPOLOGY_LEAF: {
        // Hyper-V does not expose this leaf to guests, so we can't use DefaultResult.
        cpuid_topology_level_t Ecx;
        ULONG Index;

        switch (ExitContext->CpuidAccess.Rcx) {
        case 0: // Logical Processor
            Index = 0;
            _BitScanReverse(&Index, Vm->NumberOfVcpus - 1);

            Ecx.raw = 0;
            Ecx.level_type = LEVEL_TYPE_CORE;

            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, (UINT64)Index + 1);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, Vm->NumberOfVcpus);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, Ecx.raw);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, VcpuNum);
            break;
        default:
            Ecx.raw = 0;
            Ecx.level_type = LEVEL_TYPE_INVALID;

            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, 0);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, Ecx.raw);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, 0);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, 0);
            break;
        }

        break;
    }
    case CPUID_DET_CACHE_PARAMS_LEAF: {
        cpu_cache_params_t *CpuCacheParamsRax = (cpu_cache_params_t *)&ExitContext->CpuidAccess.DefaultResultRax;

        switch (ExitContext->CpuidAccess.Rcx) {
        case 0:
        case 1:
        case 2:
            CpuCacheParamsRax->cores_per_socket_minus_one = Vm->NumberOfVcpus - 1; // HV-DISCREPANCY: VpsPerSocket
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
            break;
        case 3:
            CpuCacheParamsRax->max_num_of_lps_sharing_cache = Vm->NumberOfVcpus - 1; // HV-DISCREPANCY: VpsPerSocket
            CpuCacheParamsRax->cores_per_socket_minus_one = Vm->NumberOfVcpus - 1; // HV-DISCREPANCY: VpsPerSocket
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
            break;
        case 4:
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
            break;
        default:
            goto NotRecognized;
        }
        break;
    }

    case 6: // Thermal and Power Management Leaf
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
        break;

    case CPUID_EXT_FEATURES_LEAF:
        switch (ExitContext->CpuidAccess.Rcx) {
        case 0:
            ExitContext->CpuidAccess.DefaultResultRax = 2;
            ExitContext->CpuidAccess.DefaultResultRcx |=
                CPUID_0_07_ECX_BUS_LOCK_DETECT |
                CPUID_0_07_ECX_PKS;
            ExitContext->CpuidAccess.DefaultResultRdx |=
                CPUID_0_07_EDX_MD_CLEAR |
                CPUID_0_07_EDX_ARCH_LBR |
                CPUID_0_07_EDX_L1D_FLUSH |
                CPUID_0_07_EDX_CORE_CAP;
            ExitContext->CpuidAccess.DefaultResultRbx |=
                CPUID_0_07_EBX_FDPEXONLY;

            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
            break;
        case 1:
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
            break;
        case 2:
            ExitContext->CpuidAccess.DefaultResultRdx |=
                CPUID_0_07_2_PSFD |
                CPUID_0_07_2_IPRED_CTRL |
                CPUID_0_07_2_RRSBA_CTRL |
                CPUID_0_07_2_BHI_CTRL;

            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
            break;
        default:
            goto NotRecognized;
        }
        break;

    case CPUID_PERFMON_LEAF:
        if (!Vm->CpuSupport.PerfMon) {
            ExitContext->CpuidAccess.DefaultResultRax =
                (5ULL << 0) |   // Version 5
                (8ULL << 8);    // 8 counters per LP
            ExitContext->CpuidAccess.DefaultResultRcx = 0;
            ExitContext->CpuidAccess.DefaultResultRdx = 1ULL << 15; // AnyThread deprecated
            ExitContext->CpuidAccess.DefaultResultRbx = 0;
        }

        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
        break;

    case 8: // Reserved, zero
    case CPUID_EXT_STATE_ENUM_LEAF:
    case 0xe: // Reserved, zero
    case 0x11:
    case 0x12:
    case 0x13:
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
        break;

    case 0x14:
        switch (ExitContext->CpuidAccess.Rcx) {
        case 0:
            ExitContext->CpuidAccess.DefaultResultRax = 1; // One sub-leaf
            // FALLTHROUGH
        case 1:
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
            break;
        default:
            goto NotRecognized;
        }
        break;

    case CPUID_TSC_ATTRIBUTES_LEAF:
        ExitContext->CpuidAccess.DefaultResultRax = 1;
        ExitContext->CpuidAccess.DefaultResultRcx = NATIVE_TSC_FREQUENCY_MIN;
        ExitContext->CpuidAccess.DefaultResultRbx = 1;

        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
        break;

    case CPUID_LBR_CAPABILITIES_LEAF:
        ExitContext->CpuidAccess.DefaultResultRax = 1;
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
        break;

    case CPUID_KEYLOCKER_ATTRIBUTES_LEAF:
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
        break;

    case 0x1D:
    case 0x1E:
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23:
    case 0x80000001:
    case 0x80000006:
    case 0x80000007:
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, ExitContext->CpuidAccess.DefaultResultRax);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRcx, ExitContext->CpuidAccess.DefaultResultRcx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, ExitContext->CpuidAccess.DefaultResultRdx);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRbx, ExitContext->CpuidAccess.DefaultResultRbx);
        break;

    default:
NotRecognized:
        LogVcpuErr(Vm, VcpuNum, "Unrecognized CPUID leaf 0x%llx at RIP = 0x%llx\n",
            ExitContext->CpuidAccess.Rax,
            ExitContext->VpContext.Rip);
        return VcpuActionEmulationError;
    }

    AdvanceRip(Vm, VcpuNum, ExitContext);
    return VcpuActionKeepRunning;
}

enum VcpuAction
EmulateRDMSR(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    enum VcpuAction Action;
    ia32_vmx_allowed_bits_t *VmxMsr;
    UINT32 MsrNumber;
    UINT64 MsrValue;

    MsrNumber = REAL_MSR_NUMBER(ExitContext->MsrAccess.MsrNumber);
    MsrValue = 0;

    Action = VcpuActionKeepRunning;

    switch (MsrNumber) {
    case IA32_TSC_ADJ_MSR_ADDR:
    case IA32_SPEC_CTRL_MSR_ADDR:
        MsrValue = 0;
        break;
    case IA32_CORE_CAPABILITIES: {
        if (IsVcpuSeamldr(Vm, VcpuNum)) {
            goto NotRecognized;
        }
        ia32_core_capabilities_t *CoreCaps = (ia32_core_capabilities_t *)&MsrValue;
        CoreCaps->raw = 0;
        break;
    }
    case IA32_ARCH_CAPABILITIES_MSR_ADDR: {
        if (IsVcpuSeamldr(Vm, VcpuNum)) {
            goto NotRecognized;
        }
        ia32_arch_capabilities_t *ArchCaps = (ia32_arch_capabilities_t *)&MsrValue;
        ArchCaps->raw = 0;
        ArchCaps->rdcl_no = 1;
        ArchCaps->irbs_all = 1;
        ArchCaps->rsba = 0;
        ArchCaps->skip_l1dfl_vmentry = 1;
        ArchCaps->mds_no = 1;
        ArchCaps->if_pschange_mc_no = 1;
        ArchCaps->tsx_ctrl = 0;
        ArchCaps->taa_no = 1;
        ArchCaps->misc_package_ctls = 1;
        ArchCaps->energy_filtering_ctl = 1;
        ArchCaps->doitm = 1;
        ArchCaps->sbdr_ssdp_no = 1;
        ArchCaps->fbsdp_no = 1;
        ArchCaps->psdp_no = 1;
        ArchCaps->xapic_disable_status = 1;
        break;
    }
    case IA32_MISC_ENABLES_MSR_ADDR:
        MsrValue = GetVcpuState(Vm, VcpuNum)->MiscEnable;
        break;
    case IA32_PERF_CAPABILITIES_MSR_ADDR: {
        if (IsVcpuSeamldr(Vm, VcpuNum)) {
            goto NotRecognized;
        }
        ia32_perf_capabilities_t *PerfCaps = (ia32_perf_capabilities_t *)&MsrValue;
        PerfCaps->raw = 0;
        PerfCaps->full_write = 1;
        break;
    }
    case IA32_CORE_THREAD_COUNT_MSR_ADDR:
        MsrValue = Vm->NumberOfVcpus;
        break;
    case IA32_MISC_PACKAGE_CTLS_MSR_ADDR: {
        if (IsVcpuSeamldr(Vm, VcpuNum)) {
            goto NotRecognized;
        }
        ia32_misc_package_ctls_t *MiscPackageCtls = (ia32_misc_package_ctls_t *)&MsrValue;
        MiscPackageCtls->raw = 0;
        MiscPackageCtls->energy_filtering_enable = 1;
        break;
    }
    case IA32_XAPIC_DISABLE_STATUS_MSR_ADDR: {
        if (IsVcpuSeamldr(Vm, VcpuNum)) {
            goto NotRecognized;
        }
        ia32_xapic_disable_status_t *XapicDisableStatus = (ia32_xapic_disable_status_t *)&MsrValue;
        XapicDisableStatus->raw = 0;
        XapicDisableStatus->legacy_xapic_disabled = 1;
        break;
    }
    case SMRR_BASE_MSR_ADDR: {
        smrr_base_t *SmrrBase = (smrr_base_t *)&MsrValue;
        SmrrBase->raw = Vm->VmConfig.SmrrBase;
        break;
    }
    case SMRR_MASK_MSR_ADDR: {
        smrr_mask_t *SmrrMask = (smrr_mask_t *)&MsrValue;
        SmrrMask->raw = Vm->VmConfig.SmrrMask;
        SmrrMask->lock = 1;
        SmrrMask->vld = 1;
        break;
    }
    case IA32_SEAMRR_BASE_MSR_ADDR:
        MsrValue = Vm->VmConfig.SeamrrBase;
        break;
    case IA32_SEAMRR_MASK_MSR_ADDR: {
        ia32_seamrr_mask_t *SeamrrMask = (ia32_seamrr_mask_t *)&MsrValue;
        SeamrrMask->raw = 0;
        SeamrrMask->valid = 1;
        SeamrrMask->mask = SEAMRR_SIZE_TO_MASK(Vm->VmConfig.SeamrrSize);
        break;
    }
    case IA32_TME_ACTIVATE_MSR_ADDR: {
        ia32_tme_activate_t *TmeActivate = (ia32_tme_activate_t *)&MsrValue;
        TmeActivate->raw = 0;
        TmeActivate->lock = 1;
        TmeActivate->tme_enable = 1;
        TmeActivate->mk_tme_keyid_bits = Vm->VmConfig.KeyidBits;
        TmeActivate->algs_aes_xts_128 = 1;
        TmeActivate->algs_aes_xts_128_with_integrity = 1;
        TmeActivate->algs_aes_xts_256 = 1;
        TmeActivate->algs_aes_xts_256_with_integrity = 1;
        break;
    }
    case IA32_TME_CAPABILITY_MSR_ADDR: {
        ia32_tme_capability_t *TmeCapability = (ia32_tme_capability_t *)&MsrValue;
        TmeCapability->raw = 0;
        TmeCapability->aes_xts_128 = 1;
        TmeCapability->aes_xts_128_with_integrity = 1;
        TmeCapability->aes_xts_256 = 1;
        TmeCapability->aes_xts_256_with_integrity = 1;
        TmeCapability->mk_tme_max_keyid_bits = Vm->VmConfig.KeyidBits;
        TmeCapability->mk_tme_max_keys = (1ULL << Vm->VmConfig.KeyidBits) - 1;
        break;
    }
    case IA32_MKTME_KEYID_PARTITIONING_MSR_ADDR: {
        ia32_tme_keyid_partitioning_t *TmeKeyidPartitioning = (ia32_tme_keyid_partitioning_t *)&MsrValue;
        TmeKeyidPartitioning->raw = 0;
        TmeKeyidPartitioning->num_mktme_kids = (1 << Vm->VmConfig.KeyidBits) - Vm->VmConfig.NumPrivKeyids - 1;
        TmeKeyidPartitioning->num_tdx_priv_kids = Vm->VmConfig.NumPrivKeyids;
        break;
    }
    case IA32_WBINVDP_MSR_ADDR:
    case IA32_WBNOINVDP_MSR_ADDR:
        MsrValue = 8; // Arbitrary
        break;
    case MTRR_CAP_MSR_ADDR: {
        ia32_mtrrcap_t *MtrrCap = (ia32_mtrrcap_t *)&MsrValue;
        MtrrCap->raw = 0;
        MtrrCap->smrr = 1;
        MtrrCap->smrr_lock = 1;
        break;
    }
    case IA32_VMX_BASIC_MSR_ADDR: {
        ia32_vmx_basic_t *VmxBasic = (ia32_vmx_basic_t *)&MsrValue;
        VmxBasic->raw = 0;
        VmxBasic->vmcs_revision_id = 1;
        VmxBasic->vmcs_region_size = _2KB;
        VmxBasic->vmexit_info_on_ios = 1;
        VmxBasic->ia32_vmx_true_available = 1;
        break;
    }
    case IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR:
        VmxMsr = (ia32_vmx_allowed_bits_t *)&MsrValue;
        VmxMsr->not_allowed0 = 0x00000029;
        VmxMsr->allowed1 = VmxMsr->not_allowed0 | 0x00000080;
        break;
    case IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR:
        VmxMsr = (ia32_vmx_allowed_bits_t *)&MsrValue;
        VmxMsr->not_allowed0 = 0x91020088;
        VmxMsr->allowed1 = VmxMsr->not_allowed0 | 0x68F81E04;
        break;
    case IA32_VMX_PROCBASED_CTLS2_MSR_ADDR:
        VmxMsr = (ia32_vmx_allowed_bits_t *)&MsrValue;
        VmxMsr->not_allowed0 = 0;
        VmxMsr->allowed1 = 0xFFFFFFFF;
        break;
    case IA32_VMX_PROCBASED_CTLS3_MSR_ADDR:
        MsrValue = 0xFFFFFFFFFFFFFFFFULL;
        break;
    case IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR:
        VmxMsr = (ia32_vmx_allowed_bits_t *)&MsrValue;
        VmxMsr->not_allowed0 = 0x1F3C8204;
        VmxMsr->allowed1 = VmxMsr->not_allowed0 | 0x40001000;
        break;
    case IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR:
        VmxMsr = (ia32_vmx_allowed_bits_t *)&MsrValue;
        VmxMsr->not_allowed0 = 0x003EC004;
        VmxMsr->allowed1 = VmxMsr->not_allowed0 | 0x00402200;
        break;
    case IA32_VMX_EPT_VPID_CAP_MSR_ADDR:
        MsrValue = 0x10106334041;
        break;
    case IA32_VMX_MISC_MSR_ADDR: {
        ia32_vmx_misc_t *VmxMisc = (ia32_vmx_misc_t *)&MsrValue;
        VmxMisc->raw = 0;
        VmxMisc->unrestricted_guest = 1;
        VmxMisc->activity_hlt = 1;
        VmxMisc->activity_shutdown = 1;
        VmxMisc->pt_in_vmx = 1;
        VmxMisc->max_cr3_targets = 4;
        VmxMisc->vmwrite_any_vmcs_field = 1;
        break;
    }
    case IA32_VMX_CR0_FIXED0_MSR_ADDR:
        MsrValue = 0x20;
        break;
    case IA32_VMX_CR0_FIXED1_MSR_ADDR:
        MsrValue = 0x8005003f;
        break;
    case IA32_VMX_CR4_FIXED0_MSR_ADDR:
    case IA32_VMX_CR4_FIXED1_MSR_ADDR:
        MsrValue = 0x00002040;
        break;
    case IA32_DS_AREA_MSR_ADDR:
        MsrValue = GetVcpuState(Vm, VcpuNum)->DsArea;
        break;
    case NON_FAULTING_MSR_ADDR:
        MsrValue = GetVcpuState(Vm, VcpuNum)->NonFaultingMsr;
        break;
    case IA32_UARCH_MISC_CTL_MSR_ADDR:
        MsrValue = 0;
        break;
    case IA32_TSC_AUX_MSR_ADDR:
        MsrValue = GetVcpuState(Vm, VcpuNum)->TscAux;
        break;
    case IA32_STAR_MSR_ADDR:
        MsrValue = GetVcpuState(Vm, VcpuNum)->Star;
        break;
    case IA32_LSTAR_MSR_ADDR:
        MsrValue = GetVcpuState(Vm, VcpuNum)->Lstar;
        break;
    case IA32_FMASK_MSR_ADDR:
        MsrValue = GetVcpuState(Vm, VcpuNum)->Fmask;
        break;
    case IA32_KERNEL_GS_BASE_MSR_ADDR:
        MsrValue = GetVcpuState(Vm, VcpuNum)->KernelGsBase;
        break;
    case IA32_XSS_MSR_ADDR:
        MsrValue = GetVcpuState(Vm, VcpuNum)->Xss;
        break;
    default:
NotRecognized:
        LogVcpuErr(Vm, VcpuNum, "Unrecognized RDMSR 0x%x at RIP = 0x%llx\n",
            MsrNumber,
            ExitContext->VpContext.Rip);
        Action = VcpuActionEmulationError;
        break;
    }

    if (Action == VcpuActionKeepRunning) {
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, MsrValue & 0xFFFFFFFF);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRdx, MsrValue >> 32);
        AdvanceRip(Vm, VcpuNum, ExitContext);
    }

    return Action;
}

enum VcpuAction
EmulateWRMSR(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    enum VcpuAction Action;
    UINT32 MsrNumber;
    UINT64 MsrValue;
    BOOLEAN DoAdvance;

    DoAdvance = TRUE;

    MsrNumber = REAL_MSR_NUMBER(ExitContext->MsrAccess.MsrNumber);

    MsrValue = (ExitContext->MsrAccess.Rax & 0xFFFFFFFF) |
        (ExitContext->MsrAccess.Rdx << 32ULL);

    Action = VcpuActionKeepRunning;

    switch (MsrNumber) {
    case MSR_SANCOV_PARAMS:
        if (!Vm->VmConfig.HasSanitizers) {
            goto NotRecognized;
        }
        Action = MsrSancovParams(Vm, VcpuNum, MsrValue);
        break;
    case MSR_ASAN_REPORT:
        if (!Vm->VmConfig.HasSanitizers) {
            goto NotRecognized;
        }
        Action = MsrAsanReport(Vm, VcpuNum, MsrValue);
        break;
    case MSR_UBSAN_REPORT:
        if (!Vm->VmConfig.HasSanitizers) {
            goto NotRecognized;
        }
        Action = MsrUbsanReport(Vm, VcpuNum, MsrValue);
        break;
    case IA32_PRED_CMD_MSR_ADDR:
    case IA32_SPEC_CTRL_MSR_ADDR:
        break;
    case IA32_MISC_ENABLES_MSR_ADDR:
        GetVcpuState(Vm, VcpuNum)->MiscEnable = MsrValue;
        break;
    case IA32_SEAMEXTEND_MSR_ADDR:
        Action = MsrSeamExtend(Vm, VcpuNum, MsrValue);
        break;
    case IA32_UARCH_MISC_CTL_MSR_ADDR:
        if ((MsrValue & ~__BIT(0)) != 0) {
            SetPendingException(Vm, VcpuNum, WHvX64ExceptionTypeGeneralProtectionFault);
            DoAdvance = FALSE;
        }
        break;
    case MSR_SEAMVM_DEBUG:
        LogVcpuOk(Vm, VcpuNum, "Debug: 0x%llx\n", MsrValue);
        break;
    case IA32_DS_AREA_MSR_ADDR:
        GetVcpuState(Vm, VcpuNum)->DsArea = MsrValue;
        break;
    case NON_FAULTING_MSR_ADDR:
        GetVcpuState(Vm, VcpuNum)->NonFaultingMsr = MsrValue;
        break;
    case IA32_TSC_AUX_MSR_ADDR:
        GetVcpuState(Vm, VcpuNum)->TscAux = MsrValue;
        break;
    case IA32_STAR_MSR_ADDR:
        GetVcpuState(Vm, VcpuNum)->Star = MsrValue;
        break;
    case IA32_LSTAR_MSR_ADDR:
        GetVcpuState(Vm, VcpuNum)->Lstar = MsrValue;
        break;
    case IA32_FMASK_MSR_ADDR:
        GetVcpuState(Vm, VcpuNum)->Fmask = MsrValue;
        break;
    case IA32_KERNEL_GS_BASE_MSR_ADDR:
        GetVcpuState(Vm, VcpuNum)->KernelGsBase = MsrValue;
        break;
    case IA32_XSS_MSR_ADDR:
        GetVcpuState(Vm, VcpuNum)->Xss = MsrValue;
        break;
    default:
NotRecognized:
        LogVcpuErr(Vm, VcpuNum, "Unrecognized WRMSR 0x%x at RIP = 0x%llx, Value = 0x%llx\n",
            MsrNumber,
            ExitContext->VpContext.Rip,
            MsrValue);
        Action = VcpuActionEmulationError;
        break;
    }

    if (Action == VcpuActionKeepRunning && DoAdvance) {
        AdvanceRip(Vm, VcpuNum, ExitContext);
    }

    return Action;
}

static enum VcpuAction
EmulateSEAMRET(CORNELIUS_VM *Vm, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    UNREFERENCED_PARAMETER(Vm);
    UNREFERENCED_PARAMETER(ExitContext);
    return VcpuActionSeamRet;
}

static enum VcpuAction
EmulateSEAMOPS(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    enum VcpuAction Action;
    UINT64 Rflags;
    UINT64 Leaf;
    UINT64 Value;

#define SEAMOPS_SUCCESS                    0
#define SEAMOPS_INPUT_ERROR                1
#define SEAMOPS_ENTROPY_ERROR              2
#define SEAMOPS_DATABASE_ERROR             3

#define SEAMOPS_CAPABILITIES_LEAF          0
#define SEAMOPS_SEAMREPORT_LEAF            1
#define SEAMOPS_SEAMDB_CLEAR_LEAF          2
#define SEAMOPS_SEAMDB_INSERT_LEAF         3
#define SEAMOPS_SEAMDB_GETREF_LEAF         4
#define SEAMOPS_SEAMDB_REPORT_LEAF         5

    Leaf = GetRegister64(Vm, VcpuNum, WHvX64RegisterRax);

    switch (Leaf) {
    case SEAMOPS_CAPABILITIES_LEAF:
        // XXX: incomplete
        Value =
            (1 << SEAMOPS_SEAMDB_GETREF_LEAF) |
            (1 << SEAMOPS_SEAMDB_REPORT_LEAF);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, Value);
        Action = VcpuActionKeepRunning;
        break;
    case SEAMOPS_SEAMDB_CLEAR_LEAF:
        // XXX: incomplete
        Vm->SeamdbIndex = 0;
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, SEAMOPS_SUCCESS);
        Action = VcpuActionKeepRunning;
        break;
    case SEAMOPS_SEAMDB_INSERT_LEAF:
        // XXX: incomplete
        if (Vm->SeamdbIndex == Vm->VmConfig.SeamdbSize) {
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, SEAMOPS_DATABASE_ERROR);
        } else {
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, SEAMOPS_SUCCESS);
            Vm->SeamdbIndex += 1;
        }
        Action = VcpuActionKeepRunning;
        break;
    case SEAMOPS_SEAMDB_GETREF_LEAF:
        Rflags = ExitContext->VpContext.Rflags;

        Rflags &= ~(
            (1 << 0) |    // CF
            (1 << 2) |    // PF
            (1 << 4) |    // AF
            (1 << 7) |    // SF
            (1 << 11)     // OF
        );

        if (Vm->SeamdbIndex == 0) {
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, SEAMOPS_DATABASE_ERROR);
            Rflags |= (1ULL << 6);     // ZF
        } else {
            SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, SEAMOPS_SUCCESS);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterR10, Vm->SeamdbIndex - 1);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterR11, 0);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterR12, 0);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterR13, 0);
            SetRegister64(Vm, VcpuNum, WHvX64RegisterR14, 0);
            Rflags &= ~(1ULL << 6);    // ZF
        }

        SetRegister64(Vm, VcpuNum, WHvX64RegisterR15, Vm->VmConfig.SeamdbSize);
        SetRegister64(Vm, VcpuNum, WHvX64RegisterRflags, Rflags);

        Action = VcpuActionKeepRunning;
        break;
    default:
        LogVcpuErr(Vm, VcpuNum, "Unrecognized SEAMOPS leaf 0x%llx at RIP = 0x%llx\n",
            Leaf,
            ExitContext->VpContext.Rip);
        Action = VcpuActionEmulationError;
        break;
    }

    if (Action == VcpuActionKeepRunning) {
        AdvanceRipBy(Vm, VcpuNum, ExitContext, 4);
    }

    return Action;
}

static enum VcpuAction
EmulateSERIALIZE(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    //
    // This is here only because not all machines support SERIALIZE.
    //

    AdvanceRipBy(Vm, VcpuNum, ExitContext, 3);
    return VcpuActionKeepRunning;
}

static enum VcpuAction
EmulateINVEPT(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    UINT64 AdvanceBy;

    // 66 0F 38 80 54 24 20     invept 0x20(%rsp),%rdx
    if (ExitContext->VpException.InstructionByteCount >= 7 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x0f\x38\x80\x54\x24\x20", 7)) {
        AdvanceBy = 7;
    }
    // 66 0f 38 80 44 24 NN 	invept NN(%rsp),%rax
    else if (ExitContext->VpException.InstructionByteCount >= 7 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x0f\x38\x80\x44\x24", 6)) {
        AdvanceBy = 7;
    }
    // 66 44 0f 38 80 5c 24 NN	invept NN(%rsp),%r11
    else if (ExitContext->VpException.InstructionByteCount >= 8 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x44\x0f\x38\x80\x5c\x24", 7)) {
        AdvanceBy = 8;
    }
    // 66 0f 38 80 84 24 NN NN NN NN 	invept NN(%rsp),%rax
    else if (ExitContext->VpException.InstructionByteCount >= 10 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x0f\x38\x80\x84\x24", 6)) {
        AdvanceBy = 10;
    }
    // 66 44 0f 38 80 ac 24 NN NN NN NN 	invept NN(%rsp),%r13
    else if (ExitContext->VpException.InstructionByteCount >= 11 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x44\x0f\x38\x80\xac\x24", 7)) {
        AdvanceBy = 11;
    }
    else {
        LogVcpuErr(Vm, VcpuNum, "Unrecognized INVEPT on #UD at RIP = 0x%llx\n",
            ExitContext->VpContext.Rip);
        return VcpuActionEmulationError;
    }

    VmSucceed(Vm, VcpuNum);
    AdvanceRipBy(Vm, VcpuNum, ExitContext, AdvanceBy);
    return VcpuActionKeepRunning;
}

static enum VcpuAction
EmulatePCONFIG(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    mktme_key_program_t *MktmeKeyProgram;
    UINT64 Rflags;
    UINT64 Rax;
    UINT64 Rbx;

    Rax = GetRegister64(Vm, VcpuNum, WHvX64RegisterRax);
    Rbx = GetRegister64(Vm, VcpuNum, WHvX64RegisterRbx);

    if (Rax != 0) {
        LogVcpuErr(Vm, VcpuNum, "Unrecognized PCONFIG on #UD at RIP = 0x%llx\n",
            ExitContext->VpContext.Rip);
        return VcpuActionEmulationError;
    }
    if (Rbx % 256 != 0) {
        LogVcpuErr(Vm, VcpuNum, "RBX unaligned on PCONFIG at RIP = 0x%llx\n",
            ExitContext->VpContext.Rip);
        return VcpuActionEmulationError;
    }

    MktmeKeyProgram = (mktme_key_program_t *)GvaToHva(Vm, VcpuNum, Rbx);

    if (!InvariantsOnPCONFIG(Vm, VcpuNum, MktmeKeyProgram)) {
        return VcpuActionInvariantViolated;
    }

    MapCmrsInKeyidSpace(Vm, MktmeKeyProgram->keyid);

    Vm->KeyidActive |= (1UL << MktmeKeyProgram->keyid);

    SetRegister64(Vm, VcpuNum, WHvX64RegisterRax, 0);

    Rflags = ExitContext->VpContext.Rflags;

    Rflags &= ~(
        (1 << 0) |    // CF
        (1 << 2) |    // PF
        (1 << 4) |    // AF
        (1 << 6) |    // ZF
        (1 << 7) |    // SF
        (1 << 11)     // OF
    );

    SetRegister64(Vm, VcpuNum, WHvX64RegisterRflags, Rflags);

    AdvanceRipBy(Vm, VcpuNum, ExitContext, 3);
    return VcpuActionKeepRunning;
}

enum VcpuAction
EmulateOnUD(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    if (ExitContext->VpException.InstructionByteCount >= 5 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0f\x78", 2)) {
        return EmulateVMREAD(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 4 &&
        IsRexPrefix(ExitContext->VpException.InstructionBytes[0]) &&
        !memcmp(ExitContext->VpException.InstructionBytes + 1, "\x0f\x78", 2)) {
        return EmulateVMREAD(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 3 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0f\x79", 2)) {
        return EmulateVMWRITE(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 4 &&
        IsRexPrefix(ExitContext->VpException.InstructionBytes[0]) &&
        !memcmp(ExitContext->VpException.InstructionBytes + 1, "\x0f\x79", 2)) {
        return EmulateVMWRITE(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 2 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0f\xc7", 2)) {
        return EmulateVMPTRLD(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 3 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x0f\xc7", 3)) {
        return EmulateVMCLEAR(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 3 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0f\x01\xc2", 3)) {
        return EmulateVMLAUNCH(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 3 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0f\x01\xc3", 3)) {
        return EmulateVMRESUME(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 2 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0f\x0b", 2)) {
        return EmulateUD2(Vm, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 4 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x0f\x01\xcd", 4)) {
        return EmulateSEAMRET(Vm, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 4 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x0f\x01\xce", 4)) {
        return EmulateSEAMOPS(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 3 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0f\x01\xe8", 3)) {
        return EmulateSERIALIZE(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 4 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x0f\x38\x80", 4)) {
        return EmulateINVEPT(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 7 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x44\x0f\x38\x80\x5c\x24", 7)) {
        return EmulateINVEPT(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 7 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x66\x44\x0f\x38\x80\xac\x24", 7)) {
        return EmulateINVEPT(Vm, VcpuNum, ExitContext);
    }
    if (ExitContext->VpException.InstructionByteCount >= 3 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0f\x01\xc5", 3)) {
        return EmulatePCONFIG(Vm, VcpuNum, ExitContext);
    }

    LogVcpuErr(Vm, VcpuNum, "Unrecognized instruction on #UD at RIP = 0x%llx\n",
        ExitContext->VpContext.Rip);

    return VcpuActionEmulationError;
}

enum VcpuAction
EmulateOnGP(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    UINT32 MsrNumber;

    //
    // HV-DISCREPANCY: Hyper-V injects #GPs on VMX MSRs, without forwarding the
    // VMEXITs to us.
    //

    if (ExitContext->VpException.InstructionByteCount >= 2 &&
        !memcmp(ExitContext->VpException.InstructionBytes, "\x0f\x32", 2)) {
        MsrNumber = (UINT32)GetRegister64(Vm, VcpuNum, WHvX64RegisterRcx);

        switch (MsrNumber) {
        case IA32_VMX_BASIC_MSR_ADDR:
        case IA32_VMX_PINBASED_CTLS_MSR_ADDR:
        case IA32_VMX_PROCBASED_CTLS_MSR_ADDR:
        case IA32_VMX_EXIT_CTLS_MSR_ADDR:
        case IA32_VMX_ENTRY_CTLS_MSR_ADDR:
        case IA32_VMX_EPT_VPID_CAP_MSR_ADDR:
        case IA32_VMX_MISC_MSR_ADDR:
        case IA32_VMX_CR0_FIXED0_MSR_ADDR:
        case IA32_VMX_CR0_FIXED1_MSR_ADDR:
        case IA32_VMX_CR4_FIXED0_MSR_ADDR:
        case IA32_VMX_CR4_FIXED1_MSR_ADDR:
        case IA32_VMX_PROCBASED_CTLS2_MSR_ADDR:
        case IA32_VMX_TRUE_PINBASED_CTLS_MSR_ADDR:
        case IA32_VMX_TRUE_PROCBASED_CTLS_MSR_ADDR:
        case IA32_VMX_TRUE_EXIT_CTLS_MSR_ADDR:
        case IA32_VMX_TRUE_ENTRY_CTLS_MSR_ADDR:
        case IA32_VMX_PROCBASED_CTLS3_MSR_ADDR:
            // Initialize the ExitContext fields based on the current state.
            ExitContext->MsrAccess.MsrNumber = MsrNumber;
            ExitContext->VpContext.InstructionLength = 2;
            return EmulateRDMSR(Vm, VcpuNum, ExitContext);
        default:
            break;
        }
    }

    LogVcpuErr(Vm, VcpuNum, "Unrecognized instruction on #GP at RIP = 0x%llx, Opcode = 0x%x\n",
        ExitContext->VpContext.Rip,
        ExitContext->VpException.InstructionBytes[0]);

    return VcpuActionEmulationError;
}

enum VcpuAction
EmulateOnIO(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext)
{
    DBG_LOG_BUFFER *DbgLogBuffer = &Vm->Vcpus[VcpuNum].DbgLogBuffer;
    CHAR LogChar;

    switch (ExitContext->IoPortAccess.PortNumber) {
    case 0x3f8:
        LogChar = ExitContext->IoPortAccess.Rax & 0xff;

        // Flush if needed
        if (LogChar == '\n' || DbgLogBuffer->Cursor >= MAX_LOG_CHACHE_SIZE) {
            LogVcpuTdxDebug(Vm, VcpuNum, "%s\n", DbgLogBuffer->Buffer);
            DbgLogBuffer->Cursor = 0;
            memset(DbgLogBuffer->Buffer, 0, sizeof(DbgLogBuffer->Buffer));
        }
        if (LogChar != '\n') {
            DbgLogBuffer->Buffer[DbgLogBuffer->Cursor] = LogChar;
            DbgLogBuffer->Cursor++;
        }
        break;
    case 0x3f9:
    case 0x3fa:
    case 0x3fb:
    case 0x3fc:
    case 0x3fd:
    case 0x3ff:
    case 0x80:
        // Ignore
        break;
    default:
        LogVcpuErr(Vm, VcpuNum, "Unrecognized IO port access on port 0x%llx at RIP = 0x%llx\n",
            ExitContext->IoPortAccess.PortNumber,
            ExitContext->VpContext.Rip);
        return VcpuActionEmulationError;
    }

    AdvanceRip(Vm, VcpuNum, ExitContext);
    return VcpuActionKeepRunning;
}
