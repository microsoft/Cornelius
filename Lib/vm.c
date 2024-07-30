// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "common.h"

#pragma comment(lib, "WinHvPlatform.lib")

UINT64
GetRegister64(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_REGISTER_NAME Name)
{
    WHV_REGISTER_VALUE Value;
    HRESULT hRes;

    hRes = WHvGetVirtualProcessorRegisters(Vm->Partition, VcpuNum,
        &Name, 1, &Value);
    FAIL_IF_ERROR(hRes);

    return Value.Reg64;
}

VOID
SetRegister64(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_REGISTER_NAME Name, UINT64 Val64)
{
    WHV_REGISTER_VALUE Value;
    HRESULT hRes;

    ZeroMemory(&Value, sizeof(Value));
    Value.Reg64 = Val64;

    hRes = WHvSetVirtualProcessorRegisters(Vm->Partition, VcpuNum,
        &Name, 1, &Value);
    FAIL_IF_ERROR(hRes);
}

VOID
MarkGpaNotDirty(CORNELIUS_VM *Vm, UINT64 Gpa, SIZE_T Size)
{
    PUINT64 Bitmap = Vm->DirtyGpasBitmap;
    SIZE_T GpaOff;
    SIZE_T GpaBit;
    SIZE_T i;

    Gpa = GPA_WITHOUT_HKID(Gpa);

    for (i = 0; i < Size; i += PAGE_SIZE) {
        GpaOff = ((Gpa + i) / PAGE_SIZE) / 64ULL;
        GpaBit = ((Gpa + i) / PAGE_SIZE) % 64ULL;

        _InterlockedAnd64((LONG64 *)&Bitmap[GpaOff], ~(1ULL << GpaBit));
    }
}

static VOID
MarkGpaDirty(CORNELIUS_VM *Vm, UINT64 Gpa, SIZE_T Size)
{
    PUINT64 Bitmap = Vm->DirtyGpasBitmap;
    SIZE_T GpaOff;
    SIZE_T GpaBit;
    SIZE_T i;

    Gpa = GPA_WITHOUT_HKID(Gpa);

    for (i = 0; i < Size; i += PAGE_SIZE) {
        GpaOff = ((Gpa + i) / PAGE_SIZE) / 64ULL;
        GpaBit = ((Gpa + i) / PAGE_SIZE) % 64ULL;

        _InterlockedOr64((LONG64 *)&Bitmap[GpaOff], 1ULL << GpaBit);
    }
}

static VOID
MarkGpaMapped(CORNELIUS_VM *Vm, UINT64 Gpa, SIZE_T Size)
{
    PUINT64 Bitmap = Vm->MappedGpasBitmap;
    SIZE_T GpaOff;
    SIZE_T GpaBit;
    SIZE_T i;

    //
    // Note: we only track GPAs in Keyid 0.
    //

    if (Gpa >= Vm->LastPa) {
        return;
    }

    for (i = 0; i < Size; i += PAGE_SIZE) {
        GpaOff = ((Gpa + i) / PAGE_SIZE) / 64ULL;
        GpaBit = ((Gpa + i) / PAGE_SIZE) % 64ULL;

        _InterlockedOr64((LONG64 *)&Bitmap[GpaOff], 1ULL << GpaBit);
    }
}

static VOID
MarkGpaUnmapped(CORNELIUS_VM *Vm, UINT64 Gpa, SIZE_T Size)
{
    PUINT64 Bitmap = Vm->MappedGpasBitmap;
    SIZE_T GpaOff;
    SIZE_T GpaBit;
    SIZE_T i;

    if (Gpa >= Vm->LastPa) {
        return;
    }

    for (i = 0; i < Size; i += PAGE_SIZE) {
        GpaOff = ((Gpa + i) / PAGE_SIZE) / 64ULL;
        GpaBit = ((Gpa + i) / PAGE_SIZE) % 64ULL;

        _InterlockedAnd64((LONG64 *)&Bitmap[GpaOff], ~(1ULL << GpaBit));
    }
}

VOID
MapGpa(CORNELIUS_VM *Vm, UINT64 Gpa, SIZE_T Size)
{
    HRESULT hRes;

    if (GPA_WITHOUT_HKID(Gpa + Size) >= Vm->LastPa) {
        FATAL("GPA_WITHOUT_HKID(Gpa + Size) >= Vm->LastPa");
    }

    Size = ALIGN_UP_BY(Gpa + Size, PAGE_SIZE) - ALIGN_DOWN_BY(Gpa, PAGE_SIZE);
    Gpa = ALIGN_DOWN_BY(Gpa, PAGE_SIZE);

    hRes = WHvMapGpaRange(Vm->Partition,
                          GPA_TO_HVA(Vm, Gpa),
                          Gpa,
                          Size,
                          WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite);
    if (FAILED(hRes)) {
        printf("[!] MapGpa failed with Gpa=0x%llx Size=0x%llx\n", Gpa, Size);
        exit(-1);
    }

    MarkGpaDirty(Vm, Gpa, Size);
    MarkGpaMapped(Vm, Gpa, Size);
}

VOID
MapGpaExecutable(CORNELIUS_VM *Vm, UINT64 Gpa, SIZE_T Size)
{
    HRESULT hRes;

    hRes = WHvMapGpaRange(Vm->Partition,
                          GPA_TO_HVA(Vm, Gpa),
                          Gpa,
                          Size,
                          WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute);
    FAIL_IF_ERROR(hRes);

    MarkGpaDirty(Vm, Gpa, Size);
    MarkGpaMapped(Vm, Gpa, Size);
}

VOID
UnmapGpa(CORNELIUS_VM *Vm, UINT64 Gpa, SIZE_T Size)
{
    HRESULT hRes;

    hRes = WHvUnmapGpaRange(Vm->Partition, Gpa, Size);
    FAIL_IF_ERROR(hRes);

    MarkGpaUnmapped(Vm, Gpa, Size);
}

static VOID
CreateVCPU(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    HRESULT hRes;

    if (VcpuNum >= Vm->NumberOfVcpus) {
        FATAL("VcpuNum too large");
    }

    hRes = WHvCreateVirtualProcessor(Vm->Partition, VcpuNum, 0);
    FAIL_IF_ERROR(hRes);

    InitializeTdxState(Vm, VcpuNum);
    InitializeVcpuState(Vm, VcpuNum);
}

CORNELIUS_VM *
CreateVM(CORNELIUS_VM_CONFIG *VmConfig)
{
    WHV_PARTITION_PROPERTY PartitionProperty;
    WHV_PARTITION_HANDLE Partition;
    WHV_CAPABILITY Capability;
    UINT32 WrittenSizeInBytes;
    CORNELIUS_VM *Vm;
    HRESULT hRes;
    SIZE_T i;

    Vm = malloc(offsetof(CORNELIUS_VM, Vcpus[VmConfig->NumberOfVcpus]));
    if (Vm == NULL) {
        return NULL;
    }

    memset(Vm, 0, offsetof(CORNELIUS_VM, Vcpus[VmConfig->NumberOfVcpus]));
    Vm->NumberOfVcpus = VmConfig->NumberOfVcpus;
    memcpy(&Vm->VmConfig, VmConfig, sizeof(*VmConfig));

    //
    // Create the partition.
    //

    hRes = WHvCreatePartition(&Partition);
    FAIL_IF_ERROR(hRes);

    //
    // Set the processor features.
    //

    hRes = WHvGetCapability(WHvCapabilityCodeProcessorFeatures, &Capability, sizeof(Capability), &WrittenSizeInBytes);
    FAIL_IF_ERROR(hRes);
    if (WrittenSizeInBytes != sizeof(Capability.ProcessorFeatures)) {
        FATAL("WrittenSizeInBytes too small");
    }

    memset(&PartitionProperty, 0, sizeof(PartitionProperty));
    PartitionProperty.ProcessorFeatures = Capability.ProcessorFeatures;
    hRes = WHvSetPartitionProperty(Partition, WHvPartitionPropertyCodeProcessorFeatures, &PartitionProperty, sizeof(PartitionProperty));
    FAIL_IF_ERROR(hRes);

    //
    // Set the perfmon features.
    //

    hRes = WHvGetCapability(WHvCapabilityCodeProcessorPerfmonFeatures, &Capability, sizeof(Capability), &WrittenSizeInBytes);
    FAIL_IF_ERROR(hRes);
    if (WrittenSizeInBytes != sizeof(Capability.ProcessorPerfmonFeatures)) {
        FATAL("WrittenSizeInBytes too small");
    }

    memset(&PartitionProperty, 0, sizeof(PartitionProperty));
    PartitionProperty.ProcessorPerfmonFeatures = Capability.ProcessorPerfmonFeatures;
    hRes = WHvSetPartitionProperty(Partition, WHvPartitionPropertyCodeProcessorPerfmonFeatures, &PartitionProperty, sizeof(PartitionProperty));
    FAIL_IF_ERROR(hRes);

    Vm->CpuSupport.PerfMon = Capability.ProcessorPerfmonFeatures.PmuSupport != 0;

    //
    // Set the processor features banks.
    //

    hRes = WHvGetCapability(WHvCapabilityCodeProcessorFeaturesBanks, &Capability, sizeof(Capability), &WrittenSizeInBytes);
    FAIL_IF_ERROR(hRes);
    if (WrittenSizeInBytes != sizeof(Capability.ProcessorFeaturesBanks)) {
        FATAL("WrittenSizeInBytes too small");
    }

    if (!Capability.ProcessorFeaturesBanks.Bank1.CetSsSupport) {
        FATAL("CET_SS must be supported by the CPU");
    }
    if (!Capability.ProcessorFeaturesBanks.Bank1.CetIbtSupport) {
        FATAL("CET_IBT must be supported by the CPU");
    }

    memset(&PartitionProperty, 0, sizeof(PartitionProperty));
    PartitionProperty.ProcessorFeaturesBanks = Capability.ProcessorFeaturesBanks;
    hRes = WHvSetPartitionProperty(Partition, WHvPartitionPropertyCodeProcessorFeaturesBanks, &PartitionProperty, sizeof(PartitionProperty));
    FAIL_IF_ERROR(hRes);

    //
    // Set the processor XSAVE features.
    //

    hRes = WHvGetCapability(WHvCapabilityCodeProcessorXsaveFeatures, &Capability, sizeof(Capability), &WrittenSizeInBytes);
    FAIL_IF_ERROR(hRes);
    if (WrittenSizeInBytes != sizeof(Capability.ProcessorXsaveFeatures)) {
        FATAL("WrittenSizeInBytes too small");
    }

    memset(&PartitionProperty, 0, sizeof(PartitionProperty));
    PartitionProperty.ProcessorXsaveFeatures = Capability.ProcessorXsaveFeatures;
    hRes = WHvSetPartitionProperty(Partition, WHvPartitionPropertyCodeProcessorXsaveFeatures, &PartitionProperty, sizeof(PartitionProperty));
    FAIL_IF_ERROR(hRes);

    //
    // Set the partition properties.
    //

    memset(&PartitionProperty, 0, sizeof(PartitionProperty));
    PartitionProperty.ProcessorCount = Vm->NumberOfVcpus;
    hRes = WHvSetPartitionProperty(Partition, WHvPartitionPropertyCodeProcessorCount, &PartitionProperty, sizeof(PartitionProperty));
    FAIL_IF_ERROR(hRes);

    memset(&PartitionProperty, 0, sizeof(PartitionProperty));
    PartitionProperty.ExtendedVmExits.X64CpuidExit = 1;
    PartitionProperty.ExtendedVmExits.X64MsrExit = 1;
    PartitionProperty.ExtendedVmExits.ExceptionExit = 1;
    hRes = WHvSetPartitionProperty(Partition, WHvPartitionPropertyCodeExtendedVmExits, &PartitionProperty, sizeof(PartitionProperty));
    FAIL_IF_ERROR(hRes);

    memset(&PartitionProperty, 0, sizeof(PartitionProperty));
    // HV-DISCREPANCY: no way to specify #CP here
    PartitionProperty.ExceptionExitBitmap =
        (1 << WHvX64ExceptionTypeDivideErrorFault) |
        (1 << WHvX64ExceptionTypeDebugTrapOrFault) |
        (1 << WHvX64ExceptionTypeBreakpointTrap) |
        (1 << WHvX64ExceptionTypeOverflowTrap) |
        (1 << WHvX64ExceptionTypeBoundRangeFault) |
        (1 << WHvX64ExceptionTypeInvalidOpcodeFault) |
        (1 << WHvX64ExceptionTypeDeviceNotAvailableFault) |
        (1 << WHvX64ExceptionTypeDoubleFaultAbort) |
        (1 << WHvX64ExceptionTypeInvalidTaskStateSegmentFault) |
        (1 << WHvX64ExceptionTypeSegmentNotPresentFault) |
        (1 << WHvX64ExceptionTypeStackFault) |
        (1 << WHvX64ExceptionTypeGeneralProtectionFault) |
        (1 << WHvX64ExceptionTypePageFault) |
        (1 << WHvX64ExceptionTypeFloatingPointErrorFault) |
        (1 << WHvX64ExceptionTypeAlignmentCheckFault) |
        (1 << WHvX64ExceptionTypeMachineCheckAbort) |
        (1 << WHvX64ExceptionTypeSimdFloatingPointFault);
    hRes = WHvSetPartitionProperty(Partition, WHvPartitionPropertyCodeExceptionExitBitmap, &PartitionProperty, sizeof(PartitionProperty));
    FAIL_IF_ERROR(hRes);

    memset(&PartitionProperty, 0, sizeof(PartitionProperty));
    PartitionProperty.X64MsrExitBitmap.UnhandledMsrs = 1;
    hRes = WHvSetPartitionProperty(Partition, WHvPartitionPropertyCodeX64MsrExitBitmap, &PartitionProperty, sizeof(PartitionProperty));
    FAIL_IF_ERROR(hRes);

    //
    // Conclude the partition setup.
    //

    hRes = WHvSetupPartition(Partition);
    FAIL_IF_ERROR(hRes);

    Vm->Partition = Partition;

    //
    // Adjust the LastPa for the ASAN shadow.
    //

    Vm->HiddenPaCursor = Vm->VmConfig.LastPa;
    Vm->LastPa = Vm->VmConfig.LastPa;

    if (Vm->VmConfig.HasSanitizers) {
        // Add the maximum size of the ASAN shadow
        Vm->LastPa += Vm->VmConfig.PSeamldrRange.Size / 8;
        // Add the maximum size of the SanCov bitmap
        Vm->LastPa += GetSancovMaxBitmapSize(Vm);
    }

    if (Vm->LastPa > CORNELIUS_KEYSPACE_SIZE) {
        FATAL("Vm->LastPa > CORNELIUS_KEYSPACE_SIZE");
    }

    //
    // Create the GPAs bitmaps.
    //

    Vm->DirtyGpasBitmap = calloc(1, GPAS_BITMAP_SIZE(Vm));
    if (Vm->DirtyGpasBitmap == NULL) {
        FATAL("Vm->DirtyGpasBitmap == NULL");
    }

    Vm->MappedGpasBitmap = calloc(1, GPAS_BITMAP_SIZE(Vm));
    if (Vm->MappedGpasBitmap == NULL) {
        FATAL("Vm->MappedGpasBitmap == NULL");
    }

    //
    // Map the CMRs in Keyid 0.
    //

    MapCmrsInKeyidSpace(Vm, 0);

    //
    // Map the AddressSpace HVAs, and the SEAMRR GPAs.
    //

    Vm->AddressSpaceHva = (PUINT8)VirtualAlloc(NULL, Vm->LastPa, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Vm->AddressSpaceHva == NULL) {
        FATAL("Vm->AddressSpaceHva == NULL");
    }

    Vm->SeamrrVa = GPA_TO_HVA(Vm, Vm->VmConfig.SeamrrBase);

    MapGpaExecutable(Vm, Vm->VmConfig.SeamrrBase, Vm->VmConfig.SeamrrSize);

    Vm->IsPseamldrRangeActive = TRUE;

    //
    // Initialize the P-SEAMLDR lock.
    //

    Vm->PseamldrLock = CreateMutex(NULL, FALSE, NULL);

    //
    // Initialize the SEAMRR.
    //

    InitializeSeamRr(Vm);

    //
    // Initialize the SEAMLDR state.
    //

    InitializeSeamldrState(Vm);

    //
    // Create the VCPUs.
    //

    for (i = 0; i < Vm->NumberOfVcpus; i++) {
        CreateVCPU(Vm, (UINT32)i);
    }

    return Vm;
}

INT
GetVcpuLogLevel(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    return Vm->Vcpus[VcpuNum].LogLevel;
}

VOID
SetVcpuLogLevel(CORNELIUS_VM *Vm, UINT32 VcpuNum, INT LogLevel)
{
    Vm->Vcpus[VcpuNum].LogLevel = LogLevel;
}

UINT32
GetNumberOfVcpus(CORNELIUS_VM *Vm)
{
    return Vm->NumberOfVcpus;
}

VOID
SetPendingException(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_EXCEPTION_TYPE ExceptionType)
{
    Vm->Vcpus[VcpuNum].PendingExceptionType = ExceptionType;
    Vm->Vcpus[VcpuNum].HasPendingException = TRUE;
}

static VOID
InjectExceptionIfAny(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    WHV_X64_PENDING_INTERRUPTION_REGISTER Intr;

    if (!Vm->Vcpus[VcpuNum].HasPendingException) {
        return;
    }

    Intr.AsUINT64 = 0;
    Intr.DeliverErrorCode = 1;
    Intr.InterruptionType = WHvX64PendingException;
    Intr.InterruptionPending = 1;
    Intr.InterruptionVector = Vm->Vcpus[VcpuNum].PendingExceptionType;

    Vm->Vcpus[VcpuNum].HasPendingException = FALSE;

    SetRegister64(Vm, VcpuNum, WHvRegisterPendingInterruption, Intr.AsUINT64);
}

static VOID
DumpVCPUCallStack(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    UINT64 Rbp;
    PUINT64 Frame;

    Rbp = GetRegister64(Vm, VcpuNum, WHvX64RegisterRbp);

    while (TRUE) {
        if (Rbp == 0) {
            break;
        }

        Frame = (PUINT64)GvaToHva(Vm, VcpuNum, Rbp);
        LogVcpuErr(Vm, VcpuNum, "> 0x%llx\n", *(Frame+1));
        Rbp = *Frame;
    }
}

enum VcpuAction
RunVCPU(CORNELIUS_VM *Vm, UINT32 VcpuNum, enum VcpuMode VcpuMode)
{
    WHV_RUN_VP_EXIT_CONTEXT ExitContext;
    enum VcpuAction Action;
    HRESULT hRes;

    InstallVcpuState(Vm, VcpuNum);

    if (VcpuMode == VcpuModePseamldr) {
        Vm->Vcpus[VcpuNum].IsSeamldr = TRUE;
    } else {
        if (!Vm->SeamReady) {
            LogVcpuErr(Vm, VcpuNum, "Seam not ready\n");
            return VcpuActionSeamNotReady;
        }
        Vm->Vcpus[VcpuNum].IsSeamldr = FALSE;
    }

    if (VcpuMode == VcpuModePseamldr || VcpuMode == VcpuModeTdxModule) {
        Action = SetEntryVmcsPtr(Vm, VcpuNum);
        if (Action != VcpuActionKeepRunning) {
            return Action;
        }
    }

    if (VcpuMode == VcpuModePseamldr) {
        PseamldrLock(Vm);
        InstallSeamldrState(Vm, VcpuNum);
        SetPseamldrRangeActive(Vm, TRUE);
        LogVcpuOk(Vm, VcpuNum, "Running in P-SEAMLDR mode\n", VcpuNum);
    } else {
        InstallTdxState(Vm, VcpuNum);
        LogVcpuOk(Vm, VcpuNum, "Running in TDX mode\n", VcpuNum);
    }

    Action = VcpuActionKeepRunning;

    while (Action == VcpuActionKeepRunning) {
        InjectExceptionIfAny(Vm, VcpuNum);

        hRes = WHvRunVirtualProcessor(Vm->Partition, VcpuNum, &ExitContext, sizeof(ExitContext));
        FAIL_IF_ERROR(hRes);

        switch (ExitContext.ExitReason) {
        case WHvRunVpExitReasonMemoryAccess:
            LogVcpuErr(Vm, VcpuNum, "WHvRunVpExitReasonMemoryAccess: GPA=0x%llx\n", ExitContext.MemoryAccess.Gpa);
            LogVcpuErr(Vm, VcpuNum, "RIP = %llx\n", GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
            Action = VcpuActionEmulationError;
            break;
        case WHvRunVpExitReasonException:
            switch (ExitContext.VpException.ExceptionType) {
            case WHvX64ExceptionTypeDivideErrorFault:
                LogVcpuErr(Vm, VcpuNum, "Got #DE, RIP = 0x%llx\n", GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                Action = VcpuActionSeamCrash;
                break;
            case WHvX64ExceptionTypeInvalidOpcodeFault:
                Action = EmulateOnUD(Vm, VcpuNum, &ExitContext);
                break;
            case WHvX64ExceptionTypeGeneralProtectionFault:
                Action = EmulateOnGP(Vm, VcpuNum, &ExitContext);
                if (Action == VcpuActionEmulationError) {
                    LogVcpuErr(Vm, VcpuNum, "Got #GP, ErrorCodeValid = %d, ErrorCode = 0x%x\n",
                          ExitContext.VpException.ExceptionInfo.ErrorCodeValid,
                          ExitContext.VpException.ErrorCode);
                    Action = VcpuActionSeamCrash;
                }
                break;
            case WHvX64ExceptionTypePageFault:
                LogVcpuErr(Vm, VcpuNum, "Got #PF, ErrorCodeValid = %d, ErrorCode = 0x%x\n",
                    ExitContext.VpException.ExceptionInfo.ErrorCodeValid,
                    ExitContext.VpException.ErrorCode);
                LogVcpuErr(Vm, VcpuNum, "RIP = %llx\n", GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                Action = VcpuActionSeamCrash;
                break;
            default:
                LogVcpuErr(Vm, VcpuNum, "Got exception %x, ErrorCode=%x\n", ExitContext.VpException.ExceptionType, ExitContext.VpException.ErrorCode);
                LogVcpuErr(Vm, VcpuNum, "RIP = %llx\n", GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
                LogVcpuErr(Vm, VcpuNum, "ErrorCodeValid = %d\n", ExitContext.VpException.ExceptionInfo.ErrorCodeValid);
                Action = VcpuActionSeamCrash;
                break;
            }
            break;
        case WHvRunVpExitReasonX64Cpuid:
            Action = EmulateCPUID(Vm, VcpuNum, &ExitContext);
            break;
        case WHvRunVpExitReasonX64MsrAccess:
            if (ExitContext.MsrAccess.AccessInfo.IsWrite) {
                Action = EmulateWRMSR(Vm, VcpuNum, &ExitContext);
            } else {
                Action = EmulateRDMSR(Vm, VcpuNum, &ExitContext);
            }
            break;
        case WHvRunVpExitReasonX64Halt:
            LogVcpuErr(Vm, VcpuNum, "WHvRunVpExitReasonX64Halt\n");
            Action = VcpuActionEmulationError;
            break;
        case WHvRunVpExitReasonX64IoPortAccess:
            Action = EmulateOnIO(Vm, VcpuNum, &ExitContext);
            break;
        default:
            LogVcpuErr(Vm, VcpuNum, "Unknown vmexit %x\n", ExitContext.ExitReason);
            Action = VcpuActionEmulationError;
            break;
        }
    }

    switch (Action) {
    case VcpuActionEmulationError:
        LogVcpuErr(Vm, VcpuNum, "Emulation error, RIP=%llx, callstack:\n", ExitContext.VpContext.Rip);
        DumpVCPUCallStack(Vm, VcpuNum);
        break;
    case VcpuActionInvariantViolated:
        LogVcpuErr(Vm, VcpuNum, "Invariant violated, callstack:\n");
        DumpVCPUCallStack(Vm, VcpuNum);
        break;
    case VcpuActionSeamPanic:
        LogVcpuErr(Vm, VcpuNum, "Panicked, RIP=%llx, callstack:\n",
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        DumpVCPUCallStack(Vm, VcpuNum);
        break;
    case VcpuActionSeamCrash:
        LogVcpuErr(Vm, VcpuNum, "Crashed, callstack:\n");
        DumpVCPUCallStack(Vm, VcpuNum);
        break;
    case VcpuActionSeamRet:
        LogVcpuOk(Vm, VcpuNum, "Completed with SEAMRET, RIP=%llx, RAX=0x%llx\n",
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip),
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRax));
        if (VcpuMode == VcpuModePseamldr) {
            SyncTdxStateWithVmcs(Vm);
        }
        SyncVcpuStateWithContext(Vm, VcpuNum);
        break;
    case VcpuActionVmlaunch:
        LogVcpuOk(Vm, VcpuNum, "Completed with VMLAUNCH, RIP=%llx, VMCS=0x%llx\n",
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip),
            GetVmcsPtr(Vm, VcpuNum));
        SyncVcpuStateWithContext(Vm, VcpuNum);
        SyncVcpuStateWithTdVmcs(Vm, VcpuNum);
        break;
    case VcpuActionVmresume:
        LogVcpuOk(Vm, VcpuNum, "Completed with VMRESUME, RIP=%llx, VMCS=0x%llx\n",
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip),
            GetVmcsPtr(Vm, VcpuNum));
        SyncVcpuStateWithContext(Vm, VcpuNum);
        SyncVcpuStateWithTdVmcs(Vm, VcpuNum);
        break;
    default:
        break;
    }

    if (Action == VcpuActionSeamRet) {
        // On SEAMRET, the microcode performs a VMCLEAR of the current VMCS.
        VmcsUncache(Vm, VcpuNum, GetVmcsPtr(Vm, VcpuNum));
    }

    if (VcpuMode == VcpuModePseamldr) {
        SetPseamldrRangeActive(Vm, FALSE);
        PseamldrUnlock(Vm);
    }

    return Action;
}