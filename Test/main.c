// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Cornelius.h>

static VOID
LogStatus(char *msg, ...)
{
    va_list argp;

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 8);

    printf("[+] ");

    va_start(argp, msg);
    vprintf(msg, argp);
    va_end(argp);

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
}

static VOID
LogErr(char *msg, ...)
{
    va_list argp;

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);

    printf("[!] ");

    va_start(argp, msg);
    vprintf(msg, argp);
    va_end(argp);

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
}

static BOOLEAN
ReadBinFile(PCHAR Path, PUINT8* Buffer, PSIZE_T BufferSize)
{
    HANDLE hFile;
    DWORD BytesRead;
    DWORD FileSize;
    PUINT8 FileBytes;

    hFile = CreateFileA(Path,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    FileSize = GetFileSize(hFile, NULL);
    if (FileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return FALSE;
    }

    FileBytes = (PUINT8)VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (FileBytes == NULL) {
        CloseHandle(hFile);
        return FALSE;
    }

    if (!ReadFile(hFile, FileBytes, FileSize, &BytesRead, NULL)) {
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    if (BytesRead != FileSize) {
        return FALSE;
    }

    *Buffer = FileBytes;
    *BufferSize = FileSize;

    return TRUE;
}

static BOOLEAN
LoadPseamldrConstants(PCHAR Path, pseamldr_constants_t* PseamldrConstants)
{
    PVOID Buffer;
    SIZE_T BufferSize;

    if (!ReadBinFile(Path, (PUINT8*)&Buffer, &BufferSize)) {
        return FALSE;
    }
    if (BufferSize != sizeof(*PseamldrConstants)) {
        return FALSE;
    }

    memcpy(PseamldrConstants, Buffer, sizeof(*PseamldrConstants));
    VirtualFree(Buffer, BufferSize, MEM_DECOMMIT | MEM_RELEASE);
    return TRUE;
}

static VOID
TdUnknownVmexit(CORNELIUS_VM* Vm, UINT32 VcpuNum)
{
    VCPU_STATE* TdgState;

    TdgState = GetVcpuState(Vm, VcpuNum);
    TdgState->ExitReason = 0x6666; // Unknown VMEXIT
    TdgState->InstructionLength = 4;

    if (RunVCPU(Vm, VcpuNum, VcpuModeTdGuest) != VcpuActionSeamRet) {
        exit(-1);
    }
}

static VOID
BuildSeptTree(CORNELIUS_VM* Vm, UINT32 VcpuNum, TD_VM* TdVm, UINT64 Gpa)
{
    UINT64 Pa;
    UINT8 Level;
    UINT64 Ret;

    for (Level = 3; Level > 0; --Level) {
        Pa = AllocatePaFromCmrsAvail(Vm);
        LogStatus("Executing TDH.MEM.SEPT.ADD with entry level %d\n", Level);
        Ret = SeamcallTdx_TdhMemSeptAdd(Vm, VcpuNum, TdVm, Pa, Gpa, Level);
        if (Ret) {
            LogErr("TDH.MEM.SEPT.ADD failed with 0x%llx\n", Ret);
            exit(-1);
        }
    }
}

int
main(INT argc, PCHAR argv[])
{
    pseamldr_constants_t PseamldrConstants;
    CORNELIUS_VM_CONFIG VmConfig;
    CORNELIUS_VM *Vm;
    VOID *Snapshot;
    TD_VM *TdVm;
    PUINT8 TdxBuffer;
    SIZE_T TdxSize;
    UINT64 Ret;
    UINT32 i;

    if (argc != 4) {
        LogErr("Usage: Test.exe ConstBlob PseamldrElf TdxElf\n");
        return -1;
    }

    memset(&VmConfig, 0, sizeof(VmConfig));

    if (!LoadPseamldrConstants(argv[1], &PseamldrConstants)) {
        printf("[!] Failed to read the constants file\n");
        return -1;
    }
    if (!ReadBinFile(argv[2], &VmConfig.PSeamldrElfBytes, &VmConfig.PSeamldrElfSize)) {
        printf("[!] Failed to read the P-SEAMLDR ELF file\n");
        return -1;
    }
    if (!ReadBinFile(argv[3], &TdxBuffer, &TdxSize)) {
        printf("[!] Failed to read the TDX ELF file\n");
        return -1;
    }

    //
    // Fill in VmConfig with the parameters we want for the machine. You are free to
    // modify all fields to create any specific configuration you want.
    //
    // The memory layout we set up here is the following:
    //
    // +--------------------------------------------+
    // | Usable VMM Memory (64MB)                   |
    // +--------------------------------------------+
    // | SEAM Range (64MB)                          |
    // +--------------------------------------------+
    // | SMM Range (4KB)                            |
    // +--------------------------------------------+
    // | CMRs (variable size)                       |
    // +--------------------------------------------+
    // | ASAN Shadow (if enabled)                   |
    // +--------------------------------------------+
    //

    VmConfig.NumberOfVcpus = 4;

    VmConfig.SeamrrBase = 32 * _2MB; // SEAMRR.Base = 64MB
    VmConfig.SeamrrSize = 32 * _2MB; // SEAMRR.Limit = 64MB

    VmConfig.PSeamldrRange.Base = VmConfig.SeamrrBase + 16 * _2MB; // P-SEAMLDR range starts at 32MB within SEAMRR
    VmConfig.PSeamldrRange.Size = 16 * _2MB;

    VmConfig.DataRegionSize = PseamldrConstants.data_region_size;
    VmConfig.KeyholeRegionSize = PseamldrConstants.keyhole_region_size;
    VmConfig.KeyholeEditRegionSize = PseamldrConstants.keyhole_edit_region_size;
    VmConfig.StackRegionSize = PseamldrConstants.data_stack_size + PAGE_SIZE; // +1 for the shadow stack
    VmConfig.EntryPointOffset = PseamldrConstants.entry_point_offset;

    VmConfig.SeamdbSize = 1; // Must be at least 1

    VmConfig.KeyidBits = 4;       // 16 keys ...
    VmConfig.NumPrivKeyids = 10;  // .. 10 of which are usable by TDX

    VmConfig.SmrrBase = VmConfig.PSeamldrRange.Base + VmConfig.PSeamldrRange.Size; // SMM range starts after P-SEAMLDR range
    VmConfig.SmrrMask = 0xfffff000; // SMM range size = PAGE_SIZE

    VmConfig.NumberOfCmrs = 1;
    VmConfig.Cmrs[0].Base = VmConfig.SmrrBase + PAGE_SIZE;
    VmConfig.Cmrs[0].Size = 256 * _2MB;

    VmConfig.LastPa = VmConfig.Cmrs[0].Base + VmConfig.Cmrs[0].Size;

    VmConfig.HasSanitizers = FALSE; // Set to TRUE if you have compiled the P-SEAMLDR and TDX module with sanitizers

    //
    // Create the VM.
    //

    LogStatus("Creating the Cornelius VM\n");
    Vm = CreateVM(&VmConfig);
    if (Vm == NULL) {
        LogErr("Unable to create the VM\n");
        return -1;
    }

    //
    // Execute commands to install the TDX module and bring it to the SYS_READY
    // state.
    //
    // Note that we are in the context of the VMM making SEAMCALLs into the
    // P-SEAMLDR and the TDX module. This means that the register state visible
    // through GetVcpuState() is that of the VMM.
    //

    for (i = 0; i < GetNumberOfVcpus(Vm); i++) {
        LogStatus("Executing PSEAMLDR.INSTALL on VCPU%u\n", i);
        Ret = SeamcallPseamldr_Install(Vm, i, TdxBuffer, TdxSize);
        if (Ret != 0) {
            LogErr("PSEAMLDR.INSTALL failed with 0x%llx\n", Ret);
            return -1;
        }
    }

    LogStatus("Executing TDH.SYS.INIT\n");
    Ret = SeamcallTdx_TdhSysInit(Vm, 0);
    if (Ret != 0) {
        LogErr("TDH.SYS.INIT failed with 0x%llx\n", Ret);
        return -1;
    }

    for (i = 0; i < GetNumberOfVcpus(Vm); i++) {
        LogStatus("Executing TDH.SYS.LP.INIT on VCPU%u\n", i);
        Ret = SeamcallTdx_TdhSysLpInit(Vm, i);
        if (Ret != 0) {
            LogErr("TDH.SYS.LP.INIT failed with 0x%llx\n", Ret);
            return -1;
        }
    }

    LogStatus("Executing TDH.SYS.CONFIG\n");
    Ret = SeamcallTdx_TdhSysConfig(Vm, 0);
    if (Ret != 0) {
        LogErr("TDH.SYS.CONFIG failed with 0x%llx\n", Ret);
        return -1;
    }

    LogStatus("Executing TDH.SYS.KEY.CONFIG\n");
    Ret = SeamcallTdx_TdhSysKeyConfig(Vm, 0);
    if (Ret != 0) {
        LogErr("TDH.SYS.KEY.CONFIG failed with 0x%llx\n", Ret);
        return -1;
    }

    LogStatus("Executing TDH.SYS.TDMR.INIT\n");
    Ret = SeamcallTdx_TdhSysTdmrInit(Vm, 0);
    if (Ret != 0) {
        LogErr("TDH.SYS.TDMR.INIT failed with 0x%llx\n", Ret);
        return -1;
    }

    //
    // Create a TD guest with 2 VCPUs, and execute the TDX commands to initialize it.
    //
    // N.B.: we are still in the context of the VMM, making SEAMCALLs into the TDX
    // module.
    //

    TdVm = CreateTdVm(Vm, 2);
    if (TdVm == NULL) {
        LogErr("Unable to create the TdVm\n");
        return -1;
    }

    LogStatus("Executing TDH.MNG.CREATE\n");
    Ret = SeamcallTdx_TdhMngCreate(Vm, 0, TdVm);
    if (Ret != 0) {
        LogErr("TDH.MNG.CREATE failed with 0x%llx\n", Ret);
        return -1;
    }

    LogStatus("Executing TDH.MNG.KEY.CONFIG\n");
    Ret = SeamcallTdx_TdhMngKeyConfig(Vm, 0, TdVm);
    if (Ret != 0) {
        LogErr("TDH.MNG.KEY.CONFIG failed with 0x%llx\n", Ret);
        return -1;
    }

    LogStatus("Executing TDH.MNG.ADDCX\n");
    Ret = SeamcallTdx_TdhMngAddcx(Vm, 0, TdVm);
    if (Ret != 0) {
        LogErr("TDH.MNG.ADDCX failed with 0x%llx\n", Ret);
        return -1;
    }

    LogStatus("Executing TDH.MNG.INIT\n");
    Ret = SeamcallTdx_TdhMngInit(Vm, 0, TdVm);
    if (Ret != 0) {
        LogErr("TDH.MNG.INIT failed with 0x%llx\n", Ret);
        return -1;
    }

    for (i = 0; i < TdVm->NumberOfVcpus; i++) {
        LogStatus("Executing TDH.VP.CREATE on TDVCPU%u\n", i);
        Ret = SeamcallTdx_TdhVpCreate(Vm, 0, TdVm, i);
        if (Ret != 0) {
            LogErr("TDH.VP.CREATE failed with 0x%llx\n", Ret);
            return -1;
        }

        LogStatus("Executing TDH.VP.ADDCX on TDVCPU%u\n", i);
        Ret = SeamcallTdx_TdhVpAddcx(Vm, 0, TdVm, i);
        if (Ret != 0) {
            LogErr("TDH.VP.ADDCX failed with 0x%llx\n", Ret);
            return -1;
        }

        LogStatus("Executing TDH.VP.INIT on TDVCPU%u\n", i);
        Ret = SeamcallTdx_TdhVpInit(Vm, 0, TdVm, i);
        if (Ret != 0) {
            LogErr("TDH.VP.INIT failed with 0x%llx\n", Ret);
            return -1;
        }
    }

    UINT64 PrivatePageGpa = 1ULL << 39;
    BuildSeptTree(Vm, 0, TdVm, PrivatePageGpa);

    LogStatus("Executing TDH.MR.FINALIZE\n");
    Ret = SeamcallTdx_TdhMrFinalize(Vm, 0, TdVm);
    if (Ret != 0) {
        LogErr("TDH.MR.FINALIZE failed with 0x%llx\n", Ret);
        return -1;
    }

    UINT64 PrivatePagePa = AllocatePaFromCmrsAvail(Vm);

    LogStatus("Executing TDH.MEM.PAGE.AUG\n");
    Ret = SeamcallTdx_TdhMemPageAug(Vm, 0, TdVm, PrivatePagePa, PrivatePageGpa, 0);
    if (Ret != 0) {
        LogErr("TDH.MEM.PAGE.AUG failed with 0x%llx\n", Ret);
        return -1;
    }

    //
    // The TD guest is initialized!
    //
    // We now execute the TDH.VP.ENTER command for the TDX module to do a VMLAUNCH
    // into the TD guest. This will switch the context, see below.
    //

    LogStatus("Executing TDH.VP.ENTER\n");
    Ret = SeamcallTdx_TdhVpEnter(Vm, 0, TdVm, 0);
    if (Ret != 0) {
        LogErr("TDH.VP.ENTER failed\n");
        return -1;
    }

    //
    // The VMLAUNCH into the TD guest was successful. That means we are no longer in
    // the context of the VMM making SEAMCALLs into the TDX module, instead we are now
    // in the context of the entered VCPU of the TD guest which can trigger VMEXITs
    // into the TDX module.
    //
    // In other words, we are no longer the VMM, we are the TD guest.
    //
    // We can now execute TDCALLs into the TDX module if we want. Or trigger any
    // other kind of VMEXIT to switch back into the VMM context.
    //

    // Switch the TD guest to long mode. This fixup would normally be done by the
    // CPU automatically, but we need to do it manually in Cornelius.
    GetVcpuState(Vm, 0)->Cr0 |= CR0_PG;
    GetVcpuState(Vm, 0)->Efer |= EFER_LMA;
    GetVcpuState(Vm, 0)->Cs.Long = 1;

    // Take a snapshot of the VM. See below what we do with it.
    LogStatus("Taking snapshot\n");
    Snapshot = CreateSnapshot(Vm);
    if (Snapshot == NULL) {
        LogErr("Unable to create snapshot\n");
        return -1;
    }

    // Execute a TDCALL to accept the page we previously set up.
    LogStatus("TD executing TDG.MEM.PAGE.ACCEPT\n");
    Ret = Tdcall_TdgMemPageAccept(Vm, 0, PrivatePageGpa, 0);
    if (Ret != 0) {
        LogErr("TDG.MEM.PAGE.ACCEPT failed with 0x%llx\n", Ret);
        return -1;
    }

    // Now trigger a VMEXIT with a dummy exit reason. On success this puts us back
    // in the context of the VMM.
    LogStatus("Doing VMEXIT from TD guest\n");
    TdUnknownVmexit(Vm, 0);

    //
    // We're back as a VMM! And we can now execute SEAMCALLs again if we want.
    // Execute one into the P-SEAMLDR, just to showcase.
    //

    seamldr_info_t PseamldrInfo;

    LogStatus("TD executing PSEAMLDR.INFO\n");
    Ret = SeamcallPseamldr_Info(Vm, 0, 0x1000, &PseamldrInfo);
    if (Ret != 0) {
        LogErr("PSEAMLDR.INFO failed with 0x%llx\n", Ret);
        return -1;
    }
    // The vendor_id should always be 0x8086, sanity check that.
    if (PseamldrInfo.vendor_id != 0x8086) {
        LogErr("PSEAMLDR.INFO vendor_id 0x%x != 0x8086\n", PseamldrInfo.vendor_id);
        return -1;
    }

    //
    // Now restore the snapshot! This will restore the VM exactly back to how it was
    // when we took the snapshot. Remember that at that moment we were in the
    // context of a TD guest, and therefore we're going to be back in that context
    // from now on.
    //

    LogStatus("Restoring snapshot\n");
    RestoreSnapshot(Vm, Snapshot);

    // Trigger a VMEXIT with a dummy exit reason. On success this puts us back
    // in the context of the VMM.
    LogStatus("Doing VMEXIT from TD guest\n");
    TdUnknownVmexit(Vm, 0);

    //
    // If the P-SEAMLDR and TDX module have SanCov enabled, print the coverage
    // counts.
    //
    if (HasPseamldrSanitizers(Vm)) {
        SANCOV_BITMAP *Bitmap = GetSancovPseamldrBitmap(Vm);
        LogStatus("P-SEAMLR coverage count: %zu\n", Bitmap->NumberOfHits);
    }
    if (HasTdxModuleSanitizers(Vm)) {
        for (i = 0; i < GetNumberOfVcpus(Vm); i++) {
            SANCOV_BITMAP *Bitmap = GetSancovTdxModuleBitmap(Vm, i);
            LogStatus("TDX module coverage count for VCPU%u: %zu\n", i, Bitmap->NumberOfHits);
        }
    }

    LogStatus("Finished successfully\n");
    return 0;
}
