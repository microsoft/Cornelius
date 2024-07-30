// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <windows.h>
#include <WinHvPlatform.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef EXPORT_API
#define EXPORT_API  // Nothing
typedef VOID CORNELIUS_VM;
#endif

#define __BIT(_Num_)    (1ULL << (_Num_))

#if !defined(CORNELIUS_HIDE_TYPES)

#define PAGE_SIZE   4096ULL
#define _4KB        PAGE_SIZE
#define _2KB        (_4KB / 2)
#define _2MB        (512 * PAGE_SIZE)
#define _1GB        (512 * _2MB)

//
// P-SEAMLDR types (pseamldr_api_defs.h)
//

typedef struct pseamldr_constants_s
{
    uint64_t data_stack_size;
    uint64_t code_region_size;
    uint64_t data_region_size;
    uint64_t keyhole_region_size;
    uint64_t keyhole_edit_region_size;
    uint64_t entry_point_offset;
} pseamldr_constants_t;

//
// Cornelius types.
//

typedef struct {
    UINT64 Base;
    UINT64 Size;
} MEM_RANGE;

typedef struct {
    UINT64 TdvprPa;
} TD_VCPU;

typedef struct {
    UINT64 TdrPa;
    UINT16 NumberOfVcpus;
    TD_VCPU Vcpus[];
} TD_VM;

typedef struct {
    UINT32 NumberOfVcpus;

    PUINT8 PSeamldrElfBytes;
    SIZE_T PSeamldrElfSize;

    UINT64 SeamrrBase;
    SIZE_T SeamrrSize;

    MEM_RANGE PSeamldrRange; // P-SEAMLDR range, within SEAMRR
    UINT64 DataRegionSize;
    UINT64 KeyholeRegionSize;
    UINT64 KeyholeEditRegionSize;
    UINT64 StackRegionSize; // Includes the shadow
    UINT64 EntryPointOffset;

    SIZE_T SeamdbSize;

#define TDX_PRIV_HKID(_Vm_, _Num_)  ((1ULL << (_Vm_)->VmConfig.KeyidBits) - (_Vm_)->VmConfig.NumPrivKeyids + 1 + (_Num_))
    UINT8 KeyidBits;
    UINT32 NumPrivKeyids;

    UINT64 SmrrBase;
    UINT64 SmrrMask;

#define NUM_CMRS    32
    SIZE_T NumberOfCmrs;
    MEM_RANGE Cmrs[NUM_CMRS];

    UINT64 LastPa;

    BOOLEAN HasSanitizers;
} CORNELIUS_VM_CONFIG;

typedef struct {
    //
    // There are four types of registers here:
    //
    //  - The real registers (RR) that get installed on the VCPU.
    //  - The virtual registers (VR) that the P-SEAMLDR/TDX-MODULE can read
    //    via VMREAD/RDMSR and write via VMWRITE/WRMSR.
    //  - The read-only registers (RO) that the P-SEAMLDR/TDX-MODULE can only
    //    read via VMREAD.
    //  - The persistent registers (PR) that persist across VMM, P-SEAMLDR
    //    and TDX-MODULE.
    //

    // VMX
    UINT64 ExitReason; // RO
    UINT64 InstructionLength; // RO
    UINT64 GuestInterruptibility; // VR
    UINT64 PendingDebugException; // VR
    // CRs
    UINT64 Cr0;
    UINT64 Cr3;
    UINT64 Cr4;
    // MSRs
    UINT64 MiscEnable; // PR
    UINT64 DebugCtlMsr; // VR
    UINT64 Pat; // VR
    UINT64 Efer; // VR
    UINT64 PerfGlobalCtrl; // VR
    UINT64 SysenterEsp; // VR
    UINT64 SysenterEip; // VR
    UINT64 SysenterCs; // VR
    UINT64 Star; // RR
    UINT64 Lstar; // RR
    UINT64 Fmask; // RR
    UINT64 KernelGsBase; // RR
    UINT64 Pl0Ssp; // RR
    UINT64 Pl1Ssp; // RR
    UINT64 Pl2Ssp; // RR
    UINT64 Pl3Ssp; // RR
    UINT64 DsArea; // VR
    UINT64 NonFaultingMsr; // VR
    UINT64 TscAux; // VR -- could be made RR as the Vp reg exists
    UINT64 Xss; // RR
    // GPRs
    UINT64 Rax;
    UINT64 Rcx;
    UINT64 Rdx;
    UINT64 Rbx;
    UINT64 Rsp; // VR
    UINT64 Rbp;
    UINT64 Rsi;
    UINT64 Rdi;
    UINT64 R8;
    UINT64 R9;
    UINT64 R10;
    UINT64 R11;
    UINT64 R12;
    UINT64 R13;
    UINT64 R14;
    UINT64 R15;
    UINT64 Rip; // VR
    UINT64 Rflags; // VR
    UINT64 Ssp; // VR
    // DRs
    UINT64 Dr7; // VR
    // Segments
    WHV_X64_SEGMENT_REGISTER Cs; // VR
    // XMMs
    WHV_UINT128 Xmm0;
    WHV_UINT128 Xmm1;
    WHV_UINT128 Xmm2;
    WHV_UINT128 Xmm3;
    WHV_UINT128 Xmm4;
    WHV_UINT128 Xmm5;
    WHV_UINT128 Xmm6;
    WHV_UINT128 Xmm7;
    WHV_UINT128 Xmm8;
    WHV_UINT128 Xmm9;
    WHV_UINT128 Xmm10;
    WHV_UINT128 Xmm11;
    WHV_UINT128 Xmm12;
    WHV_UINT128 Xmm13;
    WHV_UINT128 Xmm14;
    WHV_UINT128 Xmm15;
    // XSAVE
    UINT64 Xcr0; // RR
} VCPU_STATE;

typedef struct {
    uint64_t NumberOfHits;
    uint64_t Reserved[7];
    uint8_t Bitmap[];
} SANCOV_BITMAP;

C_ASSERT(sizeof(SANCOV_BITMAP) == 64);

#include "IntelDefs/pseamldr-defs.h"
#include "IntelDefs/tdx-defs.h"
#include "x86-defs.h"

#endif // !defined(CORNELIUS_HIDE_TYPES)

#if !defined(CORNELIUS_HIDE_PROTOTYPES)

//
// commands.c
//

EXPORT_API UINT64 SeamcallPseamldr_Info(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 Gpa, seamldr_info_t *PseamldrInfo);
EXPORT_API UINT64 SeamcallPseamldr_Install(CORNELIUS_VM *Vm, UINT32 VcpuNum, PUINT8 TdxBuffer, SIZE_T TdxSize);
// BOOLEAN SeamcallTdx_TdhSysInfo(CORNELIUS_VM *Vm, UINT32 VcpuNum);
EXPORT_API UINT64 SeamcallTdx_TdhSysInit(CORNELIUS_VM *Vm, UINT32 VcpuNum);
EXPORT_API UINT64 SeamcallTdx_TdhSysLpInit(CORNELIUS_VM *Vm, UINT32 VcpuNum);
EXPORT_API UINT64 SeamcallTdx_TdhSysConfig(CORNELIUS_VM *Vm, UINT32 VcpuNum);
EXPORT_API UINT64 SeamcallTdx_TdhSysKeyConfig(CORNELIUS_VM *Vm, UINT32 VcpuNum);
EXPORT_API UINT64 SeamcallTdx_TdhSysTdmrInit(CORNELIUS_VM *Vm, UINT32 VcpuNum);
EXPORT_API UINT64 SeamcallTdx_TdhMngCreate(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm);
EXPORT_API UINT64 SeamcallTdx_TdhMngKeyConfig(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm);
EXPORT_API UINT64 SeamcallTdx_TdhMngAddcx(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm);
EXPORT_API UINT64 SeamcallTdx_TdhMngInit(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm);
EXPORT_API UINT64 SeamcallTdx_TdhVpCreate(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu);
EXPORT_API UINT64 SeamcallTdx_TdhVpAddcx(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu);
EXPORT_API UINT64 SeamcallTdx_TdhVpInit(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu);
EXPORT_API UINT64 SeamcallTdx_TdhVpWr(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu, md_field_id_t Identifier, UINT64 Value, UINT64 Mask);
EXPORT_API UINT64 SeamcallTdx_TdhVpRd(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu, md_field_id_t Identifier, UINT64 *Value);
EXPORT_API UINT64 SeamcallTdx_TdhVpEnter(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm, UINT32 TdVcpu);
EXPORT_API UINT64 SeamcallTdx_TdhMrFinalize(CORNELIUS_VM *Vm, UINT32 VcpuNum, TD_VM *TdVm);
EXPORT_API UINT64 SeamcallTdx_TdhMemSeptAdd(CORNELIUS_VM* Vm, UINT32 VcpuNum, TD_VM* TdVm, UINT64 Pa, UINT64 Gpa, UINT8 Level);
EXPORT_API UINT64 SeamcallTdx_TdhMemPageAug(CORNELIUS_VM* Vm, UINT32 VcpuNum, TD_VM* TdVm, UINT64 Pa, UINT64 Gpa, UINT8 Level);
EXPORT_API UINT64 Tdcall_TdgMemPageAccept(CORNELIUS_VM* Vm, UINT32 VcpuNum, UINT64 Gpa, UINT8 Level);
EXPORT_API VOID Tdcall_TdgVpVmcall(CORNELIUS_VM* Vm, UINT32 VcpuNum, UINT64 Control);

//
// paging.c
//

EXPORT_API BOOLEAN PaToHva(CORNELIUS_VM *Vm, UINT64 Pa, PVOID *Hva);

//
// sanitizers.c
//

EXPORT_API BOOLEAN HasPseamldrSanitizers(CORNELIUS_VM *Vm);
EXPORT_API BOOLEAN HasTdxModuleSanitizers(CORNELIUS_VM *Vm);
EXPORT_API SIZE_T GetSancovBitmapSize(CORNELIUS_VM *Vm);
EXPORT_API SANCOV_BITMAP *GetSancovPseamldrBitmap(CORNELIUS_VM *Vm);
EXPORT_API SANCOV_BITMAP *GetSancovTdxModuleBitmap(CORNELIUS_VM *Vm, UINT32 VcpuNum);
EXPORT_API VOID MarkSancovBitmapsNotDirty(CORNELIUS_VM *Vm);

//
// seam.c
//

EXPORT_API VCPU_STATE *GetVcpuState(CORNELIUS_VM *Vm, UINT32 VcpuNum);
EXPORT_API UINT64 AllocatePaFromCmrsAvail(CORNELIUS_VM *Vm);
EXPORT_API TD_VM *CreateTdVm(CORNELIUS_VM *Vm, UINT16 NumberOfVcpus);

//
// snapshot.c
//

EXPORT_API VOID *CreateSnapshot(CORNELIUS_VM *Vm);
EXPORT_API VOID RestoreSnapshot(CORNELIUS_VM *Vm, VOID *Snapshot);

//
// vm.c
//

enum VcpuAction {
    VcpuActionKeepRunning,
    VcpuActionEmulationError,
    VcpuActionInvariantViolated,
    VcpuActionSeamPanic,
    VcpuActionSeamCrash,
    VcpuActionSeamRet,
    VcpuActionVmlaunch,
    VcpuActionVmresume,
    VcpuActionSeamNotReady
};

enum VcpuMode {
    VcpuModePseamldr,
    VcpuModeTdxModule,
    VcpuModeTdGuest
};

EXPORT_API VOID MapGpa(CORNELIUS_VM *Vm, UINT64 Gpa, SIZE_T Size);
EXPORT_API VOID UnmapGpa(CORNELIUS_VM *Vm, UINT64 Gpa, SIZE_T Size);
EXPORT_API CORNELIUS_VM *CreateVM(CORNELIUS_VM_CONFIG *VmConfig);
EXPORT_API INT GetVcpuLogLevel(CORNELIUS_VM *Vm, UINT32 VcpuNum);
EXPORT_API VOID SetVcpuLogLevel(CORNELIUS_VM *Vm, UINT32 VcpuNum, INT LogLevel);
EXPORT_API UINT32 GetNumberOfVcpus(CORNELIUS_VM *Vm);
EXPORT_API enum VcpuAction RunVCPU(CORNELIUS_VM *Vm, UINT32 VcpuNum, enum VcpuMode VcpuMode);

#endif // !defined(CORNELIUS_HIDE_PROTOTYPES)