// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <WinHvPlatform.h>

#define PACKED
#define bool_t bool

#define PAGE_SIZE   4096ULL
#define _4KB        PAGE_SIZE
#define _2KB        (_4KB / 2)
#define _2MB        (512 * PAGE_SIZE)
#define _1GB        (512 * _2MB)

#include "IntelDefs/pseamldr-defs.h"
#include "IntelDefs/tdx-defs.h"
#include "x86-defs.h"

#define ALIGN_DOWN_BY(length, alignment) \
    ((ULONG_PTR)(length) & ~((ULONG_PTR)(alignment) - 1))

#define ALIGN_UP_BY(length, alignment) \
    (ALIGN_DOWN_BY(((ULONG_PTR)(length) + (alignment) - 1), alignment))

#define ALIGN_UP_POW2(_Value_)  pow(2, ceil(log(_Value_)/log(2)))

#define SEAMRR_SIZE_TO_MASK(size)  ((size) / (1 << 25ULL))

//
// HV-DISCREPANCY: WHP doesn't have an interface to forward _all_ MSRs to us,
// so we OR the MSR numbers with a magic in the higher 32 bits, and unmask it
// here.
//
#define REAL_MSR_NUMBER(_Msr_)  ((_Msr_) & ~0x0ABC0000)

#define EXPORT_API  __declspec(dllexport)

// --------------------------------------------------------------------------

#define C_KEYHOLE_EDIT_REGION_BASE  0x0000000100000000
#define C_MODULE_RGN_BASE           0x0000000200000000
#define C_CODE_RGN_BASE             0xFFFF800000000000
#define C_STACK_RGN_BASE            0xFFFF800100000000
#define C_KEYHOLE_RGN_BASE          0xFFFF800200000000
#define C_DATA_RGN_BASE             0xFFFF800300000000
#define C_SYS_INFO_TABLE_BASE       0xFFFF8003FFFF0000

#define P_SYS_INFO_TABLE_VERSION       0

#define SYS_INFO_TABLE_SOCKET_CPUID_TABLE_SIZE      8
#define SYS_INFO_TABLE_NUM_CMRS                     32

#define CORNELIUS_HIDE_PROTOTYPES
#include "Cornelius.h"
#undef CORNELIUS_HIDE_PROTOTYPES

C_ASSERT(NUM_CMRS == SYS_INFO_TABLE_NUM_CMRS);

typedef struct {
    // fields populated by mcheck
    UINT64     Version;
    UINT32     TotNumLps;
    UINT32     TotNumSockets;
    UINT32     SocketCpuidTable[SYS_INFO_TABLE_SOCKET_CPUID_TABLE_SIZE];
    MEM_RANGE  PSeamldrRange;
    UINT8      SkipSMRR2Check;
    UINT8      TDX_AC;
    UINT8      Reserved_0[62];
    MEM_RANGE  Cmr[SYS_INFO_TABLE_NUM_CMRS];
    UINT8      Reserved_1[1408];
    // fields populated by NP-SEAMLDR
    UINT64     NpSeamldrMutex;
    MEM_RANGE  CodeRgn;
    MEM_RANGE  DataRgn;
    MEM_RANGE  StackRgn;
    MEM_RANGE  KeyholeRgn;
    MEM_RANGE  KeyholeEditRgn;
    UINT64     ModuleRgnBase;
    UINT32     AcmX2ApicId;
    UINT32     AcmX2ApicIdValid;

    UINT8      Reserved2[1944 - 4 * sizeof(UINT64)];
    struct {
        UINT64 SancovCoveredStart;
        UINT64 SancovCoveredEnd;
        UINT64 AsanCoveredStart;
        UINT64 AsanCoveredEnd;
    } CorneliusSpecific;
} P_SYS_INFO_TABLE_t;
C_ASSERT(sizeof(P_SYS_INFO_TABLE_t) == 4096);

// --------------------------------------------------------------------------

#define SEAM_VA_BASE                0xFFFF800000000000ULL

#define MSR_SANCOV_PARAMS           0xAAA1
#define MSR_ASAN_REPORT             0xAAA2
#define MSR_UBSAN_REPORT            0xAAA3

#define MSR_SEAMVM_DEBUG            0xBBBB0001ULL

#define CORNELIUS_KEYSPACE_SHIFT    30
#define CORNELIUS_KEYSPACE_SIZE     (1ULL << CORNELIUS_KEYSPACE_SHIFT)

#define GPA_WITHOUT_HKID(_Gpa_)     ((_Gpa_) & (CORNELIUS_KEYSPACE_SIZE - 1))
#define HKID_FROM_GPA(_Gpa_)        ((UINT16)((_Gpa_) >> CORNELIUS_KEYSPACE_SHIFT))

#define GPA_WITHOUT_REAL_HKID(_Vm_, _Gpa_)  ((UINT64)((_Gpa_) & ((1ULL << (52 - (_Vm_)->VmConfig.KeyidBits)) - 1)))
#define REAL_HKID_FROM_GPA(_Vm_, _Gpa_)     ((UINT16)((_Gpa_) >> (52 - (_Vm_)->VmConfig.KeyidBits)))

#define GPAS_BITMAP_SIZE(_Vm_)      ALIGN_UP_BY(((_Vm_)->LastPa) / PAGE_SIZE / 8, sizeof(UINT64))

#define NUM_TD_VMCS_FIELDS  180

typedef struct {
    UINT64 Revision;
    BOOLEAN CachedOnCpu;
    UINT64 Fields[NUM_TD_VMCS_FIELDS];
} TD_VMCS;

C_ASSERT(sizeof(TD_VMCS) <= PAGE_SIZE);

typedef struct {
    UINT64 VmcsPtr;
#define SEAM_STATE_CR0      0
#define SEAM_STATE_CR3      1
#define SEAM_STATE_CR4      2
#define SEAM_STATE_ES       3
#define SEAM_STATE_CS       4
#define SEAM_STATE_SS       5
#define SEAM_STATE_DS       6
#define SEAM_STATE_FS       7
#define SEAM_STATE_GS       8
#define SEAM_STATE_TR       9
#define SEAM_STATE_IDTR     10
#define SEAM_STATE_GDTR     11
#define SEAM_STATE_PAT      12
#define SEAM_STATE_SCET     13
#define SEAM_STATE_EFER     14
#define SEAM_STATE_RIP      15
#define SEAM_STATE_RSP      16
#define SEAM_STATE_SSP      17
#define SEAM_STATE_RFLAGS   18
#define NUM_SEAM_REGS       19
    WHV_REGISTER_NAME RegisterNames[NUM_SEAM_REGS];
    WHV_REGISTER_VALUE RegisterValues[NUM_SEAM_REGS];
} SEAM_STATE;

typedef struct {
    uint64_t BitmapsGpa;
    uint64_t BitmapSize;
} SANCOV_PARAMS;

#define MAX_LOG_CHACHE_SIZE 0x100

typedef struct {
    UINT32 Cursor;
    CHAR Buffer[MAX_LOG_CHACHE_SIZE + 1];
} DBG_LOG_BUFFER;

#define VMCS_CACHE_SIZE 4

typedef struct {
    VCPU_STATE VcpuState;
    SEAM_STATE TdxState;
    BOOLEAN HasPendingException;
    WHV_EXCEPTION_TYPE PendingExceptionType;
    BOOLEAN IsSeamldr;
    INT LogLevel;
    DBG_LOG_BUFFER DbgLogBuffer;
    UINT64 VmcsCache[VMCS_CACHE_SIZE];
} CORNELIUS_VCPU;

typedef struct {
    WHV_PARTITION_HANDLE Partition;
    HANDLE PseamldrLock;

    struct {
        UINT32 PerfMon:1;
        UINT32 Rsvd:31;
    } CpuSupport;

    CORNELIUS_VM_CONFIG VmConfig;
    PUINT8 SeamrrVa;
    P_SYS_INFO_TABLE_t* PSysInfoTable;
    UINT64 CSysInfoTableVa;

    UINT64 AllocatorPa;
    UINT64 AllocatorPaEnd;

    struct {
        UINT64 Start;
        UINT64 End;
    } CmrsAvail[SYS_INFO_TABLE_NUM_CMRS];

    UINT64 LastPa;
    UINT64 HiddenPaCursor;

    PUINT64 DirtyGpasBitmap;
    PUINT64 MappedGpasBitmap;

    // Initial register values
    UINT64 BootCr3;
    UINT64 BootRip;
    UINT64 BootRsp;
    UINT64 BootSsp;

    SIZE_T SeamdbIndex;

#define NUM_KEYIDS  32
    UINT32 KeyidActive;

#define GPA_TO_HVA(_Vm_, _Gpa_) ((_Vm_)->AddressSpaceHva + GPA_WITHOUT_HKID(_Gpa_))
    PUINT8 AddressSpaceHva;

    PUINT8 VmcsHva;

    PVOID PseamldrSancovBitmapHva;

    struct {
        UINT64 BitmapsGpa;
        PUINT8 BitmapsHva;
        UINT64 BitmapSize;
    } TdxModuleSancovParams;

    SEAM_STATE SeamldrState;

    BOOLEAN IsPseamldrRangeActive;
    volatile BOOLEAN SeamReady;

    UINT32 NumberOfVcpus;
    CORNELIUS_VCPU Vcpus[];
} CORNELIUS_VM;

// --------------------------------------------------------------------------

#define FATAL(msg)  { printf("[!] %s Failed with %s\n", __func__, (msg)); exit(-1); }
#define FAIL_IF_ERROR(hr) do { if (FAILED(hr)) { printf("[!] %s Failed with %x\n", __func__, hr); exit(-1); } } while (0);
#define C_ASSERT(e) typedef char __C_ASSERT__[(e)?1:-1]

#define VMCS_INVALID_PTR    0xFFFFFFFFFFFFFFFFULL

enum VmcsType {
    VmcsTypePseamldr,
    VmcsTypeTdxModule,
    VmcsTypeTdGuest,
    VmcsTypeInvalid
};

extern const UINT64 TdVmcsFields[NUM_TD_VMCS_FIELDS];

//
// commands.c
//

BOOLEAN SeamcallTdx_TdhSysInfo(CORNELIUS_VM *Vm, UINT32 VcpuNum);

//
// elf.c
//

BOOLEAN RelocateElf(PUINT8 ElfImage, SIZE_T ElfSize, UINT64 RelocationAddr);
UINT64 GetElfEntryPoint(PUINT8 ElfImage, SIZE_T ElfSize);
UINT64 GetElfSymbolOffset(PUINT8 ElfImage, SIZE_T ElfSize, CHAR *SymbolName);

//
// emulator.c
//

enum VcpuAction EmulateCPUID(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
enum VcpuAction EmulateRDMSR(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
enum VcpuAction EmulateWRMSR(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
enum VcpuAction EmulateOnUD(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
enum VcpuAction EmulateOnGP(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);
enum VcpuAction EmulateOnIO(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_RUN_VP_EXIT_CONTEXT *ExitContext);

//
// paging.c
//

enum MAP_TYPE {
    MapTypeCode,
    MapTypeData,
    MapTypeDataUser,
    MapTypeShadowStack,
    MapTypeKeyHole
};

BOOLEAN GvaToPa(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 Gva, UINT64 *Pa);
PVOID GvaToHva(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 Gva);
BOOLEAN MapPage(CORNELIUS_VM *Vm, UINT64 Va, UINT64 Pa, enum MAP_TYPE MapType, UINT64 *PdePage);
BOOLEAN MapRange(CORNELIUS_VM *Vm, UINT64 Va, UINT64 Pa, SIZE_T Size, enum MAP_TYPE MapType);

//
// invariants.c
//

BOOLEAN InvariantsOnCPUID(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT32 Leaf);
BOOLEAN InvariantsOnPCONFIG(CORNELIUS_VM *Vm, UINT32 VcpuNum, mktme_key_program_t *MktmeKeyProgram);
BOOLEAN InvariantsOnVMPTRLD(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsPtr);
BOOLEAN InvariantsOnVMLAUNCH(CORNELIUS_VM *Vm, UINT32 VcpuNum);
BOOLEAN InvariantsOnVmcsCache(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsPtr);

//
// sanitizers.c
//

VOID InitializeAsan(CORNELIUS_VM *Vm);
enum VcpuAction MsrAsanReport(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 ReportAddr);
enum VcpuAction MsrUbsanReport(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 ReportAddr);
VOID InitializeSancov(CORNELIUS_VM *Vm);
SIZE_T GetSancovMaxBitmapSize(CORNELIUS_VM *Vm);
enum VcpuAction MsrSancovParams(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 ParamsAddr);

//
// seam.c
//

VOID InitializeSeamRr(CORNELIUS_VM *Vm);
VOID InitializeSeamldrState(CORNELIUS_VM *Vm);
VOID InstallSeamldrState(CORNELIUS_VM *Vm, UINT32 VcpuNum);
VOID InitializeVcpuState(CORNELIUS_VM *Vm, UINT32 VcpuNum);
VOID InitializeTdxState(CORNELIUS_VM *Vm, UINT32 VcpuNum);
VOID InstallTdxState(CORNELIUS_VM *Vm, UINT32 VcpuNum);
VOID PseamldrTransferVmcsSet64(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 Offset, UINT64 Value);
VOID SyncTdxStateWithVmcs(CORNELIUS_VM *Vm);
VOID SyncVcpuStateWithContext(CORNELIUS_VM *Vm, UINT32 VcpuNum);
VOID SyncVcpuStateWithTdVmcs(CORNELIUS_VM *Vm, UINT32 VcpuNum);
VOID SetPseamldrRangeActive(CORNELIUS_VM *Vm, BOOLEAN Active);
SEAM_STATE *GetTdxState(CORNELIUS_VM *Vm, UINT32 VcpuNum);
BOOLEAN IsVcpuSeamldr(CORNELIUS_VM *Vm, UINT32 VcpuNum);
VOID InstallVcpuState(CORNELIUS_VM *Vm, UINT32 VcpuNum);
UINT64 GetPseamldrEntryVmcsPtr(CORNELIUS_VM *Vm);
UINT64 GetEntryVmcsPtr(CORNELIUS_VM *Vm, UINT32 VcpuNum);
enum VcpuAction SetEntryVmcsPtr(CORNELIUS_VM *Vm, UINT32 VcpuNum);
UINT64 GetVmcsPtr(CORNELIUS_VM *Vm, UINT32 VcpuNum);
VOID SetVmcsPtr(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsPtr);
enum VmcsType GetCurrentVmcsType(CORNELIUS_VM *Vm, UINT32 VcpuNum);
VOID PseamldrLock(CORNELIUS_VM *Vm);
VOID PseamldrUnlock(CORNELIUS_VM *Vm);
VOID MapCmrsInKeyidSpace(CORNELIUS_VM *Vm, UINT16 Keyid);
BOOLEAN TdVmcsWrite64(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsField, UINT64 Value);
BOOLEAN TdVmcsRead64(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsField, PUINT64 Value);
enum VcpuAction VmcsCache(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsPtr);
VOID VmcsUncache(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 VmcsPtr);
BOOLEAN IsGpaInPseamldrRange(CORNELIUS_VM *Vm, UINT64 Gpa);
enum VcpuAction MsrSeamExtend(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 MsrValue);

//
// util.c
//

VOID LogVcpuTdxDebug(CORNELIUS_VM *Vm, UINT32 VcpuNum, char *msg, ...);
VOID LogVcpuOk(CORNELIUS_VM *Vm, UINT32 VcpuNum, char *msg, ...);
VOID LogVcpuErr(CORNELIUS_VM *Vm, UINT32 VcpuNum, char *msg, ...);

//
// vm.c
//

UINT64 GetRegister64(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_REGISTER_NAME Name);
VOID SetRegister64(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_REGISTER_NAME Name, UINT64 Val64);
VOID MarkGpaNotDirty(CORNELIUS_VM *Vm, UINT64 Gpa, SIZE_T Size);
VOID MapGpaExecutable(CORNELIUS_VM *Vm, UINT64 Gpa, SIZE_T Size);
VOID SetPendingException(CORNELIUS_VM *Vm, UINT32 VcpuNum, WHV_EXCEPTION_TYPE ExceptionType);

#define CORNELIUS_HIDE_TYPES
#include "Cornelius.h"
#undef CORNELIUS_HIDE_TYPES