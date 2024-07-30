// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "common.h"

BOOLEAN
HasPseamldrSanitizers(CORNELIUS_VM *Vm)
{
    return Vm->VmConfig.HasSanitizers;
}

BOOLEAN
HasTdxModuleSanitizers(CORNELIUS_VM *Vm)
{
    return (Vm->TdxModuleSancovParams.BitmapsHva != NULL);
}

// --------------------------------------------------------------------------

#define ASAN_SHADOW_BASE            0xFFFF900000000000ULL

typedef struct {
    void *Address;
    size_t AccessSize;
    bool IsWrite;
    uintptr_t Pc;
    uint8_t Code;
} ASAN_REPORT;

static UINT64
AsanAddressToShadow(UINT64 Address)
{
    return ASAN_SHADOW_BASE + ((Address - SEAM_VA_BASE) >> 3);
}

VOID
InitializeAsan(CORNELIUS_VM *Vm)
{
    UINT64 AsanShadowPa;
    PVOID AsanShadowHva;
    UINT64 AsanShadowVaStart;
    UINT64 AsanShadowVaEnd;
    SIZE_T AsanShadowSize;

    AsanShadowPa = Vm->HiddenPaCursor;

    AsanShadowVaStart = AsanAddressToShadow(Vm->PSysInfoTable->StackRgn.Base);
    AsanShadowVaEnd = AsanAddressToShadow(Vm->PSysInfoTable->StackRgn.Base + Vm->PSysInfoTable->StackRgn.Size);

    AsanShadowVaStart = ALIGN_DOWN_BY(AsanShadowVaStart, PAGE_SIZE);
    AsanShadowVaEnd = ALIGN_UP_BY(AsanShadowVaEnd, PAGE_SIZE);

    AsanShadowSize = AsanShadowVaEnd - AsanShadowVaStart;

    if (AsanShadowPa + AsanShadowSize > CORNELIUS_KEYSPACE_SIZE) {
        FATAL("not enough space for the ASAN shadow");
    }

    if (!MapRange(Vm, AsanShadowVaStart, AsanShadowPa, AsanShadowSize, MapTypeData)) {
        FATAL("failed to map the ASAN shadow");
    }

    AsanShadowHva = GPA_TO_HVA(Vm, AsanShadowPa);
    memset(AsanShadowHva, 0, AsanShadowSize);

    MapGpa(Vm, AsanShadowPa, AsanShadowSize);

    Vm->PSysInfoTable->CorneliusSpecific.AsanCoveredStart = Vm->PSysInfoTable->StackRgn.Base;
    Vm->PSysInfoTable->CorneliusSpecific.AsanCoveredEnd = Vm->PSysInfoTable->StackRgn.Base + Vm->PSysInfoTable->StackRgn.Size;

    Vm->HiddenPaCursor += AsanShadowSize;
    return;
}

enum VcpuAction
MsrAsanReport(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 ReportAddr)
{
    ASAN_REPORT *Report;

    Report = (ASAN_REPORT *)GvaToHva(Vm, VcpuNum, ReportAddr);

    LogVcpuErr(Vm, VcpuNum, "ASAN: illegal %s access of %zu byte%s at RIP=0x%llx\n",
        Report->IsWrite ? "write" : "read",
        Report->AccessSize,
        (Report->AccessSize != 1) ? "s" : "",
        Report->Pc);

    return VcpuActionSeamCrash;
}

// --------------------------------------------------------------------------

#define UBSAN_TYPE_OVERFLOW                 1
#define UBSAN_TYPE_ALIGNMENT                2
#define UBSAN_TYPE_UNREACHABLE              3
#define UBSAN_TYPE_CFI                      4
#define UBSAN_TYPE_CACHEMISS                5
#define UBSAN_TYPE_FLOATCASTOVERFLOW        6
#define UBSAN_TYPE_FUNCTIONTYPEMISMATCH     7
#define UBSAN_TYPE_INVALID_BUILTIN          8
#define UBSAN_TYPE_LOAD_INVALID             9
#define UBSAN_TYPE_NONNULL_ARG              10
#define UBSAN_TYPE_NONNULL_RETURN           11
#define UBSAN_TYPE_OOB_DATA                 12
#define UBSAN_TYPE_PTR_OVERFLOW             13
#define UBSAN_TYPE_SHIFT_OOB                14
#define UBSAN_TYPE_TYPE_MISMATCH            15
#define UBSAN_TYPE_VLA_BOUND_NOT_POSITIVE   16
#define UBSAN_TYPE_IMPLICIT_CONVERSION      17

typedef struct {
    uint32_t Type;
    void *Data;
} UBSAN_REPORT;

struct CSourceLocation {
    char *mFilename;
    uint32_t mLine;
    uint32_t mColumn;
};

struct CTypeDescriptor {
    uint16_t mTypeKind;
    uint16_t mTypeInfo;
    uint8_t mTypeName[1];
};

struct COverflowData {
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mType;
};

struct CUnreachableData {
    struct CSourceLocation mLocation;
};

struct CCFICheckFailData {
    uint8_t mCheckKind;
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mType;
};

struct CDynamicTypeCacheMissData {
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mType;
    void *mTypeInfo;
    uint8_t mTypeCheckKind;
};

struct CFunctionTypeMismatchData {
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mType;
};

struct CInvalidBuiltinData {
    struct CSourceLocation mLocation;
    uint8_t mKind;
};

struct CInvalidValueData {
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mType;
};

struct CNonNullArgData {
    struct CSourceLocation mLocation;
    struct CSourceLocation mAttributeLocation;
    int mArgIndex;
};

struct CNonNullReturnData {
    struct CSourceLocation mAttributeLocation;
};

struct COutOfBoundsData {
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mArrayType;
    struct CTypeDescriptor *mIndexType;
};

struct CPointerOverflowData {
    struct CSourceLocation mLocation;
};

struct CShiftOutOfBoundsData {
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mLHSType;
    struct CTypeDescriptor *mRHSType;
};

struct CTypeMismatchData {
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mType;
    unsigned long mLogAlignment;
    uint8_t mTypeCheckKind;
};

struct CTypeMismatchData_v1 {
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mType;
    uint8_t mLogAlignment;
    uint8_t mTypeCheckKind;
};

struct CVLABoundData {
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mType;
};

struct CFloatCastOverflowData {
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mFromType;
    struct CTypeDescriptor *mToType;
};

struct CImplicitConversionData {
    struct CSourceLocation mLocation;
    struct CTypeDescriptor *mFromType;
    struct CTypeDescriptor *mToType;
    uint8_t mKind;
};

struct CAlignmentAssumptionData {
    struct CSourceLocation mLocation;
    struct CSourceLocation mAssumptionLocation;
    struct CTypeDescriptor *mType;
};

enum VcpuAction
MsrUbsanReport(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 ReportAddr)
{
    struct CSourceLocation *Location;
    UBSAN_REPORT *Report;
    CHAR *FileName;

    Report = (UBSAN_REPORT *)GvaToHva(Vm, VcpuNum, ReportAddr);
    Location = (struct CSourceLocation *)GvaToHva(Vm, VcpuNum, (uint64_t)Report->Data);
    FileName = (CHAR *)GvaToHva(Vm, VcpuNum, (uint64_t)Location->mFilename);

    switch (Report->Type) {
    case UBSAN_TYPE_OVERFLOW:
    case UBSAN_TYPE_ALIGNMENT:
    case UBSAN_TYPE_UNREACHABLE:
    case UBSAN_TYPE_CFI:
    case UBSAN_TYPE_CACHEMISS:
    case UBSAN_TYPE_FLOATCASTOVERFLOW:
    case UBSAN_TYPE_FUNCTIONTYPEMISMATCH:
    case UBSAN_TYPE_INVALID_BUILTIN:
    case UBSAN_TYPE_LOAD_INVALID:
    case UBSAN_TYPE_NONNULL_ARG:
    case UBSAN_TYPE_NONNULL_RETURN:
    case UBSAN_TYPE_OOB_DATA:
    case UBSAN_TYPE_PTR_OVERFLOW:
    case UBSAN_TYPE_SHIFT_OOB:
        LogVcpuErr(Vm, VcpuNum, "UBSAN: unknown undefined behavior, %s:%u\n",
            FileName, Location->mLine);
        break;

    case UBSAN_TYPE_TYPE_MISMATCH:
        LogVcpuErr(Vm, VcpuNum, "UBSAN: type mismatch, %s:%u\n",
            FileName, Location->mLine);
        break;

    case UBSAN_TYPE_VLA_BOUND_NOT_POSITIVE:
    case UBSAN_TYPE_IMPLICIT_CONVERSION:
    default:
        LogVcpuErr(Vm, VcpuNum, "UBSAN: unknown undefined behavior at RIP=0x%llx\n",
            GetRegister64(Vm, VcpuNum, WHvX64RegisterRip));
        break;
    }

    return VcpuActionKeepRunning;
}

// --------------------------------------------------------------------------

#define SANCOV_BITMAP_BASE  0xFFFFA00000000000ULL

VOID
InitializeSancov(CORNELIUS_VM *Vm)
{
    UINT64 SancovBitmapPa;
    UINT64 SancovBitmapVaStart;
    UINT64 SancovBitmapVaEnd;
    SIZE_T SancovBitmapSize;

    SancovBitmapPa = Vm->HiddenPaCursor;

    SancovBitmapVaStart = SANCOV_BITMAP_BASE;
    SancovBitmapVaEnd = SancovBitmapVaStart + (Vm->PSysInfoTable->CodeRgn.Size / 8);

    SancovBitmapVaStart = ALIGN_DOWN_BY(SancovBitmapVaStart, PAGE_SIZE);
    SancovBitmapVaEnd = ALIGN_UP_BY(SancovBitmapVaEnd, PAGE_SIZE);

    SancovBitmapSize = SancovBitmapVaEnd - SancovBitmapVaStart;

    if (SancovBitmapPa + SancovBitmapSize > CORNELIUS_KEYSPACE_SIZE) {
        FATAL("not enough space for the ASAN shadow");
    }

    if (!MapRange(Vm, SancovBitmapVaStart, SancovBitmapPa, SancovBitmapSize, MapTypeData)) {
        FATAL("failed to map the ASAN shadow");
    }

    Vm->PseamldrSancovBitmapHva = GPA_TO_HVA(Vm, SancovBitmapPa);
    memset(Vm->PseamldrSancovBitmapHva, 0, SancovBitmapSize);

    MapGpa(Vm, SancovBitmapPa, SancovBitmapSize);

    Vm->PSysInfoTable->CorneliusSpecific.SancovCoveredStart = Vm->PSysInfoTable->CodeRgn.Base;
    Vm->PSysInfoTable->CorneliusSpecific.SancovCoveredEnd = Vm->PSysInfoTable->CodeRgn.Base + Vm->PSysInfoTable->CodeRgn.Size;

    Vm->HiddenPaCursor += SancovBitmapSize;
    return;
}

enum VcpuAction
MsrSancovParams(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 ParamsAddr)
{
    SANCOV_PARAMS *SancovParams;

    SancovParams = (SANCOV_PARAMS *)GvaToHva(Vm, VcpuNum, ParamsAddr);

    Vm->TdxModuleSancovParams.BitmapsGpa = SancovParams->BitmapsGpa;
    Vm->TdxModuleSancovParams.BitmapsHva = GPA_TO_HVA(Vm, SancovParams->BitmapsGpa);
    Vm->TdxModuleSancovParams.BitmapSize = SancovParams->BitmapSize;

    return VcpuActionKeepRunning;
}

SIZE_T
GetSancovMaxBitmapSize(CORNELIUS_VM *Vm)
{
    return sizeof(SANCOV_BITMAP) + (Vm->VmConfig.PSeamldrRange.Size / 8);
}

SIZE_T
GetSancovBitmapSize(CORNELIUS_VM *Vm)
{
    return Vm->TdxModuleSancovParams.BitmapSize;
}

SANCOV_BITMAP *
GetSancovPseamldrBitmap(CORNELIUS_VM *Vm)
{
    return (SANCOV_BITMAP *)Vm->PseamldrSancovBitmapHva;
}

SANCOV_BITMAP *
GetSancovTdxModuleBitmap(CORNELIUS_VM *Vm, UINT32 VcpuNum)
{
    return (SANCOV_BITMAP *)(Vm->TdxModuleSancovParams.BitmapsHva + VcpuNum * Vm->TdxModuleSancovParams.BitmapSize);
}

VOID
MarkSancovBitmapsNotDirty(CORNELIUS_VM *Vm)
{
    //
    // Mark the Sancov bitmaps as NotDirty, to exclude them from the snapshots.
    //

    MarkGpaNotDirty(Vm, Vm->TdxModuleSancovParams.BitmapsGpa, Vm->NumberOfVcpus * Vm->TdxModuleSancovParams.BitmapSize);
}