// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "common.h"

typedef union {
    struct
    {
        UINT64 Present : 1;
        UINT64 ReadWrite : 1;
        UINT64 User : 1;
        UINT64 WriteThrough : 1;
        UINT64 CacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Dirty : 1;
        UINT64 Pat : 1;
        UINT64 Global : 1;
        UINT64 Available0 : 3;
        UINT64 Pfn : 40;
        UINT64 Available1 : 11;
        UINT64 NoExecute : 1;
    };

    UINT64 AsUINT64;
} PT_ENTRY;

#define L1_SHIFT        12
#define L2_SHIFT        21
#define L3_SHIFT        30
#define L4_SHIFT        39

#define L1_MASK	        0x00000000001ff000
#define L2_MASK	        0x000000003fe00000
#define L3_MASK	        0x0000007fc0000000
#define L4_MASK	        0x0000ff8000000000

#define L1_IDX(VA)      (((VA) & L1_MASK) >> L1_SHIFT)
#define L2_IDX(VA)      (((VA) & L2_MASK) >> L2_SHIFT)
#define L3_IDX(VA)      (((VA) & L3_MASK) >> L3_SHIFT)
#define L4_IDX(VA)      (((VA) & L4_MASK) >> L4_SHIFT)

#define PA_TO_PFN(pa)   ((pa) / PAGE_SIZE)
#define PFN_TO_PA(pfn)  ((pfn) * PAGE_SIZE)

BOOLEAN
GvaToPa(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 Gva, UINT64 *Pa)
{
    HRESULT hRes;
    WHV_TRANSLATE_GVA_FLAGS flags = WHvTranslateGvaFlagValidateRead;
    WHV_TRANSLATE_GVA_RESULT result;
    WHV_GUEST_PHYSICAL_ADDRESS Gpa = 0;

    hRes = WHvTranslateGva(Vm->Partition, VcpuNum, Gva, flags, &result, &Gpa);
    if (FAILED(hRes)) {
        return FALSE;
    }
    if (result.ResultCode != WHvTranslateGvaResultSuccess) {
        return FALSE;
    }

    *Pa = Gpa;
    return TRUE;
}

BOOLEAN
PaToHva(CORNELIUS_VM *Vm, UINT64 Pa, PVOID *Hva)
{
    Pa = GPA_WITHOUT_HKID(Pa);

    if (Pa >= Vm->LastPa) {
        return FALSE;
    }

    *Hva = GPA_TO_HVA(Vm, Pa);
    return TRUE;
}

PVOID
GvaToHva(CORNELIUS_VM *Vm, UINT32 VcpuNum, UINT64 Gva)
{
    PVOID Hva;
    UINT64 Pa;

    if (!GvaToPa(Vm, VcpuNum, Gva, &Pa)) {
        return NULL;
    }
    if (!PaToHva(Vm, Pa, (PVOID *)&Hva)) {
        return NULL;
    }

    return Hva;
}

static BOOLEAN
AllocatePa(CORNELIUS_VM *Vm, UINT64 *Pa)
{
    if (Vm->AllocatorPa == Vm->AllocatorPaEnd) {
        return FALSE;
    }

    *Pa = Vm->AllocatorPa;
    Vm->AllocatorPa += PAGE_SIZE;
    return TRUE;
}

BOOLEAN
MapPage(CORNELIUS_VM *Vm, UINT64 Va, UINT64 Pa, enum MAP_TYPE MapType, UINT64 *PdePage)
{
    UINT64 LowerLevelPa;
    PT_ENTRY *L4;
    PT_ENTRY *L3;
    PT_ENTRY *L2;
    PT_ENTRY *L1;

    if (Vm->BootCr3 == 0) {
        if (!AllocatePa(Vm, &Vm->BootCr3)) {
            return FALSE;
        }
    }

    //
    // L4.
    //

    if (!PaToHva(Vm, Vm->BootCr3, (PVOID *)&L4)) {
        FATAL("PaToHva L4");
    }

    if (!L4[L4_IDX(Va)].Present) {
        if (!AllocatePa(Vm, &LowerLevelPa)) {
            return FALSE;
        }

        L4[L4_IDX(Va)].Present = 1;
        L4[L4_IDX(Va)].ReadWrite = 1;
        L4[L4_IDX(Va)].User = 1;
        L4[L4_IDX(Va)].Accessed = 1;
        L4[L4_IDX(Va)].Pfn = PA_TO_PFN(LowerLevelPa);
    } else {
        LowerLevelPa = PFN_TO_PA(L4[L4_IDX(Va)].Pfn);
    }

    //
    // L3.
    //

    if (!PaToHva(Vm, LowerLevelPa, (PVOID *)&L3)) {
        FATAL("PaToHva L3");
    }

    if (!L3[L3_IDX(Va)].Present) {
        if (!AllocatePa(Vm, &LowerLevelPa)) {
            return FALSE;
        }

        L3[L3_IDX(Va)].Present = 1;
        L3[L3_IDX(Va)].ReadWrite = 1;
        L3[L3_IDX(Va)].User = 1;
        L3[L3_IDX(Va)].Accessed = 1;
        L3[L3_IDX(Va)].Pfn = PA_TO_PFN(LowerLevelPa);
    } else {
        LowerLevelPa = PFN_TO_PA(L3[L3_IDX(Va)].Pfn);
    }

    //
    // L2.
    //

    if (!PaToHva(Vm, LowerLevelPa, (PVOID *)&L2)) {
        FATAL("PaToHva L2");
    }

    if (!L2[L2_IDX(Va)].Present) {
        if (!AllocatePa(Vm, &LowerLevelPa)) {
            return FALSE;
        }

        L2[L2_IDX(Va)].Present = 1;
        L2[L2_IDX(Va)].ReadWrite = 1;
        L2[L2_IDX(Va)].User = 1;
        L2[L2_IDX(Va)].Accessed = 1;
        L2[L2_IDX(Va)].Pfn = PA_TO_PFN(LowerLevelPa);
    } else {
        LowerLevelPa = PFN_TO_PA(L2[L2_IDX(Va)].Pfn);
    }

    //
    // L1.
    //

    if (!PaToHva(Vm, LowerLevelPa, (PVOID *)&L1)) {
        FATAL("PaToHva L1");
    }

    if (L1[L1_IDX(Va)].Present) {
        FATAL("L1 already present");
    }

    switch (MapType) {
    case MapTypeCode:
        L1[L1_IDX(Va)].Present = 1;
        L1[L1_IDX(Va)].Accessed = 1;
        L1[L1_IDX(Va)].Pfn = PA_TO_PFN(Pa);
        break;
    case MapTypeData:
        L1[L1_IDX(Va)].Present = 1;
        L1[L1_IDX(Va)].ReadWrite = 1;
        L1[L1_IDX(Va)].Accessed = 1;
        L1[L1_IDX(Va)].Dirty = 1;
        L1[L1_IDX(Va)].Pfn = PA_TO_PFN(Pa);
        L1[L1_IDX(Va)].NoExecute = 1;
        break;
    case MapTypeDataUser:
        L1[L1_IDX(Va)].Present = 1;
        L1[L1_IDX(Va)].ReadWrite = 1;
        L1[L1_IDX(Va)].User = 1;
        L1[L1_IDX(Va)].Accessed = 1;
        L1[L1_IDX(Va)].Dirty = 1;
        L1[L1_IDX(Va)].Pfn = PA_TO_PFN(Pa);
        L1[L1_IDX(Va)].NoExecute = 1;
        break;
    case MapTypeShadowStack:
        L1[L1_IDX(Va)].Present = 1;
        L1[L1_IDX(Va)].Accessed = 1;
        L1[L1_IDX(Va)].Dirty = 1;
        L1[L1_IDX(Va)].Pfn = PA_TO_PFN(Pa);
        L1[L1_IDX(Va)].NoExecute = 1;
        break;
    case MapTypeKeyHole:
        // Nothing: leave the leaf as non-present.
        break;
    }

    if (PdePage != NULL) {
        *PdePage = LowerLevelPa;
    }

    return TRUE;
}

BOOLEAN
MapRange(CORNELIUS_VM *Vm, UINT64 Va, UINT64 Pa, SIZE_T Size, enum MAP_TYPE MapType)
{
    while (Size > 0) {
        if (!MapPage(Vm, Va, Pa, MapType, NULL)) {
            return FALSE;
        }
        Va += PAGE_SIZE;
        Pa += PAGE_SIZE;
        Size -= PAGE_SIZE;
    }

    return TRUE;
}
