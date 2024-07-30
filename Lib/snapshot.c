// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "common.h"

typedef struct {
    PUINT64 DirtyGpasBitmap;
    PUINT64 MappedGpasBitmap;
    PUINT8 AddressSpaceHva;
    SEAM_STATE SeamldrState;
    CORNELIUS_VCPU Vcpus[];
} VM_SNAPSHOT;

VOID *
CreateSnapshot(CORNELIUS_VM *Vm)
{
    VM_SNAPSHOT *Snapshot;
    SIZE_T NumberOfUint64s;
    UINT64 Gpa;
    SIZE_T i;
    SIZE_T n;

    Snapshot = calloc(1, offsetof(VM_SNAPSHOT, Vcpus[Vm->VmConfig.NumberOfVcpus]));
    if (Snapshot == NULL) {
        return NULL;
    }

    //
    // Create the snapshot address space.
    //

    Snapshot->AddressSpaceHva = (PUINT8)VirtualAlloc(NULL, Vm->LastPa, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Snapshot->AddressSpaceHva == NULL) {
        return NULL;
    }

    //
    // GPAs bitmaps.
    //

    Snapshot->DirtyGpasBitmap = malloc(GPAS_BITMAP_SIZE(Vm));
    if (Snapshot->DirtyGpasBitmap == NULL) {
        return NULL;
    }

    memcpy(Snapshot->DirtyGpasBitmap, Vm->DirtyGpasBitmap, GPAS_BITMAP_SIZE(Vm));

    Snapshot->MappedGpasBitmap = malloc(GPAS_BITMAP_SIZE(Vm));
    if (Snapshot->MappedGpasBitmap == NULL) {
        return NULL;
    }

    memcpy(Snapshot->MappedGpasBitmap, Vm->MappedGpasBitmap, GPAS_BITMAP_SIZE(Vm));

    //
    // Copy each dirty GPA into the snapshot address space.
    //

    NumberOfUint64s = GPAS_BITMAP_SIZE(Vm) / sizeof(UINT64);

    for (i = 0; i < NumberOfUint64s; i++) {
        if (Snapshot->DirtyGpasBitmap[i] == 0ULL) {
            continue;
        }
        for (n = 0; n < 64; n++) {
            if (!(Snapshot->DirtyGpasBitmap[i] & (1ULL << n))) {
                continue;
            }

            Gpa = (i * 64ULL + n) * PAGE_SIZE;

            memcpy(Snapshot->AddressSpaceHva + Gpa,
                   Vm->AddressSpaceHva + Gpa,
                   PAGE_SIZE);
        }
    }

    //
    // Copy the VCPUs.
    //

    memcpy(Snapshot->Vcpus, Vm->Vcpus, Vm->VmConfig.NumberOfVcpus * sizeof(CORNELIUS_VCPU));

    //
    // Copy the P-SEAMLDR state.
    //

    memcpy(&Snapshot->SeamldrState, &Vm->SeamldrState, sizeof(SEAM_STATE));

    return Snapshot;
}

VOID
RestoreSnapshot(CORNELIUS_VM *Vm, VOID *_Snapshot)
{
    VM_SNAPSHOT *Snapshot = (VM_SNAPSHOT *)_Snapshot;
    SIZE_T NumberOfUint64s;
    CORNELIUS_VCPU *Vcpu;
    UINT64 VmcsPtr;
    UINT64 Gpa;
    SIZE_T i;
    SIZE_T n;

    //
    // Restore the GPAs using the DirtyGpasBitmap.
    //

    NumberOfUint64s = GPAS_BITMAP_SIZE(Vm) / sizeof(UINT64);

    for (i = 0; i < NumberOfUint64s; i++) {
        if (Snapshot->DirtyGpasBitmap[i] == 0ULL && Vm->DirtyGpasBitmap[i] == 0ULL) {
            continue;
        }

        for (n = 0; n < 64; n++) {
            Gpa = (i * 64ULL + n) * PAGE_SIZE;

            //
            // If the GPA was dirty in the snapshot, restore the page.
            //
            // If the GPA was not dirty in the snapshot, but is currently dirty,
            // zero out the page.
            //

            if (Snapshot->DirtyGpasBitmap[i] & (1ULL << n)) {
                memcpy(Vm->AddressSpaceHva + Gpa,
                       Snapshot->AddressSpaceHva + Gpa,
                       PAGE_SIZE);
            } else if (Vm->DirtyGpasBitmap[i] & (1ULL << n)) {
                memset(Vm->AddressSpaceHva + Gpa,
                       0,
                       PAGE_SIZE);
            }
        }
    }

    memcpy(Vm->DirtyGpasBitmap, Snapshot->DirtyGpasBitmap, GPAS_BITMAP_SIZE(Vm));

    //
    // Map the Keyid 0 pages according to the MappedGpasBitmap.
    //

    for (i = 0; i < NumberOfUint64s; i++) {
        if (Snapshot->MappedGpasBitmap[i] == Vm->MappedGpasBitmap[i]) {
            continue;
        }

        for (n = 0; n < 64; n++) {
            Gpa = (i * 64ULL + n) * PAGE_SIZE;

            //
            // If the GPA was mapped in the snapshot, but is not currently mapped,
            // map it.
            //
            // If the GPA was not mapped in the snapshot, but is currently mapped,
            // unmap it.
            //

            if (Snapshot->MappedGpasBitmap[i] & (1ULL << n)) {
                if (!(Vm->MappedGpasBitmap[i] & (1ULL << n))) {
                    MapGpa(Vm, Gpa, PAGE_SIZE);
                }
            } else if (Vm->MappedGpasBitmap[i] & (1ULL << n)) {
                UnmapGpa(Vm, Gpa, PAGE_SIZE);
            }
        }

        if (Snapshot->MappedGpasBitmap[i] != Vm->MappedGpasBitmap[i]) {
            FATAL("MappedGpasBitmap should be the same");
        }
    }

    //
    // Map the active Keyids.
    //

    for (i = 0; i < NUM_KEYIDS; i++) {
        if (Vm->KeyidActive & (1UL << i)) {
            MapCmrsInKeyidSpace(Vm, (UINT16)i);
        }
    }

    //
    // Restore the VCPUs.
    //

    memcpy(Vm->Vcpus, Snapshot->Vcpus, Vm->VmConfig.NumberOfVcpus * sizeof(CORNELIUS_VCPU));

    //
    // Unmap the cached VMCSs.
    //

    for (i = 0; i < Vm->VmConfig.NumberOfVcpus; i++) {
        Vcpu = &Vm->Vcpus[i];

        for (n = 0; n < VMCS_CACHE_SIZE; n++) {
            VmcsPtr = Vcpu->VmcsCache[n];

            if (VmcsPtr == 0) {
                continue;
            }
            if (VmcsPtr != GetPseamldrEntryVmcsPtr(Vm)) {
                UnmapGpa(Vm, VmcsPtr, PAGE_SIZE);
            }
        }
    }

    //
    // Restore the P-SEAMLDR state.
    //

    memcpy(&Vm->SeamldrState, &Snapshot->SeamldrState, sizeof(SEAM_STATE));
}