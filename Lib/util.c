// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "common.h"

VOID
LogVcpuTdxDebug(CORNELIUS_VM* Vm, UINT32 VcpuNum, char* msg, ...)
{
    va_list argp;

    UNREFERENCED_PARAMETER(Vm);

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);

    printf("[+][VCPU%u][DBG] ", VcpuNum);

    va_start(argp, msg);
    vprintf(msg, argp);
    va_end(argp);

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
}

VOID
LogVcpuOk(CORNELIUS_VM *Vm, UINT32 VcpuNum, char *msg, ...)
{
    va_list argp;

    if (GetVcpuLogLevel(Vm, VcpuNum) == 0) {
        return;
    }

    if (IsVcpuSeamldr(Vm, VcpuNum)) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
    } else {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);
    }

    printf("[+][VCPU%u] ", VcpuNum);

    va_start(argp, msg);
    vprintf(msg, argp);
    va_end(argp);

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
}

VOID
LogVcpuErr(CORNELIUS_VM *Vm, UINT32 VcpuNum, char *msg, ...)
{
    va_list argp;

    UNREFERENCED_PARAMETER(Vm);

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);

    printf("[!][VCPU%u] ", VcpuNum);

    va_start(argp, msg);
    vprintf(msg, argp);
    va_end(argp);

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
}