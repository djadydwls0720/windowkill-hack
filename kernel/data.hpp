#pragma once
#include "memory.h"

ULONGLONG ProcessId_global;
ULONGLONG CSGOCClientDLLAddress;
UNICODE_STRING dev;
UNICODE_STRING dos;
PDEVICE_OBJECT pDeviceObject = NULL;

typedef struct _KERNEL_READ_REQUEST {
    ULONGLONG ProcessId;
    ULONGLONG Address;
    PVOID pBuff;
    SIZE_T Size;

} KERNEL_READ_REQUEST, * PKENEL_READ_REQUEST;

typedef struct _KERNEL_READ_CHAIN_REQUEST {
    ULONGLONG ProcessId;
    ULONGLONG Address;
    ULONGLONG* Offset;
    PVOID pBuff;
    SIZE_T Size;

} KERNEL_READ_CHAIN_REQUEST, * PKERNEL_READ_CHAIN_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
    ULONGLONG ProcessId;
    ULONGLONG Address;
    PVOID pBuff;
    SIZE_T Size;

} KERNEL_WRITE_REQUEST, * PKERNEL_WRITE_REQUEST;

typedef struct _KERNEL_ADDRESS_CHAIN_REQUEST {
    ULONGLONG ProcessId;
    ULONGLONG Address;
    ULONGLONG* Offset;
    PVOID pBuff;

} KERNEL_ADDRESS_CHAIN_REQUEST, * PKERNEL_ADDRESS_CHAIN_REQUEST;