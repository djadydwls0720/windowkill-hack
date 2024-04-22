#pragma once


#ifndef A
#include "data.hpp"

//#include "communication.h"
//#define DbgMessage(x, ...) DbgPrintEx(0,0,x, __VA_ARGS__);


NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
VOID ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
#define IO_GET_CLIENTADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x666, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x667, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x668, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITES_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x66A, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_REQUEST_PROCESSID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x669, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_READ_CHAIN_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x66B, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_ADDRESS_CHAIN_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x66C, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)



NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp);

#define  A
#endif // !A


NTSTATUS Get_ClientAddress(PIRP irp) {
    PULONGLONG OutPut = (PULONGLONG)irp->AssociatedIrp.SystemBuffer;
    *OutPut = CSGOCClientDLLAddress;

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = sizeof(PULONGLONG);

    IoCompleteRequest(irp, IO_NO_INCREMENT);

    DbgPrintEx(0, 0, "Client request\n");
    return STATUS_SUCCESS;
}

NTSTATUS HandleReadMemory(PIRP irp) {
    PKENEL_READ_REQUEST ReadInput = (PKENEL_READ_REQUEST)irp->AssociatedIrp.SystemBuffer;
    PEPROCESS Process = NULL;
    DbgPrintEx(0, 0, "%llx\n", ReadInput->Address);

    if (!ReadInput->Address || !ReadInput->ProcessId) {
        DbgPrintEx(0, 0, "Process  0!\n");
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ReadInput->ProcessId, &Process))) {
        if (Process == NULL) {
            DbgPrintEx(0, 0, "notting\n");
            irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_UNSUCCESSFUL;
        }
        KernelReadVirtualMemory(Process, (PVOID)ReadInput->Address, ReadInput->pBuff, ReadInput->Size);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(KERNEL_READ_REQUEST);
    }

    return STATUS_SUCCESS;
}

NTSTATUS HandleWritesMemory(PIRP irp) {
    PKERNEL_WRITE_REQUEST WriteInput = (PKERNEL_WRITE_REQUEST)irp->AssociatedIrp.SystemBuffer;
    PEPROCESS Process;

    if (!WriteInput->Address || !WriteInput->ProcessId) {
        DbgPrintEx(0, 0, "Process  0!\n");
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)WriteInput->ProcessId, &Process))) {
        if (Process == NULL) {
            DbgPrintEx(0, 0, "notting\n");
            irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_UNSUCCESSFUL;
        }

        KernelWritesVirtualMemory(Process, (BYTE*)WriteInput->pBuff, (PVOID)WriteInput->Address, WriteInput->Size);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(KERNEL_WRITE_REQUEST);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS HandleAddressChain(PIRP irp) {
    PKERNEL_ADDRESS_CHAIN_REQUEST ReadChainInput = (PKERNEL_ADDRESS_CHAIN_REQUEST)irp->AssociatedIrp.SystemBuffer;
    PEPROCESS Process;

    if (!ReadChainInput->Address || !ReadChainInput->ProcessId) {
        DbgPrintEx(0, 0, "Process  0!\n");
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ReadChainInput->ProcessId, &Process))) {
        if (Process == NULL) {
            DbgPrintEx(0, 0, "notting\n");
            irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_UNSUCCESSFUL;
        }

        KernelGetAddressChainMemory(Process, ReadChainInput->pBuff, (PVOID)ReadChainInput->Address, ReadChainInput->Offset);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(PKERNEL_READ_CHAIN_REQUEST);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;

}

NTSTATUS HandleReadChainMemory(PIRP irp) {
    PKERNEL_READ_CHAIN_REQUEST ReadChainInput = (PKERNEL_READ_CHAIN_REQUEST)irp->AssociatedIrp.SystemBuffer;
    PEPROCESS Process;

    if (!ReadChainInput->Address || !ReadChainInput->ProcessId) {
        DbgPrintEx(0, 0, "Process  0!\n");
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ReadChainInput->ProcessId, &Process))) {
        if (Process == NULL) {
            DbgPrintEx(0, 0, "notting\n");
            irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrintEx(0, 0, "BaseAddress: %p", (PVOID)ReadChainInput->pBuff);

        KernelReadChainMemory(Process, ReadChainInput->pBuff, (PVOID)ReadChainInput->Address, ReadChainInput->Offset, ReadChainInput->Size);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(PKERNEL_READ_CHAIN_REQUEST);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;

}

NTSTATUS HandleWriteMemory(PIRP irp) {
    PKERNEL_WRITE_REQUEST WriteInput = (PKERNEL_WRITE_REQUEST)irp->AssociatedIrp.SystemBuffer;
    PEPROCESS Process;

    if (!WriteInput->Address || !WriteInput->ProcessId) {
        DbgPrintEx(0, 0, "Process  0!\n");
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)WriteInput->ProcessId, &Process))) {
        if (Process == NULL) {
            DbgPrintEx(0, 0, "notting\n");
            irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrintEx(0, 0, "writeAddr %p", (PVOID)WriteInput->Address);
        KernelWriteVirtualMemory(Process, WriteInput->pBuff, (PVOID)WriteInput->Address, WriteInput->Size);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(KERNEL_WRITE_REQUEST);
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS Get_ProcessId(PIRP irp) {
    PULONGLONG OutPut = (PULONGLONG)irp->AssociatedIrp.SystemBuffer;
    *OutPut = ProcessId_global;
    DbgPrintEx(0, 0, "process id rqeust %lld\n", ProcessId_global);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = sizeof(PULONGLONG);
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {

    if (wcsstr(FullImageName->Buffer, L"\\common\\Windowkill\\windowkill-vulkan.exe")) {

        DbgPrintEx(0, 0, "[*] ImageLoaded: %ls \n", FullImageName->Buffer);
        CSGOCClientDLLAddress = (ULONGLONG)ImageInfo->ImageBase;
        ProcessId_global = (ULONGLONG)ProcessId;
    }

}