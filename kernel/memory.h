#pragma once
#include <ntifs.h>
#include <ntdef.h>
#include <windef.h>
#pragma warning (disable: 4047 4024 4213)

NTSTATUS ZwProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    SIZE_T* NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);


NTSTATUS KernelReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
    PSIZE_T Bytes = NULL;
    NTSTATUS status;
    HANDLE ProcessHandle;
    PVOID SourceAddress_copy = SourceAddress;
    PVOID SourceAddress_copy2 = SourceAddress;
    ULONG OldProtect;
    SIZE_T Size2 = Size;
    __try {
        status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
        if (!NT_SUCCESS(status))
            DbgPrintEx(0, 0, "ObOpenObjectByPointer error: %x", status);

        status = ZwProtectVirtualMemory(ProcessHandle, &SourceAddress_copy, &Size2, PAGE_EXECUTE_READWRITE, &OldProtect);
        if (!NT_SUCCESS(status))
            DbgPrintEx(0, 0, "ZwProtectVirtualMemory error: %x", status);

        status = MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, &Bytes);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(0, 0, "error: %x", status);
        }

        status = ZwProtectVirtualMemory(ProcessHandle, &SourceAddress_copy2, &Size2, OldProtect, NULL);
        if (!NT_SUCCESS(status))
            DbgPrintEx(0, 0, "ZwProtectVirtualMemory error: %x", status);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(0, 0, "KernelReadVirtualMemory Exception: %x", status);

    }



    return STATUS_SUCCESS;
}


NTSTATUS KernelWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
    PVOID TargetAddress_copy = TargetAddress;
    PVOID TargetAddress_copy2 = TargetAddress;
    PSIZE_T Bytes = NULL;
    NTSTATUS status;
    HANDLE ProcessHandle;
    ULONG OldProtect;
    SIZE_T Size2 = Size;

    __try {
        status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
        if (!NT_SUCCESS(status))
            DbgPrintEx(0, 0, "ObOpenObjectByPointer error: %x", status);

        status = ZwProtectVirtualMemory(ProcessHandle, &TargetAddress_copy, &Size2, PAGE_EXECUTE_READWRITE, &OldProtect);
        if (!NT_SUCCESS(status))
            DbgPrintEx(0, 0, "ZwProtectVirtualMemory error: %x", status);

        status = MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, &Bytes);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(0, 0, "error: %x", status);
        }
        DbgPrintEx(0, 0, "write: %p buf: %x", TargetAddress, (ULONGLONG*)SourceAddress);

        status = ZwProtectVirtualMemory(ProcessHandle, &TargetAddress_copy2, &Size2, OldProtect, NULL);
        if (!NT_SUCCESS(status))
            DbgPrintEx(0, 0, "ZwProtectVirtualMemory error: %x", status);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(0, 0, "Exception: %x", status);

    }
    return STATUS_SUCCESS;
}

NTSTATUS KernelGetAddressChainMemory(PEPROCESS Process, PVOID SourceAddress, ULONGLONG TargetAddress, ULONGLONG* Offset) {
    SIZE_T size = 8;
    PULONGLONG offset = Offset;
    NTSTATUS status = 0;
    ULONGLONG TempAddress = (ULONGLONG)TargetAddress;
    ULONGLONG TempAddress2 = 0;
    DbgPrintEx(0, 0, "rkqt: %p", SourceAddress);
    DbgPrintEx(0, 0, "TargetAddress: %llx", TempAddress);
    __try {

        for (int i = 0; offset[i] != 0; i++) {
            if (offset[i + 1] == 0) {
                TempAddress += offset[i];
                break;
            }
            TempAddress += offset[i];
            status = KernelReadVirtualMemory(Process, (PVOID)TempAddress, (PVOID)&TempAddress2, size);
            DbgPrintEx(0, 0, "TempAddress2: %llx", TempAddress2);
            TempAddress = TempAddress2;
        }
        *(ULONGLONG*)SourceAddress = TempAddress;
        DbgPrintEx(0, 0, "rkqt point: %p", SourceAddress);
        DbgPrintEx(0, 0, "rkqt: %x", (*(ULONGLONG*)SourceAddress));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(0, 0, "KernelReadChainMemory Exception: %x", status);
    }

    return STATUS_SUCCESS;
}

NTSTATUS KernelReadChainMemory(PEPROCESS Process, PVOID SourceAddress, ULONGLONG TargetAddress, ULONGLONG* Offset, SIZE_T Size) {
    UNREFERENCED_PARAMETER(Size);
    SIZE_T size = 8;
    PULONGLONG offset = Offset;
    NTSTATUS status = 0;
    ULONGLONG TempAddress = (ULONGLONG)TargetAddress;
    ULONGLONG TempAddress2 = 0;
    DbgPrintEx(0, 0, "rkqt: %p", SourceAddress);
    DbgPrintEx(0, 0, "TargetAddress: %llx", TempAddress);
    __try {

        for (int i = 0; offset[i] != 0; i++) {
            TempAddress += offset[i];
            status = KernelReadVirtualMemory(Process, (PVOID)TempAddress, (PVOID)&TempAddress2, size);
            DbgPrintEx(0, 0, "TempAddress2: %llx", TempAddress2);

            TempAddress = TempAddress2;
        }
        *(ULONGLONG*)SourceAddress = TempAddress;
        DbgPrintEx(0, 0, "rkqt point: %p", SourceAddress);
        DbgPrintEx(0, 0, "rkqt: %x", (*(ULONGLONG*)SourceAddress));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(0, 0, "KernelReadChainMemory Exception: %x", status);

    }


    return STATUS_SUCCESS;

}

NTSTATUS KernelWritesVirtualMemory(PEPROCESS Process, BYTE* SourceAddress, ULONGLONG TargetAddress, SIZE_T Size) {
    PVOID TargetAddress_copy = (PVOID)TargetAddress;
    PVOID TargetAddress_copy2 = (PVOID)TargetAddress;
    PSIZE_T Bytes = NULL;
    NTSTATUS status;
    HANDLE ProcessHandle;
    ULONG OldProtect;
    SIZE_T Size2 = Size;
    ULONGLONG j = (int)Size;

    __try {
        status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);
        if (!NT_SUCCESS(status))
            DbgPrintEx(0, 0, "ObOpenObjectByPointer error: %x", status);

        status = ZwProtectVirtualMemory(ProcessHandle, &TargetAddress_copy, &Size2, PAGE_EXECUTE_READWRITE, &OldProtect);
        //ZwProtectVirtualMemory(ProcessHandle, &TargetAddress, &Size2, PAGE_EXECUTE_READWRITE, &OldProtect);
        if (!NT_SUCCESS(status))
            DbgPrintEx(0, 0, "ZwProtectVirtualMemory error: %x", status);




        for (ULONGLONG i = 0; i < j; i++) {

            status = MmCopyVirtualMemory(PsGetCurrentProcess(), (BYTE*)(SourceAddress + i), Process, (PVOID)TargetAddress, 1, KernelMode, &Bytes);
            if (!NT_SUCCESS(status))
                DbgPrintEx(0, 0, "error: %x", status);
            DbgPrintEx(0, 0, "write: %p buf: %p", TargetAddress, SourceAddress + i);
            TargetAddress += 1;
        }






        status = ZwProtectVirtualMemory(ProcessHandle, &TargetAddress_copy2, &Size2, OldProtect, NULL);
        if (!NT_SUCCESS(status))
            DbgPrintEx(0, 0, "ZwProtectVirtualMemory error: %x", status);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrintEx(0, 0, "Exception: %x", status);

    }
    return STATUS_SUCCESS;
}