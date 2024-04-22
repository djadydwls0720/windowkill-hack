#include "start.h"

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;

    IoCompleteRequest(irp, IO_NO_INCREMENT);// 드라이버 IRP 처리 완료 알림 함수

    DbgPrintEx(0, 0, "CreateCall was called, connection enstablishad!");

    return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;


    IoCompleteRequest(irp, IO_NO_INCREMENT);
    DbgPrintEx(0, 0, "Connection Terminate!");

    return STATUS_SUCCESS;
}


NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);// I/O 스택 위치를 얻습니다. 이를 통해 IOCTL 코드를 포함한 요청의 상세 정보 접근

    ULONG Controlcode = stack->Parameters.DeviceIoControl.IoControlCode;

    if (Controlcode == IO_GET_CLIENTADDRESS)
        Status = Get_ClientAddress(irp);

    else if (Controlcode == IO_READ_REQUEST)
        Status = HandleReadMemory(irp);

    else if (Controlcode == IO_WRITE_REQUEST)
        Status = HandleWriteMemory(irp);

    else if (Controlcode == IO_WRITES_REQUEST)
        Status = HandleWritesMemory(irp);

    else if (Controlcode == IO_REQUEST_PROCESSID)
        Status = Get_ProcessId(irp);

    else if (Controlcode == IO_ADDRESS_CHAIN_REQUEST)
        Status = HandleAddressChain(irp);

    else if (Controlcode == IO_READ_CHAIN_REQUEST)
        Status = HandleReadChainMemory(irp);

    return Status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
    pDriverObject->DriverUnload = UnloadDriver;
    UNREFERENCED_PARAMETER(pRegistryPath);

    PsSetLoadImageNotifyRoutine(ImageLoadCallback);

    RtlInitUnicodeString(&dev, L"\\Device\\guidhak");
    RtlInitUnicodeString(&dos, L"\\??\\guidhak");

    IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
    IoCreateSymbolicLink(&dos, &dev);


    pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;



    pDeviceObject->Flags |= DO_DIRECT_IO;
    pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrintEx(0, 0, "[*] load sex");
    return STATUS_SUCCESS;
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject) {
    UNREFERENCED_PARAMETER(pDriverObject);

    DbgPrintEx(0, 0, "[*] unload sex");
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);

    IoDeleteSymbolicLink(&dos);
    IoDeleteDevice(pDriverObject->DeviceObject);

    return STATUS_SUCCESS;

}