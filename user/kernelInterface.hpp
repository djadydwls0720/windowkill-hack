#include "Windows.h"
#include "stdio.h"
#include <iostream>
#include "data.h"


#define IO_GET_CLIENTADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x666, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x667, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x668, METHOD_BUFFERED,FILE_SPECIAL_ACCESS)
#define IO_REQUEST_PROCESSID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x669, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITES_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x66A   , METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_READ_CHAIN_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x66B, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_ADDRESS_CHAIN_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x66C, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

class KernelInterface {
public:
    HANDLE hDriver;

    KernelInterface(LPCSTR RegistryPath) {
        hDriver = CreateFileA(RegistryPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    }

    ULONGLONG GetClientAddress() {
        if (hDriver == INVALID_HANDLE_VALUE) {
            return 0;
        }

        ULONGLONG Address = NULL;
        DWORD Byte;

        if (DeviceIoControl(hDriver, IO_GET_CLIENTADDRESS, &Address, sizeof(Address), &Address, sizeof(Address), &Byte, NULL)) {
            return Address;
        }
        return Address;
    }


    template <typename type>
    type ReadVitualMemory(ULONGLONG ProcessId, ULONGLONG ReadAddress, SIZE_T Size) {
        type Buffer;

        KERNEL_READ_REQUEST ReadRequest;


        ReadRequest.ProcessId = ProcessId;
        ReadRequest.Address = ReadAddress;
        ReadRequest.pBuff = &Buffer;
        ReadRequest.Size = Size;


        if (DeviceIoControl(hDriver, IO_READ_REQUEST, &ReadRequest, sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), 0, 0)) {
            return Buffer;
        }
        return Buffer;

    }

    template <typename type>
    type ReadChainVitualMemory(ULONGLONG ProcessId, ULONGLONG ReadAddress, ULONGLONG* Offset, SIZE_T Size) {
        type Buffer;

        KERNEL_READ_CHAIN_REQUEST ReadRequest;


        ReadRequest.ProcessId = ProcessId;
        ReadRequest.Address = ReadAddress;
        ReadRequest.Offset = Offset;
        ReadRequest.pBuff = &Buffer;
        printf("%p", &Buffer);
        ReadRequest.Size = Size;
        if (DeviceIoControl(hDriver, IO_READ_CHAIN_REQUEST, &ReadRequest, sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), 0, 0)) {
            return Buffer;
        }
        return Buffer;

    }
    ULONGLONG GetAddressChainVitualMemory(ULONGLONG ProcessId, ULONGLONG ReadAddress, ULONGLONG* Offset) {
        ULONGLONG Buffer;

        KERNEL_ADDRESS_CHAIN_REQUEST ReadRequest;


        ReadRequest.ProcessId = ProcessId;
        ReadRequest.Address = ReadAddress;
        ReadRequest.Offset = Offset;
        ReadRequest.pBuff = &Buffer;
        printf("%p", &Buffer);
        if (DeviceIoControl(hDriver, IO_ADDRESS_CHAIN_REQUEST, &ReadRequest, sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), 0, 0)) {
            return Buffer;
        }
        return Buffer;

    }


    template <typename type>
    bool WriteVituralMemory(ULONGLONG ProcessId, ULONGLONG WriteAddress, type WriteValue, SIZE_T Size) {
        if (hDriver == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD Bytes;
        KERNEL_WRITE_REQUEST WriteRequest;

        WriteRequest.ProcessId = ProcessId;
        WriteRequest.Address = WriteAddress;
        WriteRequest.pBuff = &WriteValue;
        WriteRequest.Size = Size;

        if (DeviceIoControl(hDriver, IO_WRITE_REQUEST, &WriteRequest, sizeof(WriteRequest), 0, 0, &Bytes, NULL)) {
            return true;
        }

        return false;

    }

    bool WritesVituralMemory(ULONGLONG ProcessId, ULONGLONG WriteAddress, BYTE* WriteValue, SIZE_T Size) {
        if (hDriver == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD Bytes;
        KERNEL_WRITE_REQUEST WriteRequest;

        WriteRequest.ProcessId = ProcessId;
        WriteRequest.Address = WriteAddress;
        WriteRequest.pBuff = WriteValue;
        WriteRequest.Size = Size;

        if (DeviceIoControl(hDriver, IO_WRITES_REQUEST, &WriteRequest, sizeof(WriteRequest), 0, 0, &Bytes, NULL)) {
            return true;
        }

        return false;
    }

    LONGLONG GetProcessId() {
        if (hDriver == INVALID_HANDLE_VALUE) {
            return 0;
        }

        LONGLONG ProcessId;
        DWORD Bytes;

        if (DeviceIoControl(hDriver, IO_REQUEST_PROCESSID, &ProcessId, sizeof(ProcessId), &ProcessId, sizeof(ProcessId), &Bytes, NULL)) {
            return ProcessId;
        }

        return ProcessId;
    }
};