#include "kernelInterface.hpp"
typedef struct _Fuck
{
    BYTE fuck[1024];
} Fuck;

int main() {
    KernelInterface hDriver = KernelInterface("\\\\.\\guidhak");

    ULONGLONG processId = hDriver.GetProcessId();
    printf("%lld\n", processId);
    ULONGLONG Address = hDriver.GetClientAddress();
    printf("%llx\n", Address);
    ULONGLONG MONEY_OFFSET2[] = { 0x3401AF0,0x60, 0x238, 0x1c0,0x8, 0x68, 0x28, 0x410,0 };
    ULONGLONG MONEY_OFFSET3[] = { 0x33ea4c0,0x60, 0x238, 0x1c0,0x8, 0x68, 0x28, 0x410,0 };
    ULONGLONG MONEY_OFFSET[] = { 0x341C0B0,0x60, 0x238, 0x1c0,0x8, 0x68, 0x28, 0x410,0 };


    ULONGLONG HP_OFFSET[] = { 0x33EA4C0,0x348, 0x288, 0x1c0,0x8, 0x68, 0x28, 0XA88,0 };


    uint64_t MONEY_ADDRESS = hDriver.GetAddressChainVitualMemory(processId, Address, MONEY_OFFSET);
    if (MONEY_ADDRESS < 100000) {
        uint64_t MONEY_ADDRESS = hDriver.GetAddressChainVitualMemory(processId, Address, MONEY_OFFSET2);
        hDriver.WriteVituralMemory<int>(processId, MONEY_ADDRESS, 0xffffff, 4);
    }
    int b = hDriver.ReadVitualMemory<int>(processId, MONEY_ADDRESS, 4);
    hDriver.WriteVituralMemory<int>(processId, MONEY_ADDRESS, 0xffffff, 4);

    uint64_t HP_ADDRESS = hDriver.GetAddressChainVitualMemory(processId, Address, HP_OFFSET);
    printf("%llx\n", HP_ADDRESS);
    hDriver.WriteVituralMemory<int>(processId, HP_ADDRESS, 0xffffff, 4);


}