#include <Zyntercept/Core/Syscall/Linux/Linux.h>

ZyanBool __zyntercept_cdecl ZynterceptIs64BitSystemLinux()
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs32BitSystemLinux()
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs32BitProcessLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs64BitProcessLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsUnsupportedProcessArchitectureLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsCurrentProcessLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptVirtualMemoryInformationLinux(
    __zyntercept_out ZynterceptPagedMemoryInformation* Information)
{
    return ZYAN_FALSE;
}

ZyanU64 __zyntercept_cdecl ZynterceptAllocateMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptReleaseMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptProtectMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptQueryMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptWriteMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Request)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptReadMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Request)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptFlushMicroprocessorCacheLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptAtomicWriteMemoryLinux(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operations,
    __zyntercept_in ZyanU32 NumberOfOperations)
{
    return ZYAN_FALSE;
}
