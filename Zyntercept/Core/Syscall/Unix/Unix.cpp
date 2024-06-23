#include <Zyntercept/Core/Syscall/Unix/Unix.h>

ZyanBool __zyntercept_cdecl ZynterceptIs64BitSystemUnix()
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs32BitSystemUnix()
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs32BitProcessUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIs64BitProcessUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsUnsupportedProcessArchitectureUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptIsCurrentProcessUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptVirtualMemoryInformationUnix(
    __zyntercept_out ZynterceptPagedMemoryInformation* Information)
{
    return ZYAN_FALSE;
}

ZyanU64 __zyntercept_cdecl ZynterceptAllocateMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptReleaseMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptProtectMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptQueryMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptWriteMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Request)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptReadMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Request)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptFlushMicroprocessorCacheUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemory* MemoryBlock)
{
    return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptAtomicWriteMemoryUnix(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZynterceptPagedMemoryOperation* Operations,
    __zyntercept_in ZyanU32 NumberOfOperations)
{
    return ZYAN_FALSE;
}
