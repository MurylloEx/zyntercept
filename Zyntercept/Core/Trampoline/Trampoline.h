#ifndef ZYNTERCEPT_TRAMPOLINE_H
#define ZYNTERCEPT_TRAMPOLINE_H

#include <Zyntercept/Core/Common/Common.h>
#include <Zyntercept/Core/Disassembler/Disassembler.h>

ZyanBool __zyntercept_cdecl ZynterceptCompileTrampoline64(
    __zyntercept_in ZyanU64 TargetFunction,
    __zyntercept_in ZyanU64 TrampolineAddress,
    __zyntercept_out ZyanU8* TrampolineBuffer,
    __zyntercept_in ZyanU64 TrampolineBufferSize,
    __zyntercept_in ZydisDecoded* PrologueInstructions,
    __zyntercept_in ZyanU64 NumberOfPrologueInstructions);

ZyanBool __zyntercept_cdecl ZynterceptCompileTrampoline32(
    __zyntercept_in ZyanU64 TargetFunction,
    __zyntercept_in ZyanU64 TrampolineAddress,
    __zyntercept_out ZyanU8* TrampolineBuffer,
    __zyntercept_in ZyanU64 TrampolineBufferSize,
    __zyntercept_in ZydisDecoded* PrologueInstructions,
    __zyntercept_in ZyanU64 NumberOfPrologueInstructions);

#endif // ZYNTERCEPT_TRAMPOLINE_H
