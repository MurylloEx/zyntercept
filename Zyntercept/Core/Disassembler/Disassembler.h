#ifndef ZYNTERCEPT_DISASSEMBLER_H
#define ZYNTERCEPT_DISASSEMBLER_H

#include <Zyntercept/Core/Common/Common.h>

typedef struct ZydisDecoded_
{
    ZydisDecodedInstruction Instruction;
    ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
} ZydisDecoded;

typedef enum ZydisBranchFlow_
{
    ZYDIS_BRANCH_FLOW_GREEN,
    ZYDIS_BRANCH_FLOW_RED
} ZydisBranchFlow;

#pragma pack(push, 8)

typedef struct ZydisBranch_
{
    ZyanU64 Base;
    ZyanU64 Address;
    ZyanU64 Destination;
    ZydisMnemonic Mnemonic;
    ZydisBranchFlow Flow;

    bool operator==(const ZydisBranch_ &Value) const
    {
        return Value.Address == Address && Value.Flow == Flow;
    }
} ZydisBranch;

#pragma pack(pop)

ZyanBool __zyntercept_cdecl IsRelative(
    __zyntercept_in ZydisDecoded *DecodedInstruction);

ZyanBool __zyntercept_cdecl IsRet(
    __zyntercept_in ZydisDecoded *DecodedInstruction);

ZyanBool __zyntercept_cdecl IsCall(
    __zyntercept_in ZydisDecoded *DecodedInstruction,
    __zyntercept_out ZydisDecodedOperand **ImmediateOperand);

ZyanBool __zyntercept_cdecl IsJcc(
    __zyntercept_in ZydisDecoded *DecodedInstruction,
    __zyntercept_out ZydisDecodedOperand **ImmediateOperand);

ZyanBool __zyntercept_cdecl IsJmp(
    __zyntercept_in ZydisDecoded *DecodedInstruction,
    __zyntercept_out ZydisDecodedOperand **ImmediateOperand);

ZyanU64 __zyntercept_cdecl SizeOfDecodedDesiredInstructions(
    __zyntercept_in ZydisMachineMode MachineMode,
    __zyntercept_in ZydisStackWidth StackWidth,
    __zyntercept_in ZyanU8 *Buffer,
    __zyntercept_in ZyanUSize BufferSize,
    __zyntercept_in ZyanU32 DesiredSize);

ZyanBool __zyntercept_cdecl FindReplaceableInstructions(
    __zyntercept_in ZydisMachineMode MachineMode,
    __zyntercept_in ZydisStackWidth StackWidth,
    __zyntercept_in ZyanU8 *Buffer,
    __zyntercept_in ZyanUSize BufferSize,
    __zyntercept_in ZyanU32 SizeOfDetour,
    __zyntercept_in ZyanU64 SizeOfDecodedBuffer,
    __zyntercept_out ZydisDecoded *DecodedBuffer,
    __zyntercept_out ZyanU64 *NumberOfFoundInstructions,
    __zyntercept_out ZyanUSize *SizeOfFoundInstructions);

ZyanBool __zyntercept_cdecl FindNextFunctionBranch(
    __zyntercept_in ZydisMachineMode MachineMode,
    __zyntercept_in ZydisStackWidth StackWidth,
    __zyntercept_in ZyanU8 *Buffer,
    __zyntercept_in ZyanUSize BufferSize,
    __zyntercept_in ZyanU64 BaseAddress,
    __zyntercept_out ZydisDecoded *BranchInstruction,
    __zyntercept_out ZyanU64 *InstructionAddress,
    __zyntercept_out ZyanU64 *GreenBranchAddress,
    __zyntercept_out ZyanU64 *RedBranchAddress);

ZyanBool __zyntercept_cdecl FindFunctionBranchs(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZydisMachineMode MachineMode,
    __zyntercept_in ZydisStackWidth StackWidth,
    __zyntercept_in ZyanU64 BaseAddress,
    __zyntercept_out ZydisBranch **FoundBranchs,
    __zyntercept_out ZyanU64 *NumberOfFoundBranchs);

ZyanBool __zyntercept_cdecl HasFunctionBranchDestinationsBetween(
    __zyntercept_in ZyanVoidPointer ProcessIdentifier,
    __zyntercept_in ZydisMachineMode MachineMode,
    __zyntercept_in ZydisStackWidth StackWidth,
    __zyntercept_in ZyanU64 BaseAddress,
    __zyntercept_in ZyanU64 BeginAddress,
    __zyntercept_in ZyanU64 EndAddress);

#endif // ZYNTERCEPT_DISASSEMBLER_H
