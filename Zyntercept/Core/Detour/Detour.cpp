#include <Zyntercept/Core/Detour/Detour.h>
#include <Zyntercept/Core/Allocator/Allocator.h>
#include <Zyntercept/Core/Trampoline/Trampoline.h>
#include <Zyntercept/Core/Assembler/Assembler.h>
#include <Zyntercept/Core/Disassembler/Disassembler.h>

/* Size of <jmp rel32> instruction */
#define ZYNTERCEPT_SIZE_OF_DETOUR_JUMP 5
#define ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_64BIT 0x100
#define ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_32BIT 0x80

ZyanBool __zyntercept_cdecl ZynterceptDetourFunction64(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 HookedFunction,
	__zyntercept_out ZyanU64* TrampolineFunction,
	__zyntercept_out ZyanU8** OriginalPrologue,
	__zyntercept_out ZyanU64* OriginalPrologueSize)
{
	std::vector<ZyanU8> PayloadBuffer = {};

	ZydisMachineMode MachineMode = ZYDIS_MACHINE_MODE_LONG_64;
	ZydisStackWidth StackWidth = ZYDIS_STACK_WIDTH_64;

	ZyanU8 PrologueBuffer[64] = { 0 };
	ZyanU8 RelayBuffer[64] = { 0 };
	ZyanU8 TrampolineBuffer[192] = { 0 };

	ZyanU64 NumberOfFoundInstructions = 0;
	ZyanUSize SizeOfFoundInstructions = 0;

	ZynterceptPagedMemory Page = { 0 };
	ZynterceptPagedMemoryOperation Operation = { 0 };
	ZynterceptPagedMemoryOperation Operations[2] = { 0 };

	Operation.Address = TargetFunction;
	Operation.Buffer = PrologueBuffer;
	Operation.Size = sizeof(PrologueBuffer);

	if (!ZynterceptReadMemory(ProcessIdentifier, &Operation))
	{
		return ZYAN_FALSE;
	}

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		MachineMode,
		StackWidth,
		PrologueBuffer,
		sizeof(PrologueBuffer),
		ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

	if (!SizeOfDecodedInstructions)
	{
		return ZYAN_FALSE;
	}

	ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)malloc(SizeOfDecodedInstructions);

	if (!ReplaceableInstructions)
	{
		return ZYAN_FALSE;
	}

	if (!FindReplaceableInstructions(
		MachineMode,
		StackWidth,
		PrologueBuffer,
		sizeof(PrologueBuffer),
		ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
		SizeOfDecodedInstructions,
		ReplaceableInstructions,
		&NumberOfFoundInstructions,
		&SizeOfFoundInstructions))
	{
		free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	if (HasFunctionBranchDestinationsBetween(
		ProcessIdentifier,
		MachineMode,
		StackWidth,
		TargetFunction,
		TargetFunction + 1,
		TargetFunction + SizeOfFoundInstructions))
	{
		free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	ZyanU8* OriginalPrologueBuffer = (ZyanU8*)malloc(SizeOfFoundInstructions);

	if (!OriginalPrologueBuffer) {
		free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	memcpy(OriginalPrologueBuffer, PrologueBuffer, SizeOfFoundInstructions);

	ZyanU64 NearPageAddress = ZynterceptAllocateNearestAddress(
		ProcessIdentifier,
		TargetFunction,
		ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_64BIT,
		ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED,
		ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_EXECUTE);

	if (!NearPageAddress)
	{
		free(ReplaceableInstructions);
		free(OriginalPrologueBuffer);
		return ZYAN_FALSE;
	}

	ZyanU64 TrampolineAddress = NearPageAddress;
	ZyanU64 RelayAddress = NearPageAddress + 192;

	std::shared_ptr<AssemblyBuilder> PrologueBuilder = std::make_shared<AssemblyBuilder>(TargetFunction);
	std::shared_ptr<AssemblyBuilder> RelayBuilder = std::make_shared<AssemblyBuilder>(RelayAddress);

	PrologueBuilder->Jmp32(RelayAddress);
	RelayBuilder->Jmp64(HookedFunction);

	if (!ZynterceptCompileTrampoline64(
		TargetFunction,
		TrampolineAddress,
		TrampolineBuffer,
		sizeof(TrampolineBuffer),
		ReplaceableInstructions,
		NumberOfFoundInstructions))
	{
		goto FAILURE;
	}

	if (PrologueBuilder->Failed() || RelayBuilder->Failed())
	{
		goto FAILURE;
	}

	if (SizeOfFoundInstructions > PrologueBuilder->Size())
	{
		PrologueBuilder->Nop(SizeOfFoundInstructions - PrologueBuilder->Size());
	}

	if (sizeof(RelayBuffer) > RelayBuilder->Size())
	{
		RelayBuilder->Nop(sizeof(RelayBuffer) - RelayBuilder->Size());
	}

	if (!PrologueBuilder->CopyTo(PrologueBuffer, sizeof(PrologueBuffer)) ||
		!RelayBuilder->CopyTo(RelayBuffer, sizeof(RelayBuffer)))
	{
		goto FAILURE;
	}

	// Store trampoline bytes in the first 192 bytes and relay bytes at last 64 bytes
	PayloadBuffer.insert(PayloadBuffer.end(), std::begin(TrampolineBuffer), std::begin(TrampolineBuffer) + sizeof(TrampolineBuffer));
	PayloadBuffer.insert(PayloadBuffer.end(), std::begin(RelayBuffer), std::begin(RelayBuffer) + sizeof(RelayBuffer));

	// Paged memory operation to write detour instruction (jmp dword ptr rel32)
	Operations[0].Address = TargetFunction;
	Operations[0].Buffer = PrologueBuffer;
	Operations[0].Size = SizeOfFoundInstructions;

	// Paged memory operation to write trampoline function
	Operations[1].Address = TrampolineAddress;
	Operations[1].Buffer = PayloadBuffer.data();
	Operations[1].Size = static_cast<ZyanU64>(PayloadBuffer.size()) * sizeof(ZyanU8);

	if (!ZynterceptAtomicWriteMemory(ProcessIdentifier, Operations, 2))
	{
		goto FAILURE;
	}

	*TrampolineFunction = TrampolineAddress;
	*OriginalPrologue = OriginalPrologueBuffer;
	*OriginalPrologueSize = SizeOfFoundInstructions;

	return ZYAN_TRUE;

FAILURE:
	Page.Address = NearPageAddress;
	Page.Size = 0;
	Page.State = 0;
	Page.Protection = 0;

	free(ReplaceableInstructions);
	free(OriginalPrologueBuffer);

	ZYNTERCEPT_UNREFERENCED(ZynterceptReleaseMemory(ProcessIdentifier, &Page));

	return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptDetourFunction32(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 HookedFunction,
	__zyntercept_out ZyanU64* TrampolineFunction,
	__zyntercept_out ZyanU8** OriginalPrologue,
	__zyntercept_out ZyanU64* OriginalPrologueSize)
{
	std::vector<ZyanU8> PayloadBuffer = {};

	ZydisMachineMode MachineMode = ZYDIS_MACHINE_MODE_LEGACY_32;
	ZydisStackWidth StackWidth = ZYDIS_STACK_WIDTH_32;

	ZyanU8 PrologueBuffer[32] = { 0 };
	ZyanU8 TrampolineBuffer[96] = { 0 };

	ZyanU64 NumberOfFoundInstructions = 0;
	ZyanUSize SizeOfFoundInstructions = 0;

	ZynterceptPagedMemory Page = { 0 };
	ZynterceptPagedMemoryOperation Operation = { 0 };
	ZynterceptPagedMemoryOperation Operations[2] = { 0 };

	Operation.Address = TargetFunction;
	Operation.Buffer = PrologueBuffer;
	Operation.Size = sizeof(PrologueBuffer);

	if (!ZynterceptReadMemory(ProcessIdentifier, &Operation))
	{
		return ZYAN_FALSE;
	}

	ZyanU64 SizeOfDecodedInstructions = SizeOfDecodedDesiredInstructions(
		MachineMode,
		StackWidth,
		PrologueBuffer,
		sizeof(PrologueBuffer),
		ZYNTERCEPT_SIZE_OF_DETOUR_JUMP);

	if (!SizeOfDecodedInstructions)
	{
		return ZYAN_FALSE;
	}

	ZydisDecoded* ReplaceableInstructions = (ZydisDecoded*)std::malloc(SizeOfDecodedInstructions);

	if (!ReplaceableInstructions)
	{
		return ZYAN_FALSE;
	}

	if (!FindReplaceableInstructions(
		MachineMode,
		StackWidth,
		PrologueBuffer,
		sizeof(PrologueBuffer),
		ZYNTERCEPT_SIZE_OF_DETOUR_JUMP,
		SizeOfDecodedInstructions,
		ReplaceableInstructions,
		&NumberOfFoundInstructions,
		&SizeOfFoundInstructions))
	{
		std::free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	if (HasFunctionBranchDestinationsBetween(
		ProcessIdentifier,
		MachineMode,
		StackWidth,
		TargetFunction,
		TargetFunction + 1,
		TargetFunction + SizeOfFoundInstructions))
	{
		std::free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	ZyanU8* OriginalPrologueBuffer = (ZyanU8*)std::malloc(SizeOfFoundInstructions);

	if (!OriginalPrologueBuffer) {
		std::free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	std::memcpy(OriginalPrologueBuffer, PrologueBuffer, SizeOfFoundInstructions);

	ZyanU64 NearPageAddress = ZynterceptAllocateNearestAddress(
		ProcessIdentifier,
		TargetFunction,
		ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_32BIT,
		ZYNTERCEPT_PAGE_STATE_RESERVED | ZYNTERCEPT_PAGE_STATE_COMMITTED,
		ZYNTERCEPT_PAGE_PROTECTION_READ | ZYNTERCEPT_PAGE_PROTECTION_EXECUTE);

	if (!NearPageAddress)
	{
		std::free(ReplaceableInstructions);
		return ZYAN_FALSE;
	}

	ZyanU64 TrampolineAddress = NearPageAddress;

	std::shared_ptr<AssemblyBuilder> PrologueBuilder = std::make_shared<AssemblyBuilder>(TargetFunction);

	PrologueBuilder->Jmp32(HookedFunction);

	if (!ZynterceptCompileTrampoline32(
		TargetFunction,
		TrampolineAddress,
		TrampolineBuffer,
		sizeof(TrampolineBuffer),
		ReplaceableInstructions,
		NumberOfFoundInstructions))
	{
		goto FAILURE;
	}

	if (PrologueBuilder->Failed())
	{
		goto FAILURE;
	}

	if (SizeOfFoundInstructions > PrologueBuilder->Size())
	{
		PrologueBuilder->Nop(SizeOfFoundInstructions - PrologueBuilder->Size());
	}

	if (!PrologueBuilder->CopyTo(PrologueBuffer, sizeof(PrologueBuffer)))
	{
		goto FAILURE;
	}

	PayloadBuffer.insert(PayloadBuffer.end(), std::begin(TrampolineBuffer), std::begin(TrampolineBuffer) + sizeof(TrampolineBuffer));

	// Paged memory operation to write detour instruction (jmp dword ptr rel32)
	Operations[0].Address = TargetFunction;
	Operations[0].Buffer = PrologueBuffer;
	Operations[0].Size = SizeOfFoundInstructions;

	// Paged memory operation to write relay function and trampoline function at once
	Operations[1].Address = TrampolineAddress;
	Operations[1].Buffer = PayloadBuffer.data();
	Operations[1].Size = static_cast<ZyanU64>(PayloadBuffer.size()) * sizeof(ZyanU8);

	if (!ZynterceptAtomicWriteMemory(ProcessIdentifier, Operations, 2))
	{
		goto FAILURE;
	}

	*TrampolineFunction = TrampolineAddress;
	*OriginalPrologue = OriginalPrologueBuffer;
	*OriginalPrologueSize = SizeOfFoundInstructions;

	return ZYAN_TRUE;

FAILURE:
	Page.Address = NearPageAddress;
	Page.Size = 0;
	Page.State = 0;
	Page.Protection = 0;

	std::free(ReplaceableInstructions);
	std::free(OriginalPrologueBuffer);

	ZYNTERCEPT_UNREFERENCED(ZynterceptReleaseMemory(ProcessIdentifier, &Page));

	return ZYAN_FALSE;
}

ZyanBool __zyntercept_cdecl ZynterceptRevertDetourFunction64(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 TrampolineFunction,
	__zyntercept_in ZyanU8* OriginalPrologue,
	__zyntercept_in ZyanU64 OriginalPrologueSize)
{
	ZynterceptPagedMemoryOperation Operations[1] = { 0 };
	ZynterceptPagedMemory TrampolinePage = { 0 };

	Operations[0].Address = TargetFunction;
	Operations[0].Buffer = OriginalPrologue;
	Operations[0].Size = OriginalPrologueSize;

	TrampolinePage.Address = TrampolineFunction;
	TrampolinePage.Size = ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_64BIT;

	if (!ZynterceptAtomicWriteMemory(ProcessIdentifier, Operations, 1)) {
		return ZYAN_FALSE;
	}

	std::free(OriginalPrologue);

	if (!ZynterceptReleaseMemory(ProcessIdentifier, &TrampolinePage)) {
		return ZYAN_FALSE;
	}

	return ZYAN_TRUE;
}

ZyanBool __zyntercept_cdecl ZynterceptRevertDetourFunction32(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 TrampolineFunction,
	__zyntercept_in ZyanU8* OriginalPrologue,
	__zyntercept_in ZyanU64 OriginalPrologueSize)
{
	ZynterceptPagedMemoryOperation Operations[1] = { 0 };
	ZynterceptPagedMemory TrampolinePage = { 0 };

	Operations[0].Address = TargetFunction;
	Operations[0].Buffer = OriginalPrologue;
	Operations[0].Size = OriginalPrologueSize;

	TrampolinePage.Address = TrampolineFunction;
	TrampolinePage.Size = ZYNTERCEPT_SIZE_OF_DETOUR_EXECUTABLE_BLOCK_32BIT;

	if (!ZynterceptAtomicWriteMemory(ProcessIdentifier, Operations, 1)) {
		return ZYAN_FALSE;
	}

	std::free(OriginalPrologue);

	if (!ZynterceptReleaseMemory(ProcessIdentifier, &TrampolinePage)) {
		return ZYAN_FALSE;
	}

	return ZYAN_TRUE;
}
