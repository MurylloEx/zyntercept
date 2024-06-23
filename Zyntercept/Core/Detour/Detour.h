#ifndef ZYNTERCEPT_DETOUR_H
#define ZYNTERCEPT_DETOUR_H

#include <Zyntercept/Core/Common/Common.h>

ZyanBool ZynterceptDetourFunction64(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 HookedFunction,
	__zyntercept_out ZyanU64* TrampolineFunction,
	__zyntercept_out ZyanU8** OriginalPrologue,
	__zyntercept_out ZyanU64* OriginalPrologueSize);

ZyanBool ZynterceptDetourFunction32(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 HookedFunction,
	__zyntercept_out ZyanU64* TrampolineFunction,
	__zyntercept_out ZyanU8** OriginalPrologue,
	__zyntercept_out ZyanU64* OriginalPrologueSize);

ZyanBool ZynterceptRevertDetourFunction64(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 TrampolineFunction,
	__zyntercept_in ZyanU8* OriginalPrologue,
	__zyntercept_in ZyanU64 OriginalPrologueSize);

ZyanBool ZynterceptRevertDetourFunction32(
	__zyntercept_in ZyanVoidPointer ProcessIdentifier,
	__zyntercept_in ZyanU64 TargetFunction,
	__zyntercept_in ZyanU64 TrampolineFunction,
	__zyntercept_in ZyanU8* OriginalPrologue,
	__zyntercept_in ZyanU64 OriginalPrologueSize);

#endif // ZYNTERCEPT_DETOUR_H
