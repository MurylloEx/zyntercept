#ifndef ZYNTERCEPT_COMMON_H
#define ZYNTERCEPT_COMMON_H

#include <Zydis/Zydis.h>
#include <cstring>
#include <algorithm>

#if defined(_MSC_VER) || defined(__BORLANDC__) || defined(__CODEGEARC__) || defined(__DMC__)
// MSVC, Borland, Digital Mars and compatibles with __declspec
#define __zyntercept_noinline __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__) || defined(__INTEL_COMPILER) || \
      defined(__SUNPRO_C) || defined(__SUNPRO_CC) || defined(__xlC__) || \
      defined(__IBMC__) || defined(__IBMCPP__) || defined(__HP_cc) || \
      defined(__HP_aCC) || defined(__ARMCC_VERSION) || defined(__TI_COMPILER_VERSION__) || \
      defined(__NVCC__) || defined(__PGI) || defined(__EMSCRIPTEN__)
// GCC, Clang, Intel, Sun, IBM, HP, ARM, TI, NVIDIA, PGI, Emscripten
#define __zyntercept_noinline __attribute__((noinline))
#else
#define __zyntercept_noinline __attribute__((noinline))
#pragma message("Warning: Compiler not recognized. __zyntercept_noinline may not work properly.")
#endif

#define __zyntercept_cdecl
#define __zyntercept_in
#define __zyntercept_out

#define ZYNTERCEPT_UNREFERENCED(R) (R)
#define ZYNTERCEPT_MAXIMUM_MEMORY_RANGE 0x40000000
#define ZYNTERCEPT_IS_POINTER_BETWEEN(P, MAX, MIN) ((P < MAX) && (P > MIN))

ZyanI64 Difference(ZyanU64 First, ZyanU64 Second);

#endif // ZYNTERCEPT_COMMON_H
