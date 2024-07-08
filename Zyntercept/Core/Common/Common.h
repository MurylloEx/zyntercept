#ifndef ZYNTERCEPT_COMMON_H
#define ZYNTERCEPT_COMMON_H

#include <Zydis/Zydis.h>

#define __zyntercept_cdecl __cdecl
#define __zyntercept_in
#define __zyntercept_out

#define ZYNTERCEPT_UNREFERENCED(R) (R)
#define ZYNTERCEPT_MAXIMUM_MEMORY_RANGE 0x40000000
#define ZYNTERCEPT_IS_POINTER_BETWEEN(P, MAX, MIN) ((P < MAX) && (P > MIN))

ZyanI64 Difference(ZyanU64 First, ZyanU64 Second);

#endif // ZYNTERCEPT_COMMON_H
