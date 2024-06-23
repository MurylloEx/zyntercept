#ifndef ZYNTERCEPT_COMMON_H
#define ZYNTERCEPT_COMMON_H

#include <Zydis/Zydis.h>

#define __zyntercept_cdecl __cdecl
#define __zyntercept_in
#define __zyntercept_out

#define ZYNTERCEPT_UNREFERENCED(R) (R)

ZyanI64 Difference(ZyanU64 First, ZyanU64 Second);

#endif // ZYNTERCEPT_COMMON_H
