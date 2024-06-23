#include <Zyntercept/Core/Common/Common.h>

ZyanI64 Difference(ZyanU64 First, ZyanU64 Second) {
    ZyanU64 AbsoluteDifference = (First > Second) ? (First - Second) : (Second - First);
    return (First > Second) ? (ZyanI64)AbsoluteDifference : -1 * (ZyanI64)AbsoluteDifference;
}
