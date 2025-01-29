#include <Windows.h>
#include <Zyntercept/Zyntercept.h>
#include <Zyntercept/Core/Syscall/Syscall.h>
#include <catch2/catch_test_macros.hpp>

#define ORIGINAL_ROUTINE(FUNCTION) &(void*&)FUNCTION
#define DETOUR_ROUTINE(FUNCTION) &FUNCTION

typedef int (WINAPI* pMessageBoxW)(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType);

static volatile pMessageBoxW OriginalMessageBoxW = MessageBoxW;

int WINAPI MyMessageBoxW(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType)
{
    return OriginalMessageBoxW(hWnd, lpText, L"This function was hooked with success!", uType);
}

TEST_CASE("Should hook MessageBoxW function", "[zyntercept]")
{
    ZynterceptProcess Process = { 0 };

    Process.Identifier = GetCurrentProcess();
    Process.Architecture = ZynterceptIs64BitProcess(Process.Identifier)
        ? ZYNTERCEPT_ARCHITECTURE_64BIT 
        : ZYNTERCEPT_ARCHITECTURE_32BIT;

    ZynterceptTransactionBegin();
    ZynterceptAttachProcess(&Process);
    ZynterceptAttach(ORIGINAL_ROUTINE(OriginalMessageBoxW), DETOUR_ROUTINE(MyMessageBoxW));
    ZynterceptTransactionCommit();

    MessageBoxW(NULL, L"Title", L"Body", MB_OK);

    ZynterceptTransactionBegin();
    ZynterceptAttachProcess(&Process);
    ZynterceptDetach(ORIGINAL_ROUTINE(OriginalMessageBoxW));
    ZynterceptTransactionCommit();

    MessageBoxW(NULL, L"Title", L"Body", MB_OK);

    REQUIRE(true);
}
