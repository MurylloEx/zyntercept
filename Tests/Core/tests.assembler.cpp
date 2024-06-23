#include <Windows.h>
#include <Zyntercept/Zyntercept.h>
#include <gtest/gtest.h>

typedef int (WINAPI* pMessageBoxW)(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType);

static pMessageBoxW OriginalMessageBoxW = MessageBoxW;

int WINAPI hookedMessageBoxW(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType)
{
    return OriginalMessageBoxW(hWnd, lpText, L"Hacked by Muryllo", uType);
}

TEST(Zytercept_Assembler_Tests, TestIfItWorks)
{
    ZynterceptProcess process = { 0 };

    process.Architecture = ZYNTERCEPT_ARCHITECTURE_64BIT;
    process.Identifier = GetCurrentProcess();

    ZynterceptTransactionBegin();
    ZynterceptAttachProcess(&process);
    ZynterceptAttach(&(void*&)OriginalMessageBoxW, &hookedMessageBoxW);
    ZynterceptTransactionCommit();

    MessageBoxW(NULL, L"teste", L"teste", MB_OK);

    ZynterceptTransactionBegin();
    ZynterceptAttachProcess(&process);
    ZynterceptDetach(&(void*&)OriginalMessageBoxW);
    ZynterceptTransactionCommit();

    MessageBoxW(NULL, L"teste", L"teste", MB_OK);

    ASSERT_EQ(true, true);
    ASSERT_EQ(false, false);
}
