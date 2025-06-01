#pragma once

#include <windows.h>  // 添加 Windows 头文件来声明 DWORD

extern "C" {
__declspec(dllexport) int WxInitSDK(bool debug, int port);
__declspec(dllexport) int WxInitSDKWithPid(DWORD pid, bool debug, int port);
__declspec(dllexport) int WxInitSDKWithPath(const wchar_t *wxPath, bool debug, int port);
__declspec(dllexport) int WxDestroySDK();
}