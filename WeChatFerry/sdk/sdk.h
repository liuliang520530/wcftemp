#pragma once

extern "C" {
__declspec(dllexport) int WxInitSDK(bool debug, int port);
__declspec(dllexport) int WxInitSDKWithPid(DWORD pid, bool debug, int port);
__declspec(dllexport) int WxInitSDKWithPath(const wchar_t *wxPath, bool debug, int port);
__declspec(dllexport) int WxDestroySDK();
}