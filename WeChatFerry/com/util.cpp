#include "util.h"

#include <codecvt>
#include <filesystem>
#include <locale>
#include <optional>
#include <strsafe.h>
#include <wchar.h>
#include <fstream>
#include <string>

#include <Shlwapi.h>
#include <tlhelp32.h>

#include "log.hpp"

#pragma comment(lib, "shlwapi")
#pragma comment(lib, "Version.lib")

namespace fs = std::filesystem;

namespace util
{

constexpr char WECHATEXE[]    = "WeChat.exe";
constexpr char WECHATWINDLL[] = "WeChatWin.dll";

std::wstring s2w(const std::string &s)
{
    if (s.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring ws(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &ws[0], size_needed);
    return ws;
}

std::string w2s(const std::wstring &ws)
{
    if (ws.empty()) return std::string();
    int size_needed
        = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
    std::string s(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.size()), &s[0], size_needed, nullptr, nullptr);
    return s;
}

std::string gb2312_to_utf8(const char *gb2312)
{
    if (!gb2312) return "";

    int size_needed = MultiByteToWideChar(CP_ACP, 0, gb2312, -1, nullptr, 0);
    std::wstring ws(size_needed, 0);
    MultiByteToWideChar(CP_ACP, 0, gb2312, -1, &ws[0], size_needed);

    size_needed = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &s[0], size_needed, nullptr, nullptr);

    return s;
}

static DWORD get_wechat_pid()
{
    DWORD pid        = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
    while (Process32NextW(hSnapshot, &pe32)) {
        if (pe32.szExeFile == s2w(WECHATEXE)) {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(hSnapshot);
    return pid;
}

std::optional<std::string> get_wechat_path_from_config()
{
    // 配置文件路径，放在程序目录下
    char config_path[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, config_path, MAX_PATH);
    PathRemoveFileSpecA(config_path);
    PathAppendA(config_path, "wcf_config.ini");

    // 检查文件是否存在
    if (!PathFileExistsA(config_path)) {
        LOG_DEBUG("配置文件不存在: %s", config_path);
        return std::nullopt;
    }

    // 读取微信路径
    char wechat_path[MAX_PATH] = {0};
    GetPrivateProfileStringA("WeChatFerry", "WeChatPath", "", wechat_path, MAX_PATH, config_path);
    
    if (wechat_path[0] == '\0') {
        LOG_DEBUG("配置文件中未找到微信路径");
        return std::nullopt;
    }

    LOG_INFO("从配置文件读取微信路径: %s", wechat_path);
    return std::string(wechat_path);
}

std::string get_wechat_version_from_path(const std::string& wechat_exe_path)
{
    // 获取微信目录
    char wechat_dir[MAX_PATH] = {0};
    strcpy_s(wechat_dir, wechat_exe_path.c_str());
    PathRemoveFileSpecA(wechat_dir);
    
    // 尝试直接查找 WeChatWin.dll
    char dll_path[MAX_PATH] = {0};
    strcpy_s(dll_path, wechat_dir);
    PathAppendA(dll_path, WECHATWINDLL);
    
    if (PathFileExistsA(dll_path)) {
        auto version = get_file_version(dll_path);
        if (version) return *version;
    }
    
    // 尝试在版本目录中查找
    WIN32_FIND_DATAA find_data;
    char search_path[MAX_PATH] = {0};
    strcpy_s(search_path, wechat_dir);
    PathAppendA(search_path, "*");
    
    HANDLE find_handle = FindFirstFileA(search_path, &find_data);
    if (find_handle != INVALID_HANDLE_VALUE) {
        do {
            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                strcmp(find_data.cFileName, ".") != 0 &&
                strcmp(find_data.cFileName, "..") != 0) {
                
                char version_dll_path[MAX_PATH] = {0};
                strcpy_s(version_dll_path, wechat_dir);
                PathAppendA(version_dll_path, find_data.cFileName);
                PathAppendA(version_dll_path, WECHATWINDLL);
                
                if (PathFileExistsA(version_dll_path)) {
                    auto version = get_file_version(version_dll_path);
                    FindClose(find_handle);
                    if (version) return *version;
                    break;
                }
            }
        } while (FindNextFileA(find_handle, &find_data));
        
        FindClose(find_handle);
    }
    
    LOG_ERROR("无法从指定路径获取微信版本: %s", wechat_exe_path.c_str());
    return "";
}

static std::optional<std::string> get_wechat_path()
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Tencent\\WeChat", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        LOG_ERROR("无法打开注册表项");
        return std::nullopt;
    }

    char path[MAX_PATH] = { 0 };
    DWORD type          = REG_SZ;
    DWORD size          = sizeof(path);
    if (RegQueryValueExA(hKey, "InstallPath", nullptr, &type, reinterpret_cast<LPBYTE>(path), &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        LOG_ERROR("无法读取注册表中的 InstallPath");
        return std::nullopt;
    }
    RegCloseKey(hKey);

    PathAppendA(path, WECHATEXE);
    return std::string(path);
}

static std::optional<std::string> get_wechat_win_dll_path()
{
    auto wechat_path = get_wechat_path();
    if (!wechat_path) {
        return std::nullopt;
    }

    fs::path dll_path = *wechat_path;
    dll_path          = dll_path.parent_path();

    fs::path wechat_dll_path = dll_path / WECHATWINDLL;
    if (fs::exists(wechat_dll_path)) { // 尝试直接查找 WeChatWin.dll
        return wechat_dll_path.string();
    }

    // 微信从（大约）3.7开始，增加了一层版本目录: [3.7.0.29]
    std::optional<std::string> found_path;
    for (const auto &entry : fs::directory_iterator(dll_path)) {
        if (entry.is_directory()) {
            fs::path possible_dll = entry.path() / WECHATWINDLL;
            if (fs::exists(possible_dll)) {
                found_path = possible_dll.string();
                break; // 取第一个找到的版本号文件夹
            }
        }
    }

    if (!found_path) {
        LOG_ERROR("未找到 WeChatWin.dll");
    }

    return found_path;
}

std::optional<std::string> get_file_version(const std::string& file_path)
{
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeA(file_path.c_str(), &handle);
    if (size == 0) {
        LOG_ERROR("获取文件版本信息大小失败: %s", file_path.c_str());
        return std::nullopt;
    }

    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoA(file_path.c_str(), handle, size, data.data())) {
        LOG_ERROR("获取文件版本信息失败: %s", file_path.c_str());
        return std::nullopt;
    }

    VS_FIXEDFILEINFO* file_info = nullptr;
    UINT len = 0;
    if (!VerQueryValueA(data.data(), "\\", (LPVOID*)&file_info, &len)) {
        LOG_ERROR("查询文件版本信息失败: %s", file_path.c_str());
        return std::nullopt;
    }

    char version[64] = {0};
    sprintf_s(version, "%d.%d.%d.%d",
        HIWORD(file_info->dwFileVersionMS),
        LOWORD(file_info->dwFileVersionMS),
        HIWORD(file_info->dwFileVersionLS),
        LOWORD(file_info->dwFileVersionLS));

    return std::string(version);
}

std::string get_wechat_version()
{
    auto dll_path = get_wechat_win_dll_path();
    if (!dll_path) {
        LOG_ERROR("无法获取 WeChatWin.dll 路径");
        return "";
    }

    auto version = get_file_version(*dll_path);
    if (!version) {
        LOG_ERROR("无法获取 WeChat 版本信息");
        return "";
    }

    return *version;
}

int open_wechat(DWORD &pid)
{
    pid = get_wechat_pid();
    if (pid != 0) {
        return ERROR_SUCCESS;
    }

    auto wechat_path = util::get_wechat_path();
    if (!wechat_path) {
        LOG_ERROR("获取 WeChat 安装路径失败");
        return ERROR_FILE_NOT_FOUND;
    }

    STARTUPINFOA si        = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    std::string command_line = *wechat_path;
    if (!CreateProcessA(nullptr, command_line.data(), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr,
                        &si, &pi)) {
        return GetLastError();
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    pid = pi.dwProcessId;
    return ERROR_SUCCESS;
}

uint32_t get_memory_int_by_address(HANDLE hProcess, uint64_t addr)
{
    uint32_t value = 0;
    if (!addr || !hProcess) return value;

    ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr), &value, sizeof(value), nullptr);

    return value;
}

std::wstring get_unicode_info_by_address(HANDLE hProcess, uint64_t address)
{
    if (!hProcess || !address) return L"";

    uint64_t str_address = get_memory_int_by_address(hProcess, address);
    uint64_t str_len     = get_memory_int_by_address(hProcess, address + 0x4);
    if (str_len > 500) return L"";

    wchar_t cValue[500] = { 0 };
    if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(str_address), cValue, (str_len + 1) * sizeof(wchar_t),
                          nullptr)) {
        return std::wstring(cValue);
    }

    return L"";
}

void dbg_msg(const char *format, ...)
{
    if (!format) return;

    va_list args;
    va_start(args, format);

    va_list args_copy;
    va_copy(args_copy, args);
    int len = vsnprintf(nullptr, 0, format, args_copy);
    va_end(args_copy);

    std::vector<char> buffer(len + 1);
    vsnprintf(buffer.data(), buffer.size(), format, args);
    va_end(args);

    OutputDebugStringW(s2w(buffer.data()).c_str());
}

std::unique_ptr<WxString> new_wx_string(const char *str)
{
    return new_wx_string(str ? std::string(str) : std::string());
}

std::unique_ptr<WxString> new_wx_string(const std::string &str) { return std::make_unique<WxString>(s2w(str)); }

std::unique_ptr<WxString> new_wx_string(const wchar_t *wstr)
{
    return new_wx_string(wstr ? std::wstring(wstr) : std::wstring());
}

std::unique_ptr<WxString> new_wx_string(const std::wstring &wstr) { return std::make_unique<WxString>(wstr); }

AtWxidSplitResult<> parse_wxids(const std::string &atWxids)
{
    AtWxidSplitResult<> result;
    if (!atWxids.empty()) {
        std::wstringstream wss(util::s2w(atWxids));
        for (std::wstring wxid; std::getline(wss, wxid, L',');) {
            result.wxids.push_back(wxid);
            result.wxWxids.emplace_back(result.wxids.back());
        }
    }
    return result;
}

WxString *CreateWxString(const std::string &s)
{
    std::wstring ws = util::s2w(s);
    WxString *wxStr = reinterpret_cast<WxString *>(HeapAlloc(GetProcessHeap(), 8, sizeof(WxString)));
    if (!wxStr) return nullptr;
    size_t len   = ws.length();
    wchar_t *ptr = reinterpret_cast<wchar_t *>(HeapAlloc(GetProcessHeap(), 8, (len + 1) * sizeof(wchar_t)));
    if (!ptr) {
        HeapFree(GetProcessHeap(), 8, wxStr);
        return nullptr;
    }
    wmemcpy(ptr, ws.c_str(), len + 1);
    wxStr->wptr   = ptr;
    wxStr->size   = static_cast<DWORD>(ws.size());
    wxStr->length = static_cast<DWORD>(ws.length());
    wxStr->clen   = 0;
    wxStr->ptr    = nullptr;
    return wxStr;
}

void FreeWxString(WxString *wxStr)
{
    if (wxStr) {
        if (wxStr->wptr) HeapFree(GetProcessHeap(), 8, const_cast<wchar_t *>(wxStr->wptr));
        HeapFree(GetProcessHeap(), 8, wxStr);
    }
}
} // namespace util
