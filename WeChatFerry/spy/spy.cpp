#include "spy.h"

#include <filesystem>

#include "log.hpp"
#include "rpc_server.h"
#include "spy.h"
#include "util.h"

namespace Spy
{
int Init(void *args)
{
    auto *pp = static_cast<util::PortPath *>(args);

    Log::InitLogger(pp->path);
    if (auto dll_addr = GetModuleHandleW(L"WeChatWin.dll")) {
        WeChatDll.store(reinterpret_cast<uint64_t>(dll_addr));
    } else {
        LOG_ERROR("获取 WeChatWin.dll 模块地址失败");
        return -1;
    }

    std::string version;
    // 尝试从配置文件读取微信路径
    if (auto config_path = util::get_wechat_path_from_config()) {
        version = util::get_wechat_version_from_path(*config_path);
    } else {
        // 回退到原来的方法
        version = util::get_wechat_version();
    }
    std::string msg     = fmt::format("WCF 支持版本: {}，当前版本: {}", SUPPORT_VERSION, version);
    if (version != SUPPORT_VERSION) {
        LOG_ERROR(msg);
        util::MsgBox(NULL, msg.c_str(), "微信版本错误", MB_ICONERROR);
        return -2;
    }

    LOG_INFO(msg);
    RpcServer::getInstance().start(pp->port);

    return 0;
}

void Cleanup()
{
    LOG_DEBUG("CleanupSpy");
    RpcServer::destroyInstance();
}
}

extern "C" {
__declspec(dllexport) int InitSpy(void *args) { return Spy::Init(args); }
__declspec(dllexport) int CleanupSpy() { Spy::Cleanup(); return 0;}
}
