#pragma once
// 插件内部的进程级状态：一次只能有一个隧道，stop() 之后可以再 start()。
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

#include "../../src/tunnel/api.h"

namespace ct {

struct Runtime {
    std::mutex mu;
    std::thread worker;
    cochat_tunnel_status status{};
    cochat_tunnel_log_fn log = nullptr;
    cochat_tunnel_status_fn on_status = nullptr;
    void* user = nullptr;
    int logLevel = 1;
    bool startGuard = false;   // worker 在跑（不管连没连上）
    std::uint64_t generation = 0;  // 让退出的旧线程不覆盖新线程的状态
};

Runtime& runtime();

// 按级别写日志，并转交给主程序注册的回调（没有回调时丢弃）。
void log_line(int level, const char* fmt, ...);

void publish(const cochat_tunnel_status& st);
void publish_now();

}  // namespace ct
