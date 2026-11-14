// 让产物能在 Debian 12（glibc 2.36）上跑：为 libstdc++ 内部的 C23 引用补两个符号。
//
// 【为什么躲不掉】
// 我们静态链接 libstdc++（目标机不装它也能跑），而 libstdc++.a 里的 eh_alloc.o /
// debug.o 自己就引用了 __isoc23_strtoul。那个符号是 glibc 2.38 才有的，于是
// 在 glibc 2.41 上编出来的二进制拿到 Debian 12 上直接报
//   version `GLIBC_2.38' not found
// 整个程序起不来。这一条与我们自己有没有调用 strtoul 无关 —— 项目源码里的
// strtol/strtoull 已经全部换成 util::parse_long 与手写解析，剩下的纯粹来自库。
//
// 【为什么这样实现】
// 关键是不能写成 `return ::strtoul(...)`：glibc 2.38+ 用 __REDIRECT 把 strtoul
// 别名到 __isoc23_strtoul，那样写就是无限递归（实测：程序满核空转、无任何输出、
// 不监听端口，极难看出是自己调自己）。
// 所以这里直接转发到 __strtoul_internal —— 它是 GLIBC_2.2.5 就有的内部实现，
// 不会被重定向。
//
// 语义差异：C23 只比 C17 多了 0bxxxx 二进制前缀的识别，而我们没有任何地方依赖
// 这个行为（libstdc++ 拿它解析的是内部长度/索引，全是十进制）。
//
// 只在 Linux 编（CMake 里限定非 WIN32）；Windows 的 CRT 没有这个问题。
#include <cerrno>
#include <cstddef>

extern "C" {

// glibc 的内部入口，签名与 strtoul/strtoull 一致（多一个 group 参数）。
extern long __strtol_internal(const char*, char**, int, int);
extern unsigned long __strtoul_internal(const char*, char**, int, int);
extern long long __strtoll_internal(const char*, char**, int, int);
extern unsigned long long __strtoull_internal(const char*, char**, int, int);

// 四个都要给。只补其中一部分时，剩下那个会在别的依赖库换版本后突然冒出来
// —— 这正是这次的经过：先只补了 strtoul/strtoull（当时 grep 没看到 strtol 的
// 引用），后来静态链接 OpenSSL，它内部引用了 __isoc23_strtol，产物立刻又
// 变回 "GLIBC_2.38 not found"。
long __isoc23_strtol(const char* n, char** e, int b) {
    return __strtol_internal(n, e, b, 0);
}

unsigned long __isoc23_strtoul(const char* n, char** e, int b) {
    return __strtoul_internal(n, e, b, 0);
}

long long __isoc23_strtoll(const char* n, char** e, int b) {
    return __strtoll_internal(n, e, b, 0);
}

unsigned long long __isoc23_strtoull(const char* n, char** e, int b) {
    return __strtoull_internal(n, e, b, 0);
}

}  // extern "C"