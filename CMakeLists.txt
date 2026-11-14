cmake_minimum_required(VERSION 3.20)
project(cochat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# 服务端不依赖 OpenSSL：对外 https 由 cloudflared 边缘提供，
# 密码学使用内置实现（SHA-256 / HMAC / PBKDF2 / 安全随机数），
# 因此在 amd64 / arm64 / armv7 的 Linux 与 Windows 上装好编译器即可构建。
find_package(Threads REQUIRED)

add_executable(cochat
  src/main.cpp
  src/auth.cpp
  src/hub.cpp
  src/util.cpp
  src/crypto.cpp
  src/instances.cpp
  src/restart.cpp
  src/passwd.cpp
  src/tunnel/loader.cpp
  src/panel/admin.cpp
  src/panel/auth.cpp
  src/panel/routes.cpp
  src/panel/ui.cpp
)

# glibc 兼容层：只对 ELF 目标有意义（它给 libstdc++.a 内部引用的 C23 符号
# 提供 glibc 内部实现的转发）。Windows 的 CRT 没有这套符号，加进去只会
# 变成 undefined reference，所以按平台挑。
if(NOT WIN32)
  target_sources(cochat PRIVATE src/compat/glibc_strtoul.cpp)
endif()

target_include_directories(cochat PRIVATE src third_party "${CMAKE_CURRENT_BINARY_DIR}/generated")

target_compile_definitions(cochat PRIVATE
  CPPHTTPLIB_THREAD_POOL_COUNT=24
)

target_link_libraries(cochat PRIVATE Threads::Threads)

if(WIN32)
  target_link_libraries(cochat PRIVATE ws2_32 bcrypt)
  target_link_options(cochat PRIVATE -static -static-libgcc -static-libstdc++)
  # MinGW 的 C++ 异常依赖 SEH/SjLj unwind 信息，链接时不能把相关段回收掉，
  # 否则会缺 __gxx_personality_* / _Unwind_SjLj_* 等符号。
  target_compile_options(cochat PRIVATE -fexceptions)
  target_link_options(cochat PRIVATE -Wl,--no-gc-sections)
  # cpp-httplib 要求 Windows 10 及以上；MinGW 交叉工具链默认的 _WIN32_WINNT 偏低
  # （Ubuntu 的 mingw-w64 默认 0x0602），这里显式抬高，否则会直接 #error。
  target_compile_definitions(cochat PRIVATE
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
    NTDDI_VERSION=0x0A000000
  )
endif()

if(MSVC)
  target_compile_options(cochat PRIVATE /W3 /utf-8)
else()
  target_compile_options(cochat PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# ---------------------------------------------------------------------------
# 把前端页面嵌进可执行文件：安装脚本只分发一个二进制，不需要附带 public 目录。
# 同时保留从磁盘读取的能力（存在 public/index.html 时优先用它，便于开发调试）。
# ---------------------------------------------------------------------------
set(PUBLIC_INDEX "${CMAKE_CURRENT_SOURCE_DIR}/public/index.html")
set(GEN_DIR "${CMAKE_BINARY_DIR}/generated")

file(READ "${PUBLIC_INDEX}" PUBLIC_HEX HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," PUBLIC_BYTES "${PUBLIC_HEX}")
string(LENGTH "${PUBLIC_HEX}" PUBLIC_HEX_LEN)
math(EXPR PUBLIC_LEN "${PUBLIC_HEX_LEN} / 2")

file(MAKE_DIRECTORY "${GEN_DIR}")
file(WRITE "${GEN_DIR}/embedded_public.h"
"// 由 CMake 自动生成，请勿手工修改\n"
"#pragma once\n"
"namespace embedded {\n"
"static const unsigned char kIndexHtml[] = {\n  ${PUBLIC_BYTES}\n};\n"
"static const unsigned long kIndexHtmlLen = ${PUBLIC_LEN}UL;\n"
"}  // namespace embedded\n")

# 前端改动后重新生成
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${PUBLIC_INDEX}")


# ---------------------------------------------------------------------------
# 内建隧道插件（可插拔动态库）
#
# 为什么是动态库而不是编进主程序：
#   1) 隧道需要 OpenSSL，而主程序的核心承诺是"零第三方依赖"。把它拆出去，
#      不装 OpenSSL 的人照样能用完整功能，只是没有隧道。
#   2) 插件缺失/损坏/版本不符时，主程序要能优雅降级成一个纯局域网服务。
#      编译期内建做不到"运行时缺失"这个状态。
#
# 因此在没有 OpenSSL 的环境下，这个目标会被整体跳过，cochat 照常构建。
# ---------------------------------------------------------------------------
option(COCHAT_BUILD_TUNNEL "构建内建隧道插件（需要 OpenSSL 开发库）" ON)

if(COCHAT_BUILD_TUNNEL)
  find_package(OpenSSL QUIET)
  if(NOT OpenSSL_FOUND)
    message(STATUS "未找到 OpenSSL，跳过隧道插件（主程序不受影响）")
    set(COCHAT_BUILD_TUNNEL OFF)
  endif()
endif()

if(COCHAT_BUILD_TUNNEL)
  set(TUNNEL_SOURCES
    plugins/tunnel/netportable.cpp
    plugins/tunnel/capnp.cpp
    plugins/tunnel/tunnelrpc.cpp
    plugins/tunnel/h2.cpp
    plugins/tunnel/proxy.cpp
    plugins/tunnel/quick.cpp
    plugins/tunnel/ingress.cpp
    plugins/tunnel/client.cpp
    plugins/tunnel/plugin.cpp
  )

  # MODULE 而不是 SHARED：MODULE 库不产生导入库、不参与别的目标链接，
  # 它天生就是"运行时按路径加载"的产物，语义正好对应我们的用法。
  add_library(cochat_tunnel MODULE ${TUNNEL_SOURCES})

  # 和主程序同一个理由：插件里也静态链了 libstdc++，同样会引用 C23 符号。
  if(NOT WIN32)
    target_sources(cochat_tunnel PRIVATE src/compat/glibc_strtoul.cpp)
  endif()

  target_include_directories(cochat_tunnel PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/plugins/tunnel
  )

  target_link_libraries(cochat_tunnel PRIVATE OpenSSL::SSL OpenSSL::Crypto)

  # 只导出入口符号，其余全部隐藏。少了这个，插件的内部辅助符号会出现在
  # 动态符号表里，和主程序的静态链接符号撞车的概率不为零。
  # 产物名按平台惯例：Windows 是 cochat-tunnel.dll，Linux 是 libcochat-tunnel.so。
  # 用惯例而不是统一成无前缀，是为了让 ldd / readelf / 普通的 .so 查找习惯都能
  # 直接认出来；loader 两个名字都会试。
  if(WIN32)
    set(TUNNEL_PREFIX "")
  else()
    set(TUNNEL_PREFIX "lib")
  endif()
  set_target_properties(cochat_tunnel PROPERTIES
    PREFIX "${TUNNEL_PREFIX}"
    OUTPUT_NAME "cochat-tunnel"
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
  )

  if(WIN32)
    target_link_libraries(cochat_tunnel PRIVATE ws2_32 crypt32)
    target_compile_definitions(cochat_tunnel PRIVATE
      _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000000)
    # Windows 的 MODULE 库默认产出 .dll，无需改后缀
  else()
    target_link_libraries(cochat_tunnel PRIVATE Threads::Threads)
  endif()

  # 【必须静态链接 libstdc++ / libgcc，两个平台都要】
  #
  # 主程序是按"拿到就能跑"发的静态二进制：它的 libstdc++ 已经编进可执行文件里。
  # 插件如果还去依赖动态 libstdc++.so.6，进程里就同时存在两套 C++ 运行时 ——
  # 一边的 std::string / std::mutex / 异常表与另一边的布局不一致，
  # 调用进插件的第一行就可能段错误。
  #
  # 实测：Linux 静态主程序 + 动态插件，./cochat --tunnel 立刻 Segmentation fault
  # （不带 --tunnel 一切正常，因为那时根本不碰插件）。Windows 上同样的组合
  # 只是表现得温和些（DLL 自己带一份 CRT），但这属于运气而不是设计。
  #
  # 注意 OpenSSL 仍是动态依赖：它在系统里有稳定的 ABI，且目标机本来就需要它。
  target_link_options(cochat_tunnel PRIVATE -static-libgcc -static-libstdc++)

  if(NOT MSVC)
    target_compile_options(cochat_tunnel PRIVATE -Wall -Wextra -Wno-unused-parameter)
  else()
    target_compile_options(cochat_tunnel PRIVATE /W3 /utf-8)
  endif()

  # 构建完把插件放到主程序旁边，开发时直接就能被 loader 发现。
  add_custom_command(TARGET cochat_tunnel POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
      $<TARGET_FILE:cochat_tunnel>
      $<TARGET_FILE_DIR:cochat>
    COMMENT "隧道插件已复制到输出目录"
  )
endif()

# ---------------------------------------------------------------------------
# 单元测试（默认关闭）
#
# 默认关闭是有意的：本项目对外的承诺是"装好编译器就能构建、不依赖第三方库"，
# 而 tests/crypto_test.cpp 要拿 OpenSSL 当对照实现（证明内置 SHA-256 / HMAC /
# PBKDF2 与它逐字节一致），一旦默认打开就等于给所有人加了 OpenSSL 依赖。
# CI 与本地显式传 -DCOCHAT_BUILD_TESTS=ON 再跑 ctest。
# ---------------------------------------------------------------------------
option(COCHAT_BUILD_TESTS "构建单元测试（需要 OpenSSL 开发库）" OFF)

if(COCHAT_BUILD_TESTS)
  enable_testing()
  find_package(OpenSSL REQUIRED)

  # 与 OpenSSL 逐字节对照：内置密码学实现不能有自己的"差不多对"
  add_executable(crypto_test tests/crypto_test.cpp src/crypto.cpp)
  target_include_directories(crypto_test PRIVATE src)
  target_link_libraries(crypto_test PRIVATE OpenSSL::Crypto)
  if(WIN32)
    # crypto.cpp 的安全随机数在 Windows 上走 BCryptGenRandom
    target_link_libraries(crypto_test PRIVATE bcrypt ws2_32)
    target_compile_definitions(crypto_test PRIVATE
      _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000000)
  endif()
  add_test(NAME crypto COMMAND crypto_test)

  # JSON 往返：ICE 配置就是这么读进来的
  add_executable(json_test tests/json_test.cpp)
  target_include_directories(json_test PRIVATE src)
  add_test(NAME json COMMAND json_test)

  # 实例自述与 --cur/--res 的识别规则（不需要网络，不需要真的起服务）
  # util.cpp 的随机 token 走 crypto::random_bytes，所以 crypto.cpp 也要带上
  add_executable(ops_test tests/ops_test.cpp src/instances.cpp src/util.cpp src/crypto.cpp)
  target_include_directories(ops_test PRIVATE src third_party)
  target_link_libraries(ops_test PRIVATE Threads::Threads)
  if(WIN32)
    target_link_libraries(ops_test PRIVATE ws2_32 bcrypt)
    target_compile_definitions(ops_test PRIVATE
      _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000000)
  endif()
  add_test(NAME ops COMMAND ops_test)

  # 面板保留账号规则。只链 admin.cpp：它依赖 auth.cpp（is_reserved_user 只是
  # 字符串比较，但同一个翻译单元里还有 ensure_admin，需要 auth::Store 的符号）。
  # 不链 routes.cpp / ui.cpp —— 那两个带着 httplib 和几十 KB 内嵌页面，
  # 为了测一个纯函数不值得把整条依赖拽进来。
  add_executable(panel_test tests/panel_test.cpp src/panel/admin.cpp
                 src/panel/auth.cpp src/auth.cpp src/util.cpp src/crypto.cpp)
  target_include_directories(panel_test PRIVATE src third_party)
  target_link_libraries(panel_test PRIVATE Threads::Threads)
  if(WIN32)
    target_link_libraries(panel_test PRIVATE ws2_32 bcrypt)
    target_compile_definitions(panel_test PRIVATE
      _WIN32_WINNT=0x0A00 WINVER=0x0A00 NTDDI_VERSION=0x0A000000)
  endif()
  add_test(NAME panel COMMAND panel_test)

  if(NOT MSVC)
    foreach(t crypto_test json_test ops_test panel_test)
      target_compile_options(${t} PRIVATE -Wall -Wextra -Wno-unused-parameter)
    endforeach()
  endif()
endif()
