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
)

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

  if(NOT MSVC)
    foreach(t crypto_test json_test ops_test)
      target_compile_options(${t} PRIVATE -Wall -Wextra -Wno-unused-parameter)
    endforeach()
  endif()
endif()
