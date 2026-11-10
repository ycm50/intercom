cmake_minimum_required(VERSION 3.20)
project(intercom-server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# 服务端不依赖 OpenSSL：对外 https 由 cloudflared 边缘提供，
# 密码学使用内置实现（SHA-256 / HMAC / PBKDF2 / 安全随机数），
# 因此 amd64 / arm64 的 Linux 上装好 g++ + cmake 即可编译。
find_package(Threads REQUIRED)

add_executable(intercom-server
  src/main.cpp
  src/auth.cpp
  src/hub.cpp
  src/util.cpp
  src/crypto.cpp
)

target_include_directories(intercom-server PRIVATE src third_party)

target_compile_definitions(intercom-server PRIVATE
  CPPHTTPLIB_THREAD_POOL_COUNT=24
)

target_link_libraries(intercom-server PRIVATE Threads::Threads)

if(WIN32)
  target_link_libraries(intercom-server PRIVATE ws2_32 bcrypt)
  target_link_options(intercom-server PRIVATE -static -static-libgcc -static-libstdc++)
endif()

if(MSVC)
  target_compile_options(intercom-server PRIVATE /W3 /utf-8)
else()
  target_compile_options(intercom-server PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# 构建后交付：可执行文件 + 前端
# 前端改动也要被同步到输出目录：把 public 目录作为依赖
file(GLOB_RECURSE INTERCOM_PUBLIC_FILES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/public/*")
add_custom_target(intercom-public ALL
  COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:intercom-server>/public
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          ${CMAKE_CURRENT_SOURCE_DIR}/public
          $<TARGET_FILE_DIR:intercom-server>/public
  DEPENDS ${INTERCOM_PUBLIC_FILES}
  COMMENT "同步前端 public/ 到输出目录"
)
add_dependencies(intercom-server intercom-public)

add_custom_command(TARGET intercom-server POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:intercom-server>/public
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          ${CMAKE_CURRENT_SOURCE_DIR}/public
          $<TARGET_FILE_DIR:intercom-server>/public
)
