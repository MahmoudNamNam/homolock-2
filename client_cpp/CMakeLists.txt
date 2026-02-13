cmake_minimum_required(VERSION 3.16)
project(homolock_client CXX)

set(CMAKE_CXX_STANDARD 17)

# SEAL's bundled zlib uses an old cmake_minimum_required; with CMake 4+ set minimum to 3.5
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)

# Microsoft SEAL via FetchContent
include(FetchContent)
FetchContent_Declare(
  seal
  GIT_REPOSITORY https://github.com/microsoft/SEAL.git
  GIT_TAG        v4.1.1
  GIT_SHALLOW    TRUE
)
set(SEAL_BUILD_SEAL_CXX OFF CACHE BOOL "" FORCE)
# Avoid bundled zlib build (fails on macOS with fdopen conflict); use uncompressed serialization
set(SEAL_USE_ZLIB OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(seal)

# Find libcurl
find_package(CURL REQUIRED)

add_executable(homolock_client src/main.cpp)
target_include_directories(homolock_client PRIVATE ${seal_SOURCE_DIR}/native/src)
target_link_libraries(homolock_client PRIVATE seal CURL::libcurl)
