cmake_minimum_required(VERSION 3.10)
project(PhishingDetectionEngine)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add include directories
include_directories(include)

# Find all source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Add executable
add_executable(PhishingEngine ${SOURCES})

# Platform specific configurations for UTF-8 and colored console
if(WIN32)
    add_compile_definitions(UNICODE _UNICODE)
endif()
