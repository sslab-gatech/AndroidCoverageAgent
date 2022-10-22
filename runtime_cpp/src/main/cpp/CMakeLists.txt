# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.
cmake_minimum_required(VERSION 3.10.2)

# Include a CMake library to embed the dex file in the shared library.
include(CMakeRC.cmake)
# `gen/Instrumentation.dex` is copied in during the gradle build process, we embed it as a resource
# into the library here.
cmrc_add_resource_library(dex_resources ALIAS agent::dex gen/Instrumentation.dex)
set_property(TARGET dex_resources PROPERTY POSITION_INDEPENDENT_CODE ON)

# Declares and names the project.
project("coverage_instrumenting_agent")

# Use c++17 for features like `optional<>`
if(NOT "${CMAKE_CXX_STANDARD}")
    set(CMAKE_CXX_STANDARD 17)
endif()

# Find zlib library, slicer needs it.
find_library(zlib-lib z)

# Slicer library
file(GLOB SLICER_SRCS "slicer/*.cc")
add_library(
        slicer
        STATIC
        ${SLICER_SRCS}
)
target_include_directories(slicer PRIVATE .)
target_link_libraries(slicer ${zlib-lib})
# ---

add_library( # Sets the name of the library.
        coverage_instrumenting_agent
        # Sets the library as a shared library.
        SHARED
        # Provides a relative path to your source file(s).
        coverage_instrumenting_agent.cpp)

# Find the Android logging library.
find_library(log-lib log)

# Output library
target_link_libraries(
        # Specifies the target library.
        coverage_instrumenting_agent

        # Links the target library to the log library
        # included in the NDK.
        ${log-lib}
        # Include slicer library.
        slicer
        # Include the embedded dex file.
        agent::dex
)
