cmake_minimum_required(VERSION 3.10)
# Enforce C++20.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project(
        4crypt
        VERSION 1.0.0
        DESCRIPTION "Strong symmetric encryption tool."
        HOMEPAGE_URL "https://github.com/stuartcalder/4crypt"
)
add_compile_options(-lto -O3)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK4 REQUIRED IMPORTED_TARGET gtk4)
add_executable(
        4crypt
        Impl/CliMain.cc
        Impl/CommandLineArg.cc
        Impl/Core.cc
        Impl/Util.cc
        CommandLineArg.hh
        Core.hh
        Util.hh
)
add_executable(
        g4crypt
        Impl/CommandLineArg.cc
        Impl/Core.cc
        Impl/GuiMain.cc
        Impl/Util.cc
        CommandLineArg.hh
        Core.hh
        Util.hh
        Gui.hh
)
# Includes.
target_include_directories(4crypt  PRIVATE "${PROJECT_SOURCE_DIR}")
target_include_directories(g4crypt PRIVATE "${PROJECT_SOURCE_DIR}")
target_include_directories(g4crypt PRIVATE ${GTK4_INCLUDE_DIRS})
# Linkage.
target_link_libraries(4crypt  SSC TSC)
target_link_libraries(g4crypt SSC TSC ${GTK4_LINK_LIBRARIES})
# CFlags.
target_compile_options(g4crypt PRIVATE ${GTK4_CFLAGS_OTHER})
