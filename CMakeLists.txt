cmake_minimum_required(VERSION 3.10)
project(4crypt LANGUAGES CXX VERSION 1.0.0 DESCRIPTION "Strong symmetric encryption tool.")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MSVC)
  add_compile_options(-O3 -flto)
  add_link_options(-flto)
else()
  add_compile_options(/O2)
endif()

find_package(PkgConfig REQUIRED)
# Ask pkg-config for gtk4 (on MSYS2 the module is provided as gtk4)
pkg_check_modules(GTK4 REQUIRED gtk4)

add_executable(4crypt
  Impl/CliMain.cc
  Impl/CommandLineArg.cc
  Impl/Core.cc
  Impl/Util.cc
  CommandLineArg.hh
  Core.hh
  Util.hh
)

add_executable(g4crypt
  Impl/CommandLineArg.cc
  Impl/Core.cc
  Impl/GuiMain.cc
  Impl/Util.cc
  CommandLineArg.hh
  Core.hh
  Util.hh
  Gui.hh
)

target_include_directories(4crypt  PRIVATE "${PROJECT_SOURCE_DIR}")
target_include_directories(g4crypt PRIVATE "${PROJECT_SOURCE_DIR}")

# Link your other libraries (SSC, TSC) privately
target_link_libraries(4crypt  PRIVATE SSC TSC)
target_link_libraries(g4crypt PRIVATE SSC TSC)

# GTK4 for g4crypt
if(TARGET PkgConfig::gtk4)
  target_link_libraries(g4crypt PRIVATE PkgConfig::gtk4)
else()
  target_compile_options(g4crypt     PRIVATE ${GTK4_CFLAGS_OTHER})
  target_include_directories(g4crypt PRIVATE ${GTK4_INCLUDE_DIRS})
  target_link_libraries(g4crypt      PRIVATE ${GTK4_LIBRARIES})
endif()

