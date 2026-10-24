cmake_minimum_required(VERSION 3.10)
project(4crypt LANGUAGES CXX VERSION 0.3.0 DESCRIPTION "Strong symmetric encryption tool.")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

string(TOLOWER "${CMAKE_SYSTEM_NAME}" OS_LOWER)
set(SUFFIXES_OG ${CMAKE_FIND_LIBRARY_SUFFIXES})
set(LANG_FLAGS "")

if    (APPLE)
  set(SUFFIXES_STATIC  .a)
  set(SUFFIXES_DYNAMIC .dylib;.so)
elseif(WIN32)
  set(SUFFIXES_STATIC  .lib)
  set(SUFFIXES_DYNAMIC .dll)
elseif(UNIX)
  set(SUFFIXES_STATIC  .a)
  set(SUFFIXES_DYNAMIC .so)
endif()

if(NOT MSVC)
  add_compile_options(-O3 -flto)
  add_link_options(-flto)
else()
  add_compile_options(/O2)
endif()

if (WIN32 AND MSVC)
    set(_D "/D")
else()
    set(_D "-D")
endif()

# TODO: Make this optional.
if (WIN32)
  list(APPEND LANG_FLAGS "${_D}FOURCRYPT_IS_PORTABLE")
endif()

find_package(PkgConfig REQUIRED)
# Ask pkg-config for gtk4 (on MSYS2 the module is provided as gtk4)
pkg_check_modules(GTK4 REQUIRED gtk4)

# 4crypt's file operations are implemented inside libTSC's filecrypt module,
# which requires a recent tsc_c that provides TSC/Filecrypt.h.
find_path(TSC_FILECRYPT_HEADER TSC/Filecrypt.h)
if(NOT TSC_FILECRYPT_HEADER)
  message(FATAL_ERROR
   "TSC/Filecrypt.h was not found! Build and install a recent tsc_c "
   "(https://github.com/stuartcalder/tsc_c), which provides it.")
endif()

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

option(STATIC_SSC "Statically link SSC" OFF)
option(STATIC_TSC "Statically link TSC" OFF)

set(LIB_DEPS "")

# Find static/dynamic dependencies.
if (STATIC_SSC)
  list(APPEND LANG_FLAGS "${_D}SSC_EXTERN_STATIC_LIB")
  if (UNIX)
    find_library(NCURSES_LIB ncurses)
    list(APPEND LIB_DEPS ${NCURSES_LIB})
    if (LINUX)
      find_library(TINFO_LIB tinfo)
      list(APPEND LIB_DEPS ${TINFO_LIB})
    endif()
  endif()
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${SUFFIXES_STATIC})
else()
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${SUFFIXES_DYNAMIC})
endif()
find_library(SSC_LIB SSC)
list(APPEND LIB_DEPS ${SSC_LIB})
if (STATIC_TSC)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${SUFFIXES_STATIC})
else()
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${SUFFIXES_DYNAMIC})
endif()
find_library(TSC_LIB TSC)
list(APPEND LIB_DEPS ${TSC_LIB})

set(CMAKE_FIND_LIBRARY_SUFFIXES ${SUFFIXES_OG})

target_include_directories(4crypt  PRIVATE "${PROJECT_SOURCE_DIR}")
target_include_directories(g4crypt PRIVATE "${PROJECT_SOURCE_DIR}")
# Ensure the TSC headers (including TSC/Filecrypt.h) are found even when
# libTSC is installed somewhere non-standard.
target_include_directories(4crypt  PRIVATE "${TSC_FILECRYPT_HEADER}")
target_include_directories(g4crypt PRIVATE "${TSC_FILECRYPT_HEADER}")
target_compile_options(4crypt PRIVATE  "${LANG_FLAGS}")
target_compile_options(g4crypt PRIVATE "${LANG_FLAGS}")

if (WIN32)
  set_target_properties(g4crypt PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

# Link your other libraries (SSC, TSC) privately
target_link_libraries(4crypt  PRIVATE ${LIB_DEPS})
target_link_libraries(g4crypt PRIVATE ${LIB_DEPS})

# GTK4 for g4crypt
if(TARGET PkgConfig::gtk4)
  target_link_libraries(g4crypt PRIVATE PkgConfig::gtk4)
else()
  target_compile_options(g4crypt     PRIVATE ${GTK4_CFLAGS_OTHER})
  target_include_directories(g4crypt PRIVATE ${GTK4_INCLUDE_DIRS})
  target_link_libraries(g4crypt      PRIVATE ${GTK4_LIBRARIES})
endif()

