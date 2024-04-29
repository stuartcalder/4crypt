#ifndef FOURCRYPT_GUI_HH
#define FOURCRYPT_GUI_HH

#include "FourCrypt.hh"
#include <gtk/gtk.h>

#if   defined(SSC_OS_UNIXLIKE)
 #define FOURCRYPT_GUI_BINARY        "g4crypt"
 #define FOURCRYPT_GUI_BINARY_LENGTH 7
#elif defined(SSC_OS_WINDOWS)
 #define FOURCRYPT_GUI_BINARY        "g4crypt.exe"
 #define FOURCRYPT_GUI_BINARY_LENGTH 11
#else
 #error "Unsupported OS".
#endif

#endif
