#ifndef FOURCRYPT_UTIL_HH
#define FOURCRYPT_UTIL_HH
#include <SSC/Macro.h>
#define R_ SSC_RESTRICT

namespace fourcrypt
{

uint8_t
parse_memory(const char* R_ cstr, const size_t len);

uint8_t
parse_iterations(const char* R_ cstr, const size_t len);

uint64_t
parse_integer(const char* R_ cstr, const size_t len);

}
#undef R_
#endif
