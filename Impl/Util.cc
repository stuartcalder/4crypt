/* *
 * 4crypt - Memory-Hard Symmetric File Encryption Program
 * Copyright (C) 2025 Stuart Calder
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#include "Util.hh"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cinttypes>
#include <cctype>

#include <SSC/Error.h>
#include <SSC/Operation.h>
#include <SSC/File.h>
#include <SSC/SSC_String.h>
#define R_ SSC_RESTRICT

using namespace fourcrypt;
constexpr uint64_t KIBIBYTE {1024};
constexpr uint64_t MEBIBYTE {KIBIBYTE * KIBIBYTE};
constexpr uint64_t GIBIBYTE {MEBIBYTE * KIBIBYTE};

uint8_t
fourcrypt::parse_memory(const char* R_ str, const size_t len)
{
  uint64_t requested_bytes = 0;
  uint64_t multiplier = 1;
  uint64_t num_digits = 0;
  char* const temp = new char[len + 1];
  std::memcpy(temp, str, len + 1);
  for (size_t i = 0; i < len; ++i) {
    switch (std::toupper(static_cast<unsigned char>(str[i]))) {
      case 'K':
        multiplier = KIBIBYTE / 64;
      	goto have_multiplier;
      case 'M':
	      multiplier = MEBIBYTE / 64;
	      goto have_multiplier;
      case 'G':
	      multiplier = GIBIBYTE / 64;
	      goto have_multiplier;
      default:
	      SSC_assertMsg(isdigit(static_cast<unsigned char>(str[i])), "Invalid memory string '%s'!\n", str);
    }
  }
have_multiplier:
  /* Shift all the digits to the beginning of @temp and store the number
   * of digits in @num_digits. */
  num_digits = static_cast<uint64_t>(SSC_Cstr_shiftDigitsToFront(temp, len));
  SSC_assertMsg(num_digits, "No number supplied with memory specification!\n");

  constexpr uint64_t BYTE_MAX = 10000;
  constexpr uint64_t KIBIBYTE_MAX = 17592186044416;
  constexpr uint64_t MEBIBYTE_MAX = 17179869184;
  constexpr uint64_t GIBIBYTE_MAX = 16777216;
  uint64_t num_digit_limit = 0;
  switch (multiplier) {
    case 1:
      num_digit_limit = BYTE_MAX;
      break;
    case KIBIBYTE / 64:
      num_digit_limit = KIBIBYTE_MAX;
      break;
    case MEBIBYTE / 64:
      num_digit_limit = MEBIBYTE_MAX;
      break;
    case GIBIBYTE / 64:
      num_digit_limit = GIBIBYTE_MAX;
      break;
  }
  SSC_assertMsg(num_digits > 0 and num_digits < num_digit_limit, "Specified memory parameter digits (%" PRIu64 ")\n", num_digits);
  requested_bytes = static_cast<uint64_t>(std::strtoumax(temp, nullptr, 10));
  delete[] temp;
  requested_bytes *= multiplier;
  SSC_assertMsg(requested_bytes, "Zero memory requested!\n");
  uint64_t mask = UINT64_C(0x80'00'00'00'00'00'00'00);
  uint8_t mem = 63;
  while (!(mask & requested_bytes)) {
    mask >>= 1;
    --mem;
  }
  return mem;
}

uint8_t
fourcrypt::parse_iterations(const char* R_ str, const size_t len)
{
  char* const temp = new char[len + 1];
  std::memcpy(temp, str, len + 1);
  uint64_t num_digits = static_cast<uint64_t>(SSC_Cstr_shiftDigitsToFront(temp, len));
  if (num_digits < 1 or num_digits > 3) {
    delete[] temp;
    return 0;
  }
  int it = std::atoi(temp);
  delete[] temp;
  if (it < 1 or it > 255)
    return 0;
  return static_cast<uint8_t>(it);
}

uint64_t
fourcrypt::parse_integer(const char* R_ cstr, const size_t len)
{
  char* const temp = new char[len + 1];
  std::memcpy(temp, cstr, len + 1);
  SSC_Cstr_shiftDigitsToFront(temp, len);
  uint64_t integer = static_cast<uint64_t>(std::strtoumax(temp, nullptr, 10));
  delete[] temp;
  return integer;
}

namespace {
int
hex_digit_value(const char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}
} // ! namespace

SSC_Error_t
fourcrypt::parse_hex_key(
 const char* R_ str,
 const size_t str_len,
 const size_t hex_chars,
 uint8_t* R_  out)
{
  if (hex_chars == 0 || (hex_chars % 2) != 0)
    return SSC_ERR;
  size_t begin {0};
  size_t end   {str_len};
  // Ignore leading and trailing whitespace.
  while (begin < end && std::isspace(static_cast<unsigned char>(str[begin])))
    ++begin;
  while (end > begin && std::isspace(static_cast<unsigned char>(str[end - 1])))
    --end;
  // Accept an optional "0x"/"0X" prefix.
  if ((end - begin) > 2 && str[begin] == '0' && (str[begin + 1] == 'x' || str[begin + 1] == 'X'))
    begin += 2;
  if ((end - begin) != hex_chars)
    return SSC_ERR;
  const size_t num_bytes {hex_chars / 2};
  for (size_t i = 0; i < num_bytes; ++i) {
    const int hi {hex_digit_value(str[begin + (2 * i)])};
    const int lo {hex_digit_value(str[begin + (2 * i) + 1])};
    if (hi < 0 || lo < 0)
      return SSC_ERR;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return SSC_OK;
}

SSC_Error_t
fourcrypt::parse_key_file(const char* R_ path, const size_t hex_chars, uint8_t* R_ out)
{
  size_t file_size {0};
  if (SSC_FilePath_getSize(path, &file_size) != SSC_OK)
    return SSC_ERR;
  // The key file must hold at least @hex_chars characters; do not read absurdly large files.
  if (file_size < hex_chars || file_size > ((2 * hex_chars) + 2))
    return SSC_ERR;
  std::FILE* f {std::fopen(path, "rb")};
  if (f == nullptr)
    return SSC_ERR;
  char* const buffer = new char[file_size + 1];
  const size_t num_read {std::fread(buffer, 1, file_size, f)};
  std::fclose(f);
  if (num_read != file_size) {
    delete[] buffer;
    return SSC_ERR;
  }
  buffer[file_size] = '\0';
  const SSC_Error_t result {parse_hex_key(buffer, file_size, hex_chars, out)};
  // Do not leave key material or its hexadecimal representation lying around.
  SSC_secureZero(buffer, file_size + 1);
  delete[] buffer;
  return result;
}
