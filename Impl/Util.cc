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

#include <cstring>
#include <cstdlib>
#include <cinttypes>
#include <cctype>

#include <SSC/Error.h>
#include <SSC/String.h>
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
