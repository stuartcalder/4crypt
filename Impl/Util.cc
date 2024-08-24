#include "Util.hh"

#include <cstring>
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
  SSC_assertMsg(num_digits > 0 && num_digits < num_digit_limit, "Specified memory parameter digits (%" PRIu64 ")\n", num_digits);
  requested_bytes = static_cast<uint64_t>(std::strtoumax(temp, nullptr, 10));
  delete temp;
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
