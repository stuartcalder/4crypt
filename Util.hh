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
#ifndef FOURCRYPT_UTIL_HH
#define FOURCRYPT_UTIL_HH
#include <SSC/Macro.h>
#include <SSC/Error.h>
#define R_ SSC_RESTRICT

namespace fourcrypt
 {
  uint8_t
  parse_memory(const char* R_ cstr, const size_t len);

  uint8_t
  parse_iterations(const char* R_ cstr, const size_t len);

  uint64_t
  parse_integer(const char* R_ cstr, const size_t len);

  /* Decode exactly @hex_chars hexadecimal characters from @str into @out
   * (@hex_chars / 2 bytes). Leading and trailing whitespace is ignored, and an
   * optional "0x"/"0X" prefix is accepted. Return SSC_OK on success, and SSC_ERR
   * if @str does not consist of exactly @hex_chars valid hexadecimal characters.
   */
  SSC_Error_t
  parse_hex_key(const char* R_ str, const size_t str_len, const size_t hex_chars, uint8_t* R_ out);

  /* Read the key file at @path, and decode exactly @hex_chars hexadecimal characters
   * from its contents into @out (@hex_chars / 2 bytes). Return SSC_OK on success, and
   * SSC_ERR if the file cannot be read or does not hold a valid hexadecimal key.
   */
  SSC_Error_t
  parse_key_file(const char* R_ path, const size_t hex_chars, uint8_t* R_ out);
 }
#undef R_
#endif
