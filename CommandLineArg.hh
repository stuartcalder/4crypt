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
#ifndef COMMANDLINEARG_HH
#define COMMANDLINEARG_HH

// Local
#include "Core.hh"
// SSC
#include <SSC/CommandLineArg.h>

#define ARGS_ const int argc, char** SSC_RESTRICT argv, const int offset, void* SSC_RESTRICT data

namespace fourcrypt {

struct ArgProc
 {
  // Set the number of KDF threads to process simultaneously.
  static int batch_size(ARGS_);
  // Set the mode to Decrypt, and provide the path to the encrypted file.
  static int decrypt(ARGS_);
  // Set the mode to Describe, and provide the path to the encrypted file.
  static int describe(ARGS_);
  // Set the mode to Encrypt, and provide the path to the plaintext file.
  static int encrypt(ARGS_);
  // Disable password re-entry during encryption; not applicable to decryption.
  static int enter_password_once(ARGS_);
  // Enable entering an 'entropy password' to harden the CSPRNG.
  static int entropy(ARGS_);
  // Print help output and exit successfully.
  static int help(ARGS_);
  // Set the higher memory bound for the KDF.
  static int high_mem(ARGS_);
  // Set the number of KDF iterations per thread.
  static int iterations(ARGS_);
  // Set the lower memory bound for the KDF.
  static int low_mem(ARGS_);
  // Set the output file path.
  static int output(ARGS_);
  // Pad the output ciphertext as if it was an unpadded ciphertext of the provided size, rounded up to be divisible by 64.
  static int pad_as_if(ARGS_);
  // Pad the output ciphertext by the provided number of bytes, round up to be divisible by 64.
  static int pad_by(ARGS_);
  // Pad the output ciphertext up to the provided target size in bytes, rounded up to be divisible by 64.
  static int pad_to(ARGS_);
  // Set the number of KDF threads.
  static int threads(ARGS_);
  // Set the low and high KDF memory bounds to the same provided value.
  static int use_mem(ARGS_);
  // Enable usage of the Phi function in the KDF.
  static int use_phi(ARGS_);
 };

} // ! namespace fourcrypt
#undef ARGS_
#endif
