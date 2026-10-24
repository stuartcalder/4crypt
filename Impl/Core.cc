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
#include "Core.hh"
#include "Util.hh"
// SSC
#include <SSC/Terminal.h>
#include <SSC/Print.h>
#include <SSC/File.h>
// C++ C Lib
#include <cinttypes>
using namespace fourcrypt;

#define R_ SSC_RESTRICT

/* The 4crypt constants mirror libTSC's filecrypt constants. */
static_assert(Core::MAX_PW_BYTES      == TSC_FILECRYPT_MAX_PASSWORD_BYTES);
static_assert(Core::KEY_BYTES         == TSC_FILECRYPT_KEY_BYTES);
static_assert(Core::KEY_HEX_CHARS     == TSC_FILECRYPT_KEY_HEX_CHARS);
static_assert(Core::PAD_FACTOR        == TSC_FILECRYPT_PAD_FACTOR);
static_assert(Core::MAC_SIZE          == TSC_FILECRYPT_MAC_SIZE);
static_assert(Core::KEY_MODE_PASSWORD == TSC_FILECRYPT_KEY_MODE_PASSWORD);
static_assert(Core::KEY_MODE_RAW      == TSC_FILECRYPT_KEY_MODE_RAW);
/* The 4crypt error codes mirror libTSC's TSC_FILECRYPT_ERROR_* codes. */
static_assert(Core::ERROR_NONE                       == TSC_FILECRYPT_ERROR_NONE);
static_assert(Core::ERROR_NO_INPUT_FILENAME          == TSC_FILECRYPT_ERROR_NO_INPUT_FILENAME);
static_assert(Core::ERROR_NO_OUTPUT_FILENAME         == TSC_FILECRYPT_ERROR_NO_OUTPUT_FILENAME);
static_assert(Core::ERROR_INPUT_MEMMAP_FAILED        == TSC_FILECRYPT_ERROR_INPUT_MEMMAP_FAILED);
static_assert(Core::ERROR_OUTPUT_MEMMAP_FAILED       == TSC_FILECRYPT_ERROR_OUTPUT_MEMMAP_FAILED);
static_assert(Core::ERROR_GETTING_INPUT_FILESIZE     == TSC_FILECRYPT_ERROR_GETTING_INPUT_FILESIZE);
static_assert(Core::ERROR_INPUT_FILESIZE_TOO_SMALL   == TSC_FILECRYPT_ERROR_INPUT_FILESIZE_TOO_SMALL);
static_assert(Core::ERROR_INVALID_4CRYPT_FILE        == TSC_FILECRYPT_ERROR_INVALID_FILE);
static_assert(Core::ERROR_INPUT_SIZE_MISMATCH        == TSC_FILECRYPT_ERROR_INPUT_SIZE_MISMATCH);
static_assert(Core::ERROR_RESERVED_BYTES_USED        == TSC_FILECRYPT_ERROR_RESERVED_BYTES_USED);
static_assert(Core::ERROR_OUTPUT_FILE_EXISTS         == TSC_FILECRYPT_ERROR_OUTPUT_FILE_EXISTS);
static_assert(Core::ERROR_MAC_VALIDATION_FAILED      == TSC_FILECRYPT_ERROR_MAC_VALIDATION_FAILED);
static_assert(Core::ERROR_KDF_FAILED                 == TSC_FILECRYPT_ERROR_KDF_FAILED);
static_assert(Core::ERROR_METADATA_VALIDATION_FAILED == TSC_FILECRYPT_ERROR_METADATA_VALIDATION_FAILED);
static_assert(Core::ERROR_KEY_MODE_MISMATCH          == TSC_FILECRYPT_ERROR_KEY_MODE_MISMATCH);
static_assert(Core::ERROR_KEY_MALFORMED              == TSC_FILECRYPT_ERROR_KEY_MALFORMED);
static_assert(Core::ERROR_PASSWORD_TOO_LARGE         == TSC_FILECRYPT_ERROR_PASSWORD_TOO_LARGE);
static_assert(Core::ERROR_ENTROPY_TOO_LARGE          == TSC_FILECRYPT_ERROR_ENTROPY_TOO_LARGE);
static_assert(Core::ERROR_SIZE_OVERFLOW              == TSC_FILECRYPT_ERROR_SIZE_OVERFLOW);
/* The 4crypt error descriptors mirror libTSC's error descriptors. */
static_assert(static_cast<uint8_t>(Core::ErrType::CORE)   == TSC_FILECRYPT_ERR_TYPE_CORE);
static_assert(static_cast<uint8_t>(Core::ErrType::MEMMAP) == TSC_FILECRYPT_ERR_TYPE_MEMMAP);
static_assert(static_cast<uint8_t>(Core::InOutDir::NONE)   == TSC_FILECRYPT_IN_OUT_DIR_NONE);
static_assert(static_cast<uint8_t>(Core::InOutDir::INPUT)  == TSC_FILECRYPT_IN_OUT_DIR_INPUT);
static_assert(static_cast<uint8_t>(Core::InOutDir::OUTPUT) == TSC_FILECRYPT_IN_OUT_DIR_OUTPUT);

/* The prompt strings below spell out the maximum password length and the
 * exact number of hexadecimal characters in a raw symmetric key. Guard them
 * with static_assert's so they cannot fall out of sync with the constants.
 */
static_assert(Core::MAX_PW_BYTES == 125, "MAX_PW_BYTES changed!");
#define MAX_PW_BYTES_STR "125"
static_assert(Core::KEY_HEX_CHARS == 128, "KEY_HEX_CHARS changed!");
#define KEY_HEX_CHARS_STR "128"

#if   defined(SSC_OS_UNIXLIKE)
 #define NEWLINE_ "\n"
#elif defined(SSC_OS_WINDOWS)
 #define NEWLINE_ "\n\r"
#else
 #error "Invalid OS!"
#endif

using PlainOldData = Core::PlainOldData;

// Core static variable initialization.
std::string Core::password_prompt{
 "Please input a password (max length " MAX_PW_BYTES_STR " characters)." NEWLINE_
};
std::string Core::reentry_prompt{
  "Please input the same password again." NEWLINE_
};
std::string Core::entropy_prompt{
  "Please input up to " MAX_PW_BYTES_STR " random characters." NEWLINE_
};
std::string Core::key_prompt{
  "Please input your raw key as " KEY_HEX_CHARS_STR " hexadecimal characters." NEWLINE_
};
std::string Core::key_reentry_prompt{
  "Please input the same key again." NEWLINE_
};

/* Allocate a PlainOldData object on the heap and initialize its variables. */
Core::Core()
{
  this->pod = new PlainOldData;
  PlainOldData::init(*this->getPod());
}

/* Destroy the PlainOldData object and deallocate the memory. */
Core::~Core()
{
  PlainOldData::del(*this->getPod());
  delete this->getPod();
}

/* The initial state of most of the data in a PlainOldData consists of zero bytes, but there
 * are a few exceptions.
 */
void Core::PlainOldData::init(PlainOldData& pod)
{
  memset(pod.password_buffer   , 0, sizeof(pod.password_buffer));
  memset(pod.verify_buffer     , 0, sizeof(pod.verify_buffer));
  memset(pod.entropy_buffer    , 0, sizeof(pod.entropy_buffer));
  memset(pod.key_input_buffer  , 0, sizeof(pod.key_input_buffer));
  memset(pod.key_verify_buffer , 0, sizeof(pod.key_verify_buffer));
  memset(pod.user_key          , 0, sizeof(pod.user_key));
  pod.input_filename  = nullptr;
  pod.output_filename = nullptr;
  pod.input_filename_size  = 0;
  pod.output_filename_size = 0;
  pod.password_size = 0;
  pod.key_size = 0;
  pod.entropy_size  = 0;
  pod.padding_size  = 0;
  pod.thread_count  = 1;
  pod.thread_batch_size = 0;
  pod.execute_mode = ExeMode::NONE;
  pod.padding_mode = PadMode::ADD;
  pod.memory_low  = MEM_DEFAULT;
  pod.memory_high = MEM_DEFAULT;
  pod.iterations = 1;
  pod.flags      = 0;
}

/* Destroy and deallocate the data owned by a PlainOldData object. */
void Core::PlainOldData::del(PlainOldData& pod)
{
  delete[] pod.input_filename;
  delete[] pod.output_filename;
  SSC_secureZero(&pod, sizeof(pod));
}

/* Ensure that the thread batch size does not exceed the total specified thread count, as that
 * would be a contradiction.
 */
void Core::PlainOldData::touchup(PlainOldData& pod)
{
  if (pod.thread_batch_size == 0 || pod.thread_batch_size > pod.thread_count)
    pod.thread_batch_size = pod.thread_count;
}

/* Tune for lesser memory usage, and therefore faster execution. */
void Core::PlainOldData::set_fast(PlainOldData& pod)
{
  pod.memory_low  = MEM_FAST;
  pod.memory_high = MEM_FAST;
}

/* Tune for a middling amount of memory, providing more security without being too slow to execute. */
void Core::PlainOldData::set_normal(PlainOldData& pod)
{
  pod.memory_low  = MEM_NORMAL;
  pod.memory_high = MEM_NORMAL;
}

/* On systems that define SSC_HAS_GETAVAILABLESYSTEMMEMORY...
 *   Use as much memory as can be safely spared.
 * On all other systems...
 *   Tune for a middling amount of memory.
 */
void Core::PlainOldData::set_strong(PlainOldData& pod)
{
  #ifdef SSC_HAS_GETAVAILABLESYSTEMMEMORY
  const uint64_t available {SSC_getAvailableSystemMemory()};
  if (Core::memoryFromBitShift(MEM_STRONG) < available)
   {
    pod.memory_low  = MEM_STRONG;
    pod.memory_high = MEM_STRONG;
   }
  else
   {
    PlainOldData::set_normal(pod);
   }
  uint64_t n_threads;
  for (n_threads = 2; true; ++n_threads)
   {
    if ((Core::memoryFromBitShift(pod.memory_high) * n_threads) < available)
      break;
   }
  pod.thread_count = n_threads;

  #else
  PlainOldData::set_normal(pod);
  #endif
  pod.flags |= ENABLE_PHI;
}

/* Return a raw pointer to a PlainOldData object. */
PlainOldData* Core::getPod()
{
  return this->pod;
}

/* Map the TSC_Filecrypt error descriptors onto 4crypt's descriptors. The
 * static_assert's at the top of this file guarantee that the values match.
 */
void Core::mapErrorDescriptors(
 const TSC_Filecrypt_ErrType  lib_err_type,
 const TSC_Filecrypt_InOutDir lib_err_dir,
 ErrType* R_  err_type,
 InOutDir* R_ err_dir)
{
  if (err_type != nullptr)
    (*err_type) = static_cast<ErrType>(lib_err_type);
  if (err_dir != nullptr)
    (*err_dir)  = static_cast<InOutDir>(lib_err_dir);
}

SSC_CodeError_t Core::encrypt(
 ErrType*  err_type,
 InOutDir* err_dir)
{
  PlainOldData* mypod {this->getPod()};
  // We require an input filepath for encryption.
  if (mypod->input_filename == nullptr)
    return ERROR_NO_INPUT_FILENAME;
  // If an output file path wasn't provided, construct one.
  if (mypod->output_filename == nullptr) {
    mypod->output_filename_size = mypod->input_filename_size + 3;
    mypod->output_filename = new char[mypod->output_filename_size + 1];
    memcpy(
     mypod->output_filename,
     mypod->input_filename,
     mypod->input_filename_size);
    memcpy(
     mypod->output_filename + mypod->input_filename_size,
     extension,
     sizeof(extension));
  }

  // Get the size of the input file.
  size_t input_filesize;
  if (SSC_FilePath_getSize(mypod->input_filename, &input_filesize) != SSC_OK)
    return ERROR_GETTING_INPUT_FILESIZE;

  // Translate the user's requested padding into the bytes libTSC shall append.
  {
    const SSC_CodeError_t padding_err {this->resolvePadding(input_filesize)};
    if (padding_err != ERROR_NONE)
      return padding_err;
  }

  // If a raw symmetric key has not already been initialized, then initialize it.
  if (mypod->flags & Core::USE_KEY) {
    if (mypod->key_size == 0) {
      // Get the raw symmetric key.
      const SSC_CodeError_t key_err {this->getKey(not (mypod->flags & Core::ENTER_PASS_ONCE))};
      if (key_err != ERROR_NONE)
        return key_err;
    }
    if (mypod->flags & Core::SUPPLEMENT_ENTROPY) {
      // Get the entropy characters to harden libTSC's CSPRNG with.
      this->getPassword(false, true);
    }
  }
  // If the password has not already been initialized, then initialize it.
  else if (mypod->password_size == 0) {
    // Get the encryption password.
    this->getPassword(not (mypod->flags & Core::ENTER_PASS_ONCE), false);
    if (mypod->flags & Core::SUPPLEMENT_ENTROPY) {
      // Get the entropy characters to harden libTSC's CSPRNG with.
      this->getPassword(false, true);
    }
  }

  // Assemble the KDF parameters for libTSC.
  const TSC_Filecrypt_KdfParams kdf_params {
    mypod->memory_low,
    mypod->memory_high,
    mypod->iterations,
    static_cast<bool>(mypod->flags & Core::ENABLE_PHI),
    mypod->thread_count,
    mypod->thread_batch_size
  };
  /* Only pass entropy bytes when the user supplemented entropy. */
  const uint8_t* entropy     {nullptr};
  size_t         entropy_len {0};
  if (mypod->flags & Core::SUPPLEMENT_ENTROPY) {
    entropy     = mypod->entropy_buffer;
    entropy_len = static_cast<size_t>(mypod->entropy_size);
  }

  // Encrypt the input file. On failure, libTSC writes the error's type and
  // the concerning file to the descriptors below.
  TSC_Filecrypt_ErrType   lib_err_type {TSC_FILECRYPT_ERR_TYPE_CORE};
  TSC_Filecrypt_InOutDir  lib_err_dir  {TSC_FILECRYPT_IN_OUT_DIR_NONE};
  const SSC_Error_t result {
   (mypod->flags & Core::USE_KEY)
   ? TSC_Filecrypt_encryptWithKey(
      &lib_err_type,
      &lib_err_dir,
      mypod->input_filename,
      mypod->output_filename,
      mypod->user_key,
      mypod->padding_size,
      entropy,
      entropy_len)
   : TSC_Filecrypt_encryptWithPassword(
      &lib_err_type,
      &lib_err_dir,
      mypod->input_filename,
      mypod->output_filename,
      mypod->password_buffer,
      static_cast<size_t>(mypod->password_size),
      entropy,
      entropy_len,
      &kdf_params,
      mypod->padding_size)
  };
  // The entropy characters are no longer needed.
  SSC_secureZero(mypod->entropy_buffer, sizeof(mypod->entropy_buffer));
  mypod->entropy_size = 0;
  Core::mapErrorDescriptors(lib_err_type, lib_err_dir, err_type, err_dir);
  return static_cast<SSC_CodeError_t>(result);
}

/* Translate the user's requested padding (interpreted according to the
 * PlainOldData's padding_mode) into the number of padding bytes libTSC
 * should append to the input file's payload. libTSC rounds the payload up
 * to the next multiple of PAD_FACTOR, and never produces a file smaller
 * than the minimum 4crypt file size, so only the TARGET and AS_IF padding
 * modes necessitate translation here. Return ERROR_NONE on success, and
 * ERROR_INVALID_PADDING if the request is impossible.
 */
SSC_CodeError_t Core::resolvePadding(const uint64_t input_filesize)
{
  PlainOldData* mypod {this->getPod()};
  switch (mypod->padding_mode) {
    // @padding_size already counts the bytes to append to the payload.
    case PadMode::ADD:
      return ERROR_NONE;
    // Goal: The output file is an exact, specific size specified in @padding_size.
    case PadMode::TARGET:
      if (mypod->padding_size < input_filesize)
        break;
      if ((mypod->padding_size - input_filesize) < TSC_FILECRYPT_METADATA_SIZE)
        break;
      mypod->padding_size -= (input_filesize + TSC_FILECRYPT_METADATA_SIZE);
      mypod->padding_mode  = PadMode::ADD;
      return ERROR_NONE;
    // Add padding as if the input file's size were @padding_size.
    case PadMode::AS_IF:
      if (mypod->padding_size < input_filesize)
        break;
      mypod->padding_size -= input_filesize;
      mypod->padding_mode  = PadMode::ADD;
      return ERROR_NONE;
    // Unrecognized padding mode.
    default:
      break;
  }
  return ERROR_INVALID_PADDING;
}

SSC_CodeError_t Core::decrypt(
 ErrType*  err_type,
 InOutDir* err_dir)
{
  PlainOldData* mypod {this->getPod()};
  // Ensure an input filepath is provided.
  if (mypod->input_filename == nullptr) {
    if (err_dir != nullptr)
      (*err_dir) = InOutDir::INPUT;
    return ERROR_NO_INPUT_FILENAME;
  }
  if (mypod->output_filename == nullptr) {
    const uint64_t size {mypod->input_filename_size};
    if (size > extension_length && memcmp(mypod->input_filename + (size - extension_length), extension, extension_length) == 0) {
      mypod->output_filename_size = size - extension_length;
      mypod->output_filename = new char[mypod->output_filename_size + 1];
      memcpy(mypod->output_filename, mypod->input_filename, mypod->output_filename_size);
      mypod->output_filename[mypod->output_filename_size] = '\0';
    }
    else {
      if (err_dir != nullptr)
        (*err_dir) = InOutDir::OUTPUT;
      return ERROR_NO_OUTPUT_FILENAME;
    }
  }
  // If a raw symmetric key has not already been initialized, then initialize it.
  if (mypod->flags & Core::USE_KEY) {
    if (mypod->key_size == 0) {
      // Get the raw symmetric key.
      const SSC_CodeError_t key_err {this->getKey(false)};
      if (key_err != ERROR_NONE)
        return key_err;
    }
  }
  // If the decryption password has not already been initialized, then initialize it.
  else if (mypod->password_size == 0)
    this->getPassword(false, false);

  // Decrypt the input file. libTSC verifies the Message Authentication Code
  // before any plaintext is released, and on failure it writes the error's
  // type and the concerning file to the descriptors below.
  TSC_Filecrypt_ErrType   lib_err_type {TSC_FILECRYPT_ERR_TYPE_CORE};
  TSC_Filecrypt_InOutDir  lib_err_dir  {TSC_FILECRYPT_IN_OUT_DIR_NONE};
  const SSC_Error_t result {
   (mypod->flags & Core::USE_KEY)
   ? TSC_Filecrypt_decryptWithKey(
      &lib_err_type,
      &lib_err_dir,
      mypod->input_filename,
      mypod->output_filename,
      mypod->user_key,
      mypod->thread_batch_size)
   : TSC_Filecrypt_decryptWithPassword(
      &lib_err_type,
      &lib_err_dir,
      mypod->input_filename,
      mypod->output_filename,
      mypod->password_buffer,
      static_cast<size_t>(mypod->password_size),
      mypod->thread_batch_size)
  };
  Core::mapErrorDescriptors(lib_err_type, lib_err_dir, err_type, err_dir);
  return static_cast<SSC_CodeError_t>(result);
}

/* Describe the metadata of a 4crypt-encrypted file. libTSC reads the
 * plaintext header of the input file; no credential is required, and the
 * Message Authentication Code is not verified.
 */
SSC_CodeError_t Core::describe(
 ErrType*  err_type,
 InOutDir* err_dir)
{
  PlainOldData* mypod {this->getPod()};
  if (mypod->input_filename == nullptr) {
    if (err_dir != nullptr)
      (*err_dir) = InOutDir::INPUT;
    return ERROR_NO_INPUT_FILENAME;
  }
  TSC_Filecrypt_HeaderInfo info {};
  TSC_Filecrypt_ErrType   lib_err_type {TSC_FILECRYPT_ERR_TYPE_CORE};
  TSC_Filecrypt_InOutDir  lib_err_dir  {TSC_FILECRYPT_IN_OUT_DIR_NONE};
  const SSC_Error_t result {
   TSC_Filecrypt_describe(
    &lib_err_type,
    &lib_err_dir,
    mypod->input_filename,
    &info)
  };
  if (result != SSC_OK) {
    Core::mapErrorDescriptors(lib_err_type, lib_err_dir, err_type, err_dir);
    return static_cast<SSC_CodeError_t>(result);
  }
  // Print plaintext header information from beginning to end.
  if (info.key_mode == Core::KEY_MODE_RAW)
    puts("The file is encrypted with a raw symmetric key.");
  else if (info.uses_phi)
    puts("The Phi function IS USED! Beware cache-timing attacks!");
  printf(
   "The file size is................%s.\n",
   Core::makeMemoryString(info.file_size).c_str());
  if (info.key_mode != Core::KEY_MODE_RAW) {
    if (info.memory_low == info.memory_high) {
      printf(
       "The KDF Memory Bound is.........%s\n",
       Core::makeMemoryStringBitShift(info.memory_low).c_str());
    }
    else {
      printf("The KDF Lower Memory Bound is...%s\n", Core::makeMemoryStringBitShift(info.memory_low).c_str());
      printf("The KDF Upper Memory Bound is...%s\n", Core::makeMemoryStringBitShift(info.memory_high).c_str());
    }
    printf("The KDF Thread Count is.........%" PRIu64 " thread(s).\n", info.thread_count);
    printf("Each KDF thread iterates........%" PRIu8  " time(s).\n", info.iterations);
  }
  static constexpr uint8_t print_mode {SSC_PRINT_HEX | SSC_PRINT_PREFIX | SSC_PRINT_NEWLINE};

  printf("The Threefish512 Tweak is.......");
  SSC_printBytesMode(info.tweak, TSC_THREEFISH512_TWEAK_BYTES, print_mode);

  printf("The Catena512 Salt is...........");
  SSC_printBytesMode(info.salt, sizeof(info.salt), print_mode);

  printf("Threefish512 CTR-Mode's IV is...");
  SSC_printBytesMode(info.ctr_iv, sizeof(info.ctr_iv), print_mode);
  return ERROR_NONE;
}

/* Prompt the user for a password to be entered at a command-line terminal.
 * If @enter_twice is true the user will be prompted a second time to confirm that
 * they entered the password correctly.
 * If @entropy is true the password will be written to a unique entropy buffer, that
 * will later get passed to libTSC to harden its CSPRNG.
 */
void Core::getPassword(bool enter_twice, bool entropy)
{
  PlainOldData* mypod {this->getPod()};
  SSC_Terminal_init();
  if (enter_twice && !entropy) {
    mypod->password_size = static_cast<uint64_t>(
     SSC_Terminal_getPasswordChecked(
      mypod->password_buffer,
      mypod->verify_buffer,
      Core::password_prompt.c_str(),
      Core::reentry_prompt.c_str(),
      1,
      MAX_PW_BYTES,
      PW_BUFFER_BYTES));
    SSC_secureZero(mypod->verify_buffer, sizeof(mypod->verify_buffer));
    SSC_Terminal_end();
  }
  else {
    uint8_t*    p;
    const char* str;
    uint64_t*   sz;
    if (entropy) {
      p   = mypod->entropy_buffer;
      str = Core::entropy_prompt.c_str();
      sz  = &mypod->entropy_size;
    }
    else {
      p   = mypod->password_buffer;
      str = Core::password_prompt.c_str();
      sz  = &mypod->password_size;
    }
    *sz = static_cast<uint64_t>(SSC_Terminal_getPassword(
     p,
     str,
     1,
     MAX_PW_BYTES,
     PW_BUFFER_BYTES));
    SSC_Terminal_end();
  }
}

/* Prompt the user for a raw symmetric key to be entered at a command-line terminal
 * as KEY_HEX_CHARS hexadecimal characters.
 * If @enter_twice is true the user will be prompted a second time to confirm that
 * they entered the key correctly.
 * On failure to decode the hexadecimal characters, return ERROR_KEY_MALFORMED.
 */
SSC_CodeError_t Core::getKey(bool enter_twice)
{
  PlainOldData* mypod {this->getPod()};
  SSC_Terminal_init();
  uint64_t hex_size;
  if (enter_twice) {
    hex_size = static_cast<uint64_t>(
     SSC_Terminal_getPasswordChecked(
      mypod->key_input_buffer,
      mypod->key_verify_buffer,
      Core::key_prompt.c_str(),
      Core::key_reentry_prompt.c_str(),
      static_cast<int>(Core::KEY_HEX_CHARS),
      static_cast<int>(Core::KEY_HEX_CHARS),
      static_cast<int>(Core::KEY_BUFFER_BYTES)));
    SSC_secureZero(mypod->key_verify_buffer, sizeof(mypod->key_verify_buffer));
  }
  else {
    hex_size = static_cast<uint64_t>(
     SSC_Terminal_getPassword(
      mypod->key_input_buffer,
      Core::key_prompt.c_str(),
      static_cast<int>(Core::KEY_HEX_CHARS),
      static_cast<int>(Core::KEY_HEX_CHARS),
      static_cast<int>(Core::KEY_BUFFER_BYTES)));
  }
  SSC_Terminal_end();
  // Decode the hexadecimal characters into the raw symmetric key.
  const SSC_Error_t decode_err {parse_hex_key(
   reinterpret_cast<const char*>(mypod->key_input_buffer),
   hex_size,
   Core::KEY_HEX_CHARS,
   mypod->user_key)};
  SSC_secureZero(mypod->key_input_buffer, sizeof(mypod->key_input_buffer));
  if (decode_err != SSC_OK)
    return ERROR_KEY_MALFORMED;
  mypod->key_size = Core::KEY_BYTES;
  return ERROR_NONE;
}

/* Return a std::string representation of the bitshift interpreted as a number of bytes. */
std::string Core::makeMemoryStringBitShift(const uint8_t mem_bitshift)
{
  return Core::makeMemoryString(static_cast<uint64_t>(1) << (mem_bitshift + 6));
}

/* Return a std::string representation of the uint64_t interpreted as a number of bytes. */
std::string Core::makeMemoryString(const uint64_t value)
{
  constexpr uint64_t kibibyte {1024};
  constexpr uint64_t mebibyte {kibibyte * kibibyte};
  constexpr uint64_t gibibyte {mebibyte * kibibyte};
  constexpr uint64_t tebibyte {gibibyte * kibibyte};
  enum class Size {
    None = 0, Kibi = 1, Mebi = 2, Gibi = 3, Tebi = 4
  };
  static const char* size_strings[] = {
    "Byte(s)", "Kibibyte(s)", "Mebibyte(s)", "Gibibyte(s)", "Tebibyte(s)"
  };

  std::string s             {};
  uint64_t    size          {1};
  uint64_t    size_count    {0};
  double      size_fraction {0.0};
  Size        size_enum     {Size::None};

  // Determine which size class the value belongs to.
  if (value >= tebibyte) {
    size = tebibyte;
    size_enum = Size::Tebi;
  }
  else if (value >= gibibyte) {
    size = gibibyte;
    size_enum = Size::Gibi;
  }
  else if (value >= mebibyte) {
    size = mebibyte;
    size_enum = Size::Mebi;
  }
  else if (value >= kibibyte) {
    size = kibibyte;
    size_enum = Size::Kibi;
  }
  // Determine the number of "sizes" in the value.
  size_count = value / size;
  // Determine what fraction of a size the value contains.
  if (size != 1) {
    size_fraction = static_cast<double>(value - (size_count * size)) / size;
  }
  s += std::to_string(size_count); // Append the number of "sizes".
  // If applicable, append the size fraction.
  if (size_fraction != 0.0) {
    s += ".";
    {
      std::string tmp {std::to_string(size_fraction * 100)};
      tmp.resize(2);
      s += tmp;
    }
  }
  s += ' ';
  // Append the size string.
  s += size_strings[static_cast<int>(size_enum)];

  return s;
}
