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
#ifndef FOURCRYPT_CORE_HH
#define FOURCRYPT_CORE_HH

// C++ STL
#include <string>
// SSC
#include <SSC/Typedef.h>
#include <SSC/Memory.h>
// TSC
#include <TSC/Filecrypt.h>

#if !defined(SSC_LANG_CPP)
 #error "We need C++!"
#elif SSC_LANG_CPP < SSC_CPP_20
 #error "We need at least C++20!"
#endif

#define R_ SSC_RESTRICT

namespace fourcrypt
 {
  /* 4crypt's front end to libTSC's filecrypt module, which implements the
   * entire 4crypt on-disk format. Core gathers credentials and parameters
   * from the user, and delegates the file operations themselves to the
   * TSC_Filecrypt_* procedures.
   */
  class Core
   {
   public:
  //// Public constants and types.

    static constexpr size_t MAX_PW_BYTES    {TSC_FILECRYPT_MAX_PASSWORD_BYTES}; // (125)
    static constexpr size_t PW_BUFFER_BYTES {MAX_PW_BYTES + 1};
    // Raw symmetric keys are KEY_BYTES bytes, provided as KEY_HEX_CHARS hexadecimal characters.
    static constexpr size_t KEY_BYTES        {TSC_FILECRYPT_KEY_BYTES};     // (64)
    static constexpr size_t KEY_HEX_CHARS    {TSC_FILECRYPT_KEY_HEX_CHARS}; // (128)
    static constexpr size_t KEY_BUFFER_BYTES {KEY_HEX_CHARS + 2};
    // The key mode of a 4crypt-encrypted file, stored in the header's key-mode field.
    static constexpr uint8_t KEY_MODE_PASSWORD {TSC_FILECRYPT_KEY_MODE_PASSWORD}; // The secret keys were derived from a password.
    static constexpr uint8_t KEY_MODE_RAW      {TSC_FILECRYPT_KEY_MODE_RAW};      // The secret keys were expanded from a raw symmetric key.
    static constexpr char    extension[4] { '.', '4', 'c', '\0' };
    static constexpr size_t  extension_length {3}; // Only consider '.', '4', and 'c'.

    static constexpr SSC_BitFlag8_t ENABLE_PHI         {0b00000001}; // Enable the Phi function.
    static constexpr SSC_BitFlag8_t SUPPLEMENT_ENTROPY {0b00000010}; // Supplement entropy from stdin.
    static constexpr SSC_BitFlag8_t ENTER_PASS_ONCE    {0b00000100}; // Don't re-enter password during encrypt.
    static constexpr SSC_BitFlag8_t USE_KEY            {0b00001000}; // Use a raw symmetric key instead of a password.
    static constexpr SSC_BitFlag8_t KEY_FROM_FILE      {0b00010000}; // The raw symmetric key was read from a key file.
    static constexpr uint8_t MEM_FAST    {TSC_FILECRYPT_MEM_FAST};   // 128 Mebibytes.
    static constexpr uint8_t MEM_NORMAL  {TSC_FILECRYPT_MEM_NORMAL}; // 1   Gibibyte.
    static constexpr uint8_t MEM_STRONG  {TSC_FILECRYPT_MEM_STRONG}; // 2   Gibibytes.
    static constexpr uint8_t MEM_DEFAULT {MEM_NORMAL};
    static constexpr uint64_t memoryFromBitShift(uint8_t bitshift)
     {
      return static_cast<uint64_t>(1) << (bitshift + 6);
     }

    static constexpr uint64_t PAD_FACTOR {TSC_FILECRYPT_PAD_FACTOR}; // Files will always be a multiple of 64 bytes.
    static constexpr uint64_t MAC_SIZE   {TSC_FILECRYPT_MAC_SIZE};   // The Message Authentication Code is 64 bytes.

    // What does the user want the software to do?
    enum class ExeMode
     {
      NONE, ENCRYPT, DECRYPT, DESCRIBE
     };
    // How does the user want the padding they requested to be done?
    enum class PadMode
     {
      ADD, TARGET, AS_IF
     };
    // Distinguish input from output files.
    enum class InOutDir
     {
      NONE   = TSC_FILECRYPT_IN_OUT_DIR_NONE,
      INPUT  = TSC_FILECRYPT_IN_OUT_DIR_INPUT,
      OUTPUT = TSC_FILECRYPT_IN_OUT_DIR_OUTPUT
     };
    // Distinguish errors produced by 4crypt/libTSC logic from errors produced inside memory-map operations.
    enum class ErrType
     {
      CORE   = TSC_FILECRYPT_ERR_TYPE_CORE,
      MEMMAP = TSC_FILECRYPT_ERR_TYPE_MEMMAP
     };
  //// 4crypt Code Errors. (The numbering mirrors libTSC's TSC_FILECRYPT_ERROR_* codes.)

    static constexpr SSC_CodeError_t ERROR_NONE                       {TSC_FILECRYPT_ERROR_NONE};
    static constexpr SSC_CodeError_t ERROR_NO_INPUT_FILENAME          {TSC_FILECRYPT_ERROR_NO_INPUT_FILENAME};
    static constexpr SSC_CodeError_t ERROR_NO_OUTPUT_FILENAME         {TSC_FILECRYPT_ERROR_NO_OUTPUT_FILENAME};
    static constexpr SSC_CodeError_t ERROR_INPUT_MEMMAP_FAILED        {TSC_FILECRYPT_ERROR_INPUT_MEMMAP_FAILED};
    static constexpr SSC_CodeError_t ERROR_OUTPUT_MEMMAP_FAILED       {TSC_FILECRYPT_ERROR_OUTPUT_MEMMAP_FAILED};
    static constexpr SSC_CodeError_t ERROR_GETTING_INPUT_FILESIZE     {TSC_FILECRYPT_ERROR_GETTING_INPUT_FILESIZE};
    static constexpr SSC_CodeError_t ERROR_INPUT_FILESIZE_TOO_SMALL   {TSC_FILECRYPT_ERROR_INPUT_FILESIZE_TOO_SMALL};
    static constexpr SSC_CodeError_t ERROR_INVALID_4CRYPT_FILE        {TSC_FILECRYPT_ERROR_INVALID_FILE};
    static constexpr SSC_CodeError_t ERROR_INPUT_SIZE_MISMATCH        {TSC_FILECRYPT_ERROR_INPUT_SIZE_MISMATCH};
    static constexpr SSC_CodeError_t ERROR_RESERVED_BYTES_USED        {TSC_FILECRYPT_ERROR_RESERVED_BYTES_USED};
    static constexpr SSC_CodeError_t ERROR_OUTPUT_FILE_EXISTS         {TSC_FILECRYPT_ERROR_OUTPUT_FILE_EXISTS};
    static constexpr SSC_CodeError_t ERROR_MAC_VALIDATION_FAILED      {TSC_FILECRYPT_ERROR_MAC_VALIDATION_FAILED};
    static constexpr SSC_CodeError_t ERROR_KDF_FAILED                 {TSC_FILECRYPT_ERROR_KDF_FAILED};
    static constexpr SSC_CodeError_t ERROR_METADATA_VALIDATION_FAILED {TSC_FILECRYPT_ERROR_METADATA_VALIDATION_FAILED};
    static constexpr SSC_CodeError_t ERROR_KEY_MODE_MISMATCH          {TSC_FILECRYPT_ERROR_KEY_MODE_MISMATCH};
    static constexpr SSC_CodeError_t ERROR_KEY_MALFORMED              {TSC_FILECRYPT_ERROR_KEY_MALFORMED};
    static constexpr SSC_CodeError_t ERROR_KEY_MODE_UNSUPPORTED       {TSC_FILECRYPT_ERROR_KEY_MODE_UNSUPPORTED};
    static constexpr SSC_CodeError_t ERROR_PASSWORD_TOO_LARGE         {TSC_FILECRYPT_ERROR_PASSWORD_TOO_LARGE};
    static constexpr SSC_CodeError_t ERROR_ENTROPY_TOO_LARGE          {TSC_FILECRYPT_ERROR_ENTROPY_TOO_LARGE};
    static constexpr SSC_CodeError_t ERROR_SIZE_OVERFLOW              {TSC_FILECRYPT_ERROR_SIZE_OVERFLOW};
    /* 4crypt-local error: the user requested an impossible amount of padding
     * (e.g. --pad-to with a target smaller than the input file). libTSC does
     * not produce this error.
     */
    static constexpr SSC_CodeError_t ERROR_INVALID_PADDING            { -20};
    /* The data collected from the user that Core passes to libTSC. All the
     * secret bytes inside live only as long as the PlainOldData object itself.
     */
    struct PlainOldData
     {
       alignas(uint64_t) uint8_t   password_buffer   [PW_BUFFER_BYTES]; // Store the password here when encrypting/decrypting.
       uint8_t                     verify_buffer     [PW_BUFFER_BYTES]; // Verify @password_buffer here when encrypting.
       alignas(uint64_t) uint8_t   entropy_buffer    [PW_BUFFER_BYTES]; // Store entropy characters here before passing them to libTSC.
       alignas(uint64_t) uint8_t   key_input_buffer  [KEY_BUFFER_BYTES]; // Store the hexadecimal characters of a raw symmetric key here.
       alignas(uint64_t) uint8_t   key_verify_buffer [KEY_BUFFER_BYTES]; // Verify @key_input_buffer here when encrypting.
       alignas(uint64_t) uint8_t   user_key          [KEY_BYTES];        // The decoded raw symmetric key.
       char*                       input_filename;  // Where is the input file?
       char*                       output_filename; // Where is the output file?
       uint64_t                    input_filename_size;  // How many bytes is the input file name?
       uint64_t                    output_filename_size; // How many bytes is the output file name?
       uint64_t                    password_size; // How many bytes is the password?
       uint64_t                    key_size;      // How many bytes is the raw symmetric key? (Zero means there is none.)
       uint64_t                    entropy_size;  // How many entropy bytes were provided?
       uint64_t                    padding_size;  // How many bytes of padding?
       uint64_t                    thread_count;  // How many KDF threads?
       uint64_t                    thread_batch_size; // How many KDF threads execute concurrently?
       ExeMode                     execute_mode;  // What shall we do? Encrypt? Decrypt? Describe?
       PadMode                     padding_mode;  // What context were the padding bytes specified for?
       uint8_t                     memory_low;    // What is the lower memory bound of the KDF?
       uint8_t                     memory_high;   // What is the upper memory bound of the KDF?
       uint8_t                     iterations;    // How many times will each thread of the KDF iterate?
       SSC_BitFlag8_t              flags;         // Bit Flag parameters, such as whether to enable entropy supplementation.

       static void init(PlainOldData& pod);    // Initialize the values of a PlainOldData object.
       static void del(PlainOldData& pod);     // Destroy a PlainOldData object.
       static void touchup(PlainOldData& pod); // Ensure the values inside a PlainOldData object are valid & consistent.
       static void set_fast(PlainOldData& pod);
       static void set_normal(PlainOldData& pod);
       static void set_strong(PlainOldData& pod); //TODO
      };

  //// Public methods.

    /* Return a raw pointer to a PlainOldData object. */
    PlainOldData*   getPod();
    /* Encrypt the input file into a new 4crypt-encrypted output file, delegating
     * the file operations themselves to libTSC's filecrypt module.
     * If an error occurs, return the SSC_CodeError_t and specify the
     * ErrType as well as the InOutDir (whether the error concerns
     * the input or the output file).
     */
    SSC_CodeError_t encrypt(ErrType* err_type, InOutDir* err_dir);
    /* Decrypt the 4crypt-encrypted input file into a new output file, delegating
     * the file operations themselves to libTSC's filecrypt module. libTSC
     * verifies the file's Message Authentication Code before releasing any
     * plaintext.
     * If an error occurs, return the SSC_CodeError_t and specify the
     * ErrType as well as the InOutDir (whether the error concerns
     * the input or the output file).
     */
    SSC_CodeError_t decrypt(ErrType* err_type, InOutDir* err_dir);
    /* Describe the metadata of a 4crypt-encrypted file.
     * If an error occurs, return the SSC_CodeError_t and specify the
     * ErrType as well as the InOutDir (whether the error concerns
     * the input or the output file).
     */
    SSC_CodeError_t describe(ErrType* err_type, InOutDir* err_dir);
  //// Constructors / Destructors

    Core();
    ~Core();
   private:
  //// Data

    PlainOldData*      pod;
  //// Static Data

    static std::string password_prompt;
    static std::string reentry_prompt;
    static std::string entropy_prompt;
    static std::string key_prompt;
    static std::string key_reentry_prompt;
  //// Static procedures.

    /* Return a std::string representation of the bitshift interpreted as a number of bytes. */
    static std::string makeMemoryStringBitShift(const uint8_t mem_bitshift);
    /* Return a std::string representation of the uint64_t interpreted as a number of bytes. */
    static std::string makeMemoryString(const uint64_t value);
  //// Private methods.

    /* Prompt the user for a password to be entered at a command-line terminal.
     * If @enter_twice is true the user will be prompted a second time to confirm that
     * they entered the password correctly.
     * If @entropy is true the password will be written to a unique entropy buffer, that
     * will later get passed to libTSC to harden its CSPRNG.
     */
    void            getPassword(bool enter_twice, bool entropy);
    /* Prompt the user for a raw symmetric key to be entered at a command-line terminal
     * as KEY_HEX_CHARS hexadecimal characters.
     * If @enter_twice is true the user will be prompted a second time to confirm that
     * they entered the key correctly.
     * On failure to decode the hexadecimal characters, return ERROR_KEY_MALFORMED.
     */
    SSC_CodeError_t getKey(bool enter_twice);
    /* Translate the user's requested padding (interpreted according to the
     * PlainOldData's padding_mode) into the number of padding bytes libTSC
     * should append to the input file's payload. libTSC rounds the payload up
     * to the next multiple of PAD_FACTOR, and never produces a file smaller
     * than the minimum 4crypt file size, so only the TARGET and AS_IF padding
     * modes necessitate translation here. Return ERROR_NONE on success, and
     * ERROR_INVALID_PADDING if the request is impossible.
     */
    SSC_CodeError_t resolvePadding(const uint64_t input_filesize);
    /* Map the TSC_Filecrypt error descriptors onto 4crypt's descriptors. */
    static void     mapErrorDescriptors(
                     const TSC_Filecrypt_ErrType  lib_err_type,
                     const TSC_Filecrypt_InOutDir lib_err_dir,
                     ErrType* R_         err_type,
                     InOutDir* R_        err_dir);
   };
 } // ! namespace fourcrypt
#undef R_
#endif
