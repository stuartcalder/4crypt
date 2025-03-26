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
#include <SSC/MemMap.h>
// TSC
#include <TSC/CSPRNG.h>
#include <TSC/Catena512.h>
#include <TSC/Threefish512.h>

#if !defined(SSC_LANG_CPP)
 #error "We need C++!"
#elif SSC_LANG_CPP < SSC_CPP_20
 #error "We need at least C++20!"
#endif

#define R_ SSC_RESTRICT

namespace fourcrypt
 {
  class Core
   {
   public:
  //// Public constants and types.

    static constexpr size_t MAX_PW_BYTES {125};
    static constexpr size_t PW_BUFFER_BYTES {MAX_PW_BYTES + 1};
    static_assert(SSC_ENDIAN == SSC_ENDIAN_LITTLE || SSC_ENDIAN == SSC_ENDIAN_BIG, "Only big and little endian supported!");
    static constexpr bool is_little_endian = []() -> bool { return (SSC_ENDIAN == SSC_ENDIAN_LITTLE); }();
    static constexpr uint8_t magic[4]     { 0xe2, 0x2a, 0x1e, 0x9b };
    static constexpr char    extension[4] { '.', '4', 'c', '\0' };
    static constexpr size_t  extension_length {3}; // Only consider '.', '4', and 'c'.
  
    static constexpr SSC_BitFlag8_t ENABLE_PHI         {0b00000001}; // Enable the Phi function.
    static constexpr SSC_BitFlag8_t SUPPLEMENT_ENTROPY {0b00000010}; // Supplement entropy from stdin.
    static constexpr SSC_BitFlag8_t ENTER_PASS_ONCE    {0b00000100}; // Don't re-enter password during encrypt.
    static constexpr uint8_t MEM_FAST    {21}; // 128 Mebibytes.
    static constexpr uint8_t MEM_NORMAL  {24}; // 1   Gibibyte.
    static constexpr uint8_t MEM_STRONG  {25}; // 2   Gibibytes.
    static constexpr uint8_t MEM_DEFAULT {MEM_NORMAL};
    static constexpr uint64_t memoryFromBitShift(uint8_t bitshift)
     {
      return static_cast<uint64_t>(1) << (bitshift + 6);
     }
  
    static constexpr uint64_t PAD_FACTOR {64}; // Files will always be a multiple of 64 bytes.
    static constexpr uint64_t MAC_SIZE   {64}; // The Message Authentication Code is 64 bytes.
  
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
      NONE   = 0,
      INPUT  = 1,
      OUTPUT = 2
     };
    // Distinguish errors that happen inside Core logic from errors that happen inside SSC_MemMap procedure calls.
    enum class ErrType
     {
      CORE, MEMMAP
     };
  //// 4crypt Code Errors.

    static constexpr SSC_CodeError_t ERROR_NONE                       {  0};
    static constexpr SSC_CodeError_t ERROR_NO_INPUT_FILENAME          { -1};
    static constexpr SSC_CodeError_t ERROR_NO_OUTPUT_FILENAME         { -2};
    static constexpr SSC_CodeError_t ERROR_INPUT_MEMMAP_FAILED        { -3};
    static constexpr SSC_CodeError_t ERROR_OUTPUT_MEMMAP_FAILED       { -4};
    static constexpr SSC_CodeError_t ERROR_GETTING_INPUT_FILESIZE     { -5};
    static constexpr SSC_CodeError_t ERROR_INPUT_FILESIZE_TOO_SMALL   { -6};
    static constexpr SSC_CodeError_t ERROR_INVALID_4CRYPT_FILE        { -7};
    static constexpr SSC_CodeError_t ERROR_INPUT_SIZE_MISMATCH        { -8};
    static constexpr SSC_CodeError_t ERROR_RESERVED_BYTES_USED        { -9};
    static constexpr SSC_CodeError_t ERROR_OUTPUT_FILE_EXISTS         {-10};
    static constexpr SSC_CodeError_t ERROR_MAC_VALIDATION_FAILED      {-11};
    static constexpr SSC_CodeError_t ERROR_KDF_FAILED                 {-12};
    static constexpr SSC_CodeError_t ERROR_METADATA_VALIDATION_FAILED {-13};
    struct PlainOldData
     {
      TSC_Threefish512Ctr         tf_ctr; // Threefish512 Cipher in Counter Mode.
      TSC_CSPRNG                  rng;    // Skein512-based Cryptographically Secure Pseudorandom Number Generator.
      alignas(uint64_t) uint8_t   hash_buffer     [TSC_THREEFISH512_BLOCK_BYTES * 2]; // Enough room for two distinct 64 byte hashes in 1 buffer.
      uint64_t                    tf_sec_key      [TSC_THREEFISH512_KEY_WORDS_WITH_PARITY];   // Secret encryption key.
      uint64_t                    tf_tweak        [TSC_THREEFISH512_TWEAK_WORDS_WITH_PARITY]; // Public Threefish512 Tweak.
      uint64_t                    mac_key         [TSC_THREEFISH512_BLOCK_WORDS]; // Secret authentication key.
      alignas(uint64_t) uint8_t   catena_salt     [TSC_CATENA512_SALT_BYTES]; // Public Catena512 salt.
      uint64_t                    tf_ctr_iv       [TSC_THREEFISH512CTR_IV_WORDS]; // Public Initialization Vector for Threefish512 in Counter Mode.
      uint8_t                     password_buffer [PW_BUFFER_BYTES]; // Store the password here when encrypting/decrypting.
      uint8_t                     verify_buffer   [PW_BUFFER_BYTES]; // Verify @password_buffer here when encrypting.
      uint8_t                     entropy_buffer  [PW_BUFFER_BYTES]; // Store entropy characters here before hashing them into the @rng.
      SSC_MemMap                  input_map;  // Memory-map the input file.
      SSC_MemMap                  output_map; // Memory-map the output file.
      char*                       input_filename;  // Where is the input file?
      char*                       output_filename; // Where is the output file?
      TSC_Skein512*               skein512;   // Point to the TSC_Skein512 internal to @rng.
      uint64_t                    tf_ctr_idx; // The current keystream byte index for Threefish512 in Counter Mode.
      uint64_t                    input_filename_size; // How many bytes is the input file name?
      uint64_t                    output_filename_size; // How many bytes is the output file name?
      uint64_t                    password_size; // How many bytes is the password?
      uint64_t                    entropy_size;  // How many entropy bytes were provided?
      uint64_t                    padding_size;  // How many bytes of padding?
      uint64_t                    thread_count;  // How many KDF threads?
      uint64_t                    thread_batch_size; // How many KDF threads per batch? i.e. How many threads execute concurrently?
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
    using StatusCallback_f  = void(void* data);
  
  //// Public methods.

    /* Return a raw pointer to a PlainOldData object. */
    PlainOldData*   getPod();
    /* Initiate counter mode encryption and subsequent MAC authentication.
     * If an error occurs, return the SSC_CodeError_t and specify the
     * ErrType as well as the InOutDir (whether the error occured specifically
     * with input or output).
     *
     * When @status_callback is non-nullptr it gets called at several arbitrary intervals to allow
     * external code to roughly track the status of execution.
     */
    SSC_CodeError_t encrypt(ErrType* err_type, InOutDir* err_dir , StatusCallback_f* status_callback= nullptr, void* scb_data = nullptr);
    /* Initiate MAC authentication and subsequent Counter Mode decryption.
     * If an error occurs, return the SSC_CodeError_t and specify the
     * ErrType as well as the InOutDir (whether the error occured specifically
     * with input or output).
     *
     * @status_callback gets called at several arbitrary intervals to allow
     * external code to roughly track the status of execution.
     */
    SSC_CodeError_t decrypt(ErrType* err_type, InOutDir* err_dir , StatusCallback_f* status_callback = nullptr, void* scb_data = nullptr);
    /* Describe the metadata of a 4crypt-encrypted file.
     * If an error occurs, return the SSC_CodeError_t and specify the
     * ErrType as well as the InOutDir (whether the error occured specifically
     * with input or output).
     *
     * When @status_callback is non-nullptr it gets called at several arbitrary intervals to allow
     * external code to roughly track the status of execution.
     */
    SSC_CodeError_t describe(ErrType* err_type, InOutDir* err_dir, StatusCallback_f* status_callback = nullptr, void* scb_data = nullptr);
    /* This function returns the size of a 4crypt-encrypted file header. */
    static consteval uint64_t getHeaderSize();
    /* 4crypt metadata consists of the header at the beginning of a file as well as the Message Authentication Code at the end. */
    static consteval uint64_t getMetadataSize();
    /* The minimum size of a 4crypt-encrypted file consists of the 4crypt metadata with a single block of PAD_FACTOR (64) bytes. */
    static consteval uint64_t getMinimumOutputSize();
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
  //// Static procedures.

    /* The kdf function shall be used to instance threads of CATENA512
     * key derivation functions, which are then XORd together to form a 512 bit secret.
     * The 512 bit secret is hashed to produce a 1024 bit secret; the first 512 bits of this
     * newly created 1024 bits is used as the secret key of Threefish512 in Counter Mode. The latter
     * 512 bits is used as the secret key of Threefish512-MAC for authentication.
     */
    static void kdf(uint8_t* R_ output, PlainOldData* R_ pod, TSC_Catena512* R_ catena, SSC_Error_t* R_ err, uint64_t thread_idx);
    /* Perform basic validity checks of the metadata of the (input or output)
     * file. Return true when the metadata is valid and false otherwise.
     */
    static bool        verifyBasicMetadata(PlainOldData* extpod, InOutDir dir);
    /* Return a std::string representation of the bitshift interpreted as a number of bytes. */
    static std::string makeMemoryStringBitShift(const uint8_t mem_bitshift);
    /* Return a std::string representation of the uint64_t interpreted as a number of bytes. */
    static std::string makeMemoryString(const uint64_t value);
    /* For systems that define SSC_HAS_GETAVAILABLESYSTEMMEMORY...
     *   Return a left bitwise shift that will not exceed the amount of currently available system memory.
     * For other systems...
     *   Return a left bitwise shift that will result in a "moderate" amount of memory usage.
     */
    static uint8_t     getDefaultMemoryUsageBitShift(void);
  //// Private methods.

    /* Prompt the user for a password to be entered at a command-line terminal. 
     * If @enter_twice is true the user will be prompted a second time to confirm that
     * they entered the password correctly.
     * If @entropy is true the password will be written to a unique entropy password buffer, that
     * will later get hashed into the Cryptographically Secure PseudoRandom Number Generator.
     */
    void            getPassword(bool enter_twice, bool entropy);
    /* Given an input file's @input_filesize, as well as the number
     * of padding bytes requested by the user (if any) determine how many padding
     * bytes to actually add such that the resultant file will be divisible
     * into even blocks of PAD_FACTOR bytes.
     */
    SSC_Error_t     normalizePadding(const uint64_t input_filesize);
    /* Generate all the pseudorandom data required for the
     * PlainOldData object pointed to inside of Core.
     */
    void            genRandomElements();
    /* Run the key derivation function utilizing as many threads
     * as were specified by the user. This necessitates a lot of dynamic
     * allocation.
     */
    SSC_Error_t     runKDF();
    /* Verify that the @size bytes starting at @begin produce the same Message Authentication
     * Code as that stored at @mac.
     */
    SSC_Error_t     verifyMAC(const uint8_t* R_ mac, const uint8_t* R_ begin, const uint64_t size);
    /* Memory-map the Input and/or Output files.
     * If there's an error return the code and write the direction (input or output) to @map_err_idx.
     */
    SSC_CodeError_t mapFiles(InOutDir* map_err_idx, size_t input_size = 0, size_t output_size = 0, InOutDir only_map = InOutDir::NONE);
    /* Check the input and output memory maps.
     * For each: if the pointer is valid synchronize the memory map.
     * Fail if either operation fails.
     */
    SSC_Error_t     syncMaps();
    /* De-initialize the input and output memory maps
     * (if those pointers are non-nullptr).
     */
    void            unmapFiles();
    /* Write a 4crypt header to the bytes starting at @to.
     * Return a pointer to the byte immediately following the written header.
     */
    uint8_t*        writeHeader(uint8_t* to);
    /* Read the plaintext portion of a 4crypt-encrypted file header's bytes @from, and store any resultant errors
     * at @err. On success return a pointer just past the header's plaintext. On failure return an invalid pointer.
     */
    const uint8_t*  readHeaderPlaintext(const uint8_t* R_ from, SSC_CodeError_t* R_ err);
    /* Read the ciphertext portion of a 4crypt-encrypted file header's bytes @from, and store any resultant errors
     * at @err. On success return a pointer just past the header's ciphertext. On failure return an invalid pointer.
     */
    const uint8_t*  readHeaderCiphertext(const uint8_t* R_ from, SSC_CodeError_t* R_ err);
    /* Encrypt the @num bytes of plaintext at @from and store the
     * ciphertext at @to. Return the address immediately following the last byte
     * of ciphertext written at @to.
     */
    uint8_t*        writeCiphertext(uint8_t* R_ to, const uint8_t* R_ from, const size_t num);
    /* Decrypt the @num bytes of ciphertext at @from and store the
     * plaintext at @to. Return the address immediately following the last byte
     * of plaintext written at @to.
     */
    void            writePlaintext(uint8_t* R_ to, const uint8_t* R_ from, const size_t num);
    /* Calculate the Skein512-MAC of the @num bytes beginning at @from, and store
     * the resulting MAC at @to.
     */
    void            writeMAC(uint8_t* R_ to, const uint8_t* R_ from, const size_t num);
   };
 } // ! namespace fourcrypt
#undef R_
#endif
