#ifndef FOURCRYPT_HH
#define FOURCRYPT_HH

#include <string>

#include <SSC/Typedef.h>
#include <SSC/Memory.h>
#include <SSC/MemMap.h>
#include <PPQ/CSPRNG.h>
#include <PPQ/Catena512.h>
#include <PPQ/Threefish512.h>

#if !defined(SSC_LANG_CPP)
 #error "We need C++!"
#elif SSC_LANG_CPP < SSC_CPP_20
 #error "We need at least C++20!"
#endif

#define R_ SSC_RESTRICT

class FourCrypt
{
  public:
    // Public constants and types.
    static constexpr const size_t MAX_PW_BYTES = 125;
    static constexpr const size_t PW_BUFFER_BYTES = MAX_PW_BYTES + 1;
    static_assert(SSC_ENDIAN == SSC_ENDIAN_LITTLE || SSC_ENDIAN == SSC_ENDIAN_BIG, "Only big and little endian supported!");
    static constexpr const bool is_little_endian = []() -> bool { return (SSC_ENDIAN == SSC_ENDIAN_LITTLE); }();
    static constexpr const uint8_t magic[4] = { 0xe2, 0x2a, 0x1e, 0x9b };

    static constexpr const SSC_BitFlag8_t ENABLE_PHI =         0b00000001; // Enable the Phi function.
    static constexpr const SSC_BitFlag8_t SUPPLEMENT_ENTROPY = 0b00000010; // Supplement entropy from stdin.
    static constexpr const SSC_BitFlag8_t ENTER_PASS_ONCE    = 0b00000100; // Don't re-enter password during encrypt.

    // 4crypt Code Errors.
    static constexpr const SSC_CodeError_t ERROR_NO_INPUT_FILENAME          =  -1;
    static constexpr const SSC_CodeError_t ERROR_NO_OUTPUT_FILENAME         =  -2;
    static constexpr const SSC_CodeError_t ERROR_INPUT_MEMMAP_FAILED        =  -3;
    static constexpr const SSC_CodeError_t ERROR_OUTPUT_MEMMAP_FAILED       =  -4;
    static constexpr const SSC_CodeError_t ERROR_GETTING_INPUT_FILESIZE     =  -5;
    static constexpr const SSC_CodeError_t ERROR_INPUT_FILESIZE_TOO_SMALL   =  -6;
    static constexpr const SSC_CodeError_t ERROR_INVALID_4CRYPT_FILE        =  -7;
    static constexpr const SSC_CodeError_t ERROR_INPUT_SIZE_MISMATCH        =  -8;
    static constexpr const SSC_CodeError_t ERROR_RESERVED_BYTES_USED        =  -9;
    static constexpr const SSC_CodeError_t ERROR_OUTPUT_FILE_EXISTS         = -10;
    static constexpr const SSC_CodeError_t ERROR_MAC_VALIDATION_FAILED      = -11;
    static constexpr const SSC_CodeError_t ERROR_KDF_FAILED                 = -12;
    static constexpr const SSC_CodeError_t ERROR_METADATA_VALIDATION_FAILED = -13;

    static constexpr const uint8_t  MEM_DEFAULT = 24;
    static constexpr const uint64_t PAD_FACTOR = 64;
    static constexpr const uint64_t MAC_SIZE = 64;

    enum class ExeMode
    {
      NONE, ENCRYPT, DECRYPT, DESCRIBE
    };
    enum class PadMode
    {
      ADD, TARGET, AS_IF
    };
    enum class InOutDir
    {
      NONE   = 0,
      INPUT  = 1,
      OUTPUT = 2
    };
    enum class ErrType
    {
      FOURCRYPT, MEMMAP
    };
    struct PlainOldData
    {
      PPQ_Threefish512CounterMode tf_ctr; // Threefish512 Cipher in Counter Mode.
      PPQ_CSPRNG                  rng;    // Skein512-based Pseudorandom Number Generator.
      alignas(uint64_t) uint8_t   hash_buffer     [PPQ_THREEFISH512_BLOCK_BYTES * 2]; // Enough room for 2 64 byte hashes in 1 buffer.
      uint64_t                    tf_sec_key      [PPQ_THREEFISH512_EXTERNAL_KEY_WORDS]; // Secret encryption key.
      uint64_t                    tf_tweak        [PPQ_THREEFISH512_EXTERNAL_TWEAK_WORDS]; // Public Threefish512 Tweak.
      alignas(uint64_t) uint8_t   mac_key         [PPQ_THREEFISH512_BLOCK_BYTES]; // Secret authentication key.
      alignas(uint64_t) uint8_t   catena_salt     [PPQ_CATENA512_SALT_BYTES]; // Public Catena512 salt.
      alignas(uint64_t) uint8_t   tf_ctr_iv       [PPQ_THREEFISH512COUNTERMODE_IV_BYTES]; // Public Initialization Vector for Threefish512 in Counter Mode.
      uint8_t                     password_buffer [PW_BUFFER_BYTES]; // Store the password here when encrypting/decrypting.
      uint8_t                     verify_buffer   [PW_BUFFER_BYTES]; // Verify @password_buffer here when encrypting.
      uint8_t                     entropy_buffer  [PW_BUFFER_BYTES]; // Store entropy characters here before hashing them into the @rng.
      SSC_MemMap                  input_map;  // Memory-map the input file.
      SSC_MemMap                  output_map; // Memory-map the output file.
      char*                       input_filename;  // Where is the input file?
      char*                       output_filename; // Where is the output file?
      PPQ_UBI512*                 ubi512; // Point to the PPQ_UBI512 struct internal to @rng.
      uint64_t                    tf_ctr_idx; // The current keystream byte index for Threefish512 in Counter Mode.
      uint64_t                    input_filename_size; // How many bytes is the input file name?
      uint64_t                    output_filename_size; // How many bytes is the output file name?
      uint64_t                    password_size; // How many bytes is the password?
      uint64_t                    entropy_size;  // How many entropy bytes were provided?
      uint64_t                    padding_size;  // How many bytes of padding?
      uint64_t                    thread_count;  // How many KDF threads?
      ExeMode                     execute_mode;  // What shall we do? Encrypt? Decrypt? Describe?
      PadMode                     padding_mode;  // What context were the padding bytes specified for?
      uint8_t                     memory_low;    // What is the lower memory bound of the KDF?
      uint8_t                     memory_high;   // What is the upper memory bound of the KDF?
      uint8_t                     iterations;    // How many times will each thread of the KDF iterate?
      SSC_BitFlag8_t              flags;         // Bit Flag parameters, such as whether to enable entropy supplementation.

      static void init(PlainOldData& pod);
      static void del(PlainOldData& pod);
    };
    // Public Static Data
    static bool memlock_initialized;
    // Public methods.
    PlainOldData*   getPod();
    SSC_CodeError_t encrypt(ErrType* err_type, InOutDir* err_dir);
    SSC_CodeError_t decrypt(ErrType* err_type, InOutDir* err_dir);
    SSC_CodeError_t describe(ErrType* err_type, InOutDir* err_dir);
    static consteval uint64_t getHeaderSize();
    static consteval uint64_t getMetadataSize();
    static consteval uint64_t getMinimumOutputSize();
    // Constructors / Destructors
    FourCrypt();
    ~FourCrypt();
  private:
    // Data
    PlainOldData*      pod;
    // Static Data
    static std::string password_prompt;
    static std::string reentry_prompt;
    static std::string entropy_prompt;
    // Static procedures.
    static bool        verifyBasicMetadata(PlainOldData* extpod, InOutDir dir);
    static std::string makeMemoryStringBitShift(const uint8_t mem_bitshift);
    static std::string makeMemoryString(const uint64_t value);
    // Private methods.
    void            getPassword(bool enter_twice, bool entropy);
    SSC_Error_t     normalizePadding(const uint64_t input_filesize);
    void            genRandomElements();
    SSC_Error_t     runKDF();
    SSC_Error_t     verifyMAC(const uint8_t* R_ mac, const uint8_t* R_ begin, const uint64_t size);
    SSC_CodeError_t mapFiles(InOutDir* map_err_idx, size_t input_size = 0, size_t output_size = 0, InOutDir only_map = InOutDir::NONE);
    SSC_Error_t     syncMaps();
    void            unmapFiles();
    uint8_t*        writeHeader(uint8_t* to);
    const uint8_t*  readHeaderPlaintext(const uint8_t* R_ from, SSC_CodeError_t* R_ err);
    const uint8_t*  readHeaderCiphertext(const uint8_t* R_ from, SSC_CodeError_t* R_ err);
    uint8_t*        writeCiphertext(uint8_t* R_ to, const uint8_t* R_ from, const size_t num);
    void            writePlaintext(uint8_t* R_ to, const uint8_t* R_ from, const size_t num);
    void            writeMAC(uint8_t* R_ to, const uint8_t* R_ from, const size_t num);
};

#undef R_

#endif
