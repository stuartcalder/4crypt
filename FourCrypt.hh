#ifndef FOURCRYPT_HH
#define FOURCRYPT_HH

#include <string>

#include <SSC/Typedef.h>
#include <SSC/Memory.h>
#include <SSC/MemMap.h>
#include <PPQ/CSPRNG.h>
#include <PPQ/Catena512.h>

#if !defined(SSC_LANG_CPP)
 #error "We need C++!"
#elif SSC_LANG_CPP < SSC_CPP_20
 #error "We need at least C++20!"
#endif

class FourCrypt
{
  public:
    // Public constants and types.
    static constexpr size_t MAX_PW_BYTES = 125;
    static constexpr size_t PW_BUFFER_BYTES = MAX_PW_BYTES + 1;
    static_assert(SSC_ENDIAN == SSC_ENDIAN_LITTLE || SSC_ENDIAN == SSC_ENDIAN_BIG, "Invalid endianness!");
    static constexpr const bool is_little_endian = []() -> bool { return (SSC_ENDIAN == SSC_ENDIAN_LITTLE); }();
    static constexpr const uint8_t magic[4] = { 0xe2, 0x2a, 0x1e, 0x9b };

    static constexpr const SSC_BitFlag8_t ENABLE_PHI =         0b00000001; // Enable the Phi function.
    static constexpr const SSC_BitFlag8_t SUPPLEMENT_ENTROPY = 0b00000010; // Supplement entropy from stdin.

    static constexpr const SSC_CodeError_t ERROR_NO_INPUT_FILENAME      = -1;
    static constexpr const SSC_CodeError_t ERROR_NO_OUTPUT_FILENAME     = -2;
    static constexpr const SSC_CodeError_t ERROR_INPUT_MEMMAP_FAILED    = -3;
    static constexpr const SSC_CodeError_t ERROR_OUTPUT_MEMMAP_FAILED   = -4;
    static constexpr const SSC_CodeError_t ERROR_GETTING_INPUT_FILESIZE = -5;

    static constexpr const uint8_t  MEM_DEFAULT = 25;
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
    struct PlainOldData
    {
      PPQ_Threefish512CounterMode tf_ctr;
      PPQ_CSPRNG                  rng;
      alignas(uint64_t) uint8_t   hash_buffer     [PPQ_THREEFISH512_BLOCK_BYTES];
      uint64_t                    tf_sec_key      [PPQ_THREEFISH512_EXTERNAL_KEY_WORDS];
      uint64_t                    tf_tweak        [PPQ_THREEFISH512_EXTERNAL_TWEAK_WORDS];
      alignas(uint64_t) uint8_t   mac_key         [PPQ_THREEFISH512_BLOCK_BYTES];
      alignas(uint64_t) uint8_t   catena_salt     [PPQ_CATENA512_SALT_BYTES];
      alignas(uint64_t) uint8_t   tf_ctr_iv       [PPQ_THREEFISH512COUNTERMODE_IV_BYTES];
      uint8_t                     password_buffer [PW_BUFFER_BYTES];
      uint8_t                     verify_buffer   [PW_BUFFER_BYTES];
      uint8_t                     entropy_buffer  [PW_BUFFER_BYTES];
      SSC_MemMap                  input_map;
      SSC_MemMap                  output_map;
      char*                       input_filename;
      char*                       output_filename;
      PPQ_UBI512*                 ubi512;
      uint64_t                    tf_ctr_idx;
      uint64_t                    input_filename_size;
      uint64_t                    output_filename_size;
      uint64_t                    password_size;
      uint64_t                    entropy_size;
      uint64_t                    padding_size;
      uint64_t                    thread_count;
      ExeMode                     execute_mode;
      PadMode                     padding_mode;
      uint8_t                     memory_low;
      uint8_t                     memory_high;
      uint8_t                     iterations;
      SSC_BitFlag8_t              flags;

      static void init(PlainOldData& pod);
      static void del(PlainOldData& pod);
    };
    // Public Static Data
    static bool memlock_initialized;
    // Public methods.
    PlainOldData*   getPod();
    SSC_CodeError_t encrypt();//TODO
    SSC_CodeError_t decrypt();//TODO
    SSC_CodeError_t describe();//TODO
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
    // Private methods.
    void            getPassword(bool enter_twice, bool entropy);//TODO
    SSC_Error_t     normalizePadding(const uint64_t input_filesize);//TODO
    void            genRandomElments();
    SSC_Error_t     runKDF();//TODO
    SSC_CodeError_t mapFiles(int* map_err_idx, size_t input_size = 0, size_t output_size = 0);
    SSC_CodeError_t unmapFiles();//TODO
    uint8_t*        writeHeader(uint8_t* to);
    const uint8_t*  readHeader(const uint8_t* from);//TODO
    uint8_t*        writeCiphertext(uint8_t* to, const uint8_t* from, const size_t num);//TODO
    void            writeMAC(uint8_t* to, const uint8_t* from, const size_t num);//TODO
};

#endif
