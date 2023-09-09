#ifndef FOURCRYPT_HH
#define FOURCRYPT_HH

#include <string>

#include <SSC/Typedef.h>
#include <SSC/Memory.h>
#include <SSC/MemMap.h>
#include <PPQ/CSPRNG.h>


class FourCrypt
{
  public:
    // Public constants and types.
    static constexpr size_t MAX_PW_BYTES = 125;
    static constexpr size_t PW_BUFFER_BYTES = MAX_PW_BYTES + 1;
    static constexpr const std::string MAX_PW_BYTES_STR{"125"};

    static constexpr SSC_BitFlag8_t ENABLE_PHI =         0b00000001; // Enable the Phi function.
    static constexpr SSC_BitFlag8_t SUPPLEMENT_ENTROPY = 0b00000010; // Supplement entropy from stdin.

    static constexpr SSC_CodeError_t ERROR_NO_INPUT_FILENAME    = -1;
    static constexpr SSC_CodeError_t ERROR_NO_OUTPUT_FILENAME   = -2;
    static constexpr SSC_CodeError_t ERROR_INPUT_MEMMAP_FAILED  = -3;
    static constexpr SSC_CodeError_t ERROR_OUTPUT_MEMMAP_FAILED = -4;

    static constexpr uint8_t MEM_DEFAULT = 25;

    enum class ExeMode
    {
      NONE, ENCRYPT, DECRYPT, DESCRIBE
    };
    enum class PadMode
    {
      NONE, ADD, TARGET, AS_IF
    };
    struct PlainOldData
    {
      PPQ_Threefish512CounterMode tf_ctr;
      PPQ_CSPRNG                  rng;
      uint64_t                    tf_key   [PPQ_THREEFISH512_EXTERNAL_KEY_WORDS];
      uint64_t                    tf_tweak [PPQ_THREEFISH512_EXTERNAL_TWEAK_WORDS];
      SSC_MemMap                  input_map;
      SSC_MemMap                  output_map;
      uint8_t                     password_buffer [PW_BUFFER_BYTES];
      uint8_t                     verify_buffer   [PW_BUFFER_BYTES];
      char*                       input_filename;
      char*                       output_filename;
      uint64_t                    tf_ctr_idx;
      uint64_t                    input_filename_size;
      uint64_t                    output_filename_size;
      uint64_t                    password_size;
      uint64_t                    padding_size;
      uint64_t                    thread_count;
      ExeMode                     execute_mode;
      PadMode                     padding_mode;
      uint8_t                     memory_low;
      uint8_t                     memory_high;
      uint8_t                     iterations;
      SSC_BitFlag8_t              flags;
      static void init(PlainOldData* pod)
      {
        pod->tf_ctr = PPQ_THREEFISH512COUNTERMODE_NULL_LITERAL;
        pod->rng = PPQ_CSPRNG_NULL_LITERAL;
        memset(pod->tf_key, 0, sizeof(pod->tf_key));
        memset(pod->tf_tweak, 0, sizeof(pod->tf_tweak));
        pod->input_map = SSC_MEMMAP_NULL_LITERAL;
        pod->output_map = SSC_MEMMAP_NULL_LITERAL;
        memset(pod->password_buffer, 0, sizeof(pod->password_buffer));
        memset(pod->verify_buffer, 0, sizeof(pod->verify_buffer));
        pod->input_filename = nullptr;
        pod->output_filename = nullptr;
        pod->tf_ctr_idx = 0;
        pod->input_filename_size = 0;
        pod->output_filename_size = 0;
        pod->password_size = 0;
        pod->padding_size = 0;
        pod->thread_count = 1;
        pod->execute_mode = ExeMode::NONE;
        pod->padding_mode = PadMode::NONE;
        pod->memory_low = MEM_DEFAULT;
        pod->memory_high = MEM_DEFAULT;
        pod->iterations = 1;
        pod->flags = 0;
      }
      static void del(PlainOldData* pod)
      {
        delete pod->input_filename;
        delete pod->output_filename;
        SSC_secureZero(pod, sizeof(*pod));
      }
    };
    // Public Static Data
    static bool memlock_initialized;
    // Public accessors.
    PlainOldData* getPod();
    // Public methods.
    SSC_CodeError_t encrypt();//TODO
    SSC_CodeError_t decrypt();//TODO
    SSC_CodeError_t describe();//TODO
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
    void            getPassword(bool enter_twice);//TODO
    void            getEntropy();//TODO
    SSC_CodeError_t mapFiles();//TODO
    SSC_CodeError_t unmapFiles();//TODO
    uint8_t*        writeHeader(uint8_t* to);//TODO
    const uint8_t*  readHeader(const uint8_t* from);//TODO
    uint8_t*        writeCiphertext(uint8_t* to, const uint8_t* from, const size_t num);//TODO
};

#endif
