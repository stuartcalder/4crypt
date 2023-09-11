#include "FourCrypt.hh"
#define SSC_EXTERN_MEMLOCK // Enable memory locking.
#include <SSC/MemLock.h>
#include <SSC/Terminal.h>
#include <PPQ/Skein512.h>

static_assert(FourCrypt::MAX_PW_BYTES == 125, "MAX_PW_BYTES changed!");
#define MAX_PW_BYTES_STR "125"

#if defined(SSC_OS_UNIXLIKE)
 #define NEWLINE_ "\n"
#elif defined(SSC_OS_WINDOWS)
 #define NEWLINE_ "\n\r"
#else
 #error "Invalid OS!"
#endif

using PlainOldData = FourCrypt::PlainOldData;
enum {
  INPUT = 1,
  OUTPUT = 2
};

// FourCrypt static variable initialization.
bool FourCrypt::memlock_initialized{false};
std::string FourCrypt::password_prompt{
 "Please input a password (max length " MAX_PW_BYTES_STR " characters)." NEWLINE_
};
std::string FourCrypt::reentry_prompt{
  "Please input the same password again." NEWLINE_
};
std::string FourCrypt::entropy_prompt{
  "Please input up to " MAX_PW_BYTES_STR " random characters)." NEWLINE_
};

FourCrypt::FourCrypt()
{
  #if defined(SSC_MEMLOCK_H)
  if (!FourCrypt::memlock_initialized) {
    SSC_MemLock_Global_initHandled();
    FourCrypt::memlock_initialized = true;
  }
  #endif
  this->pod = new PlainOldData;
  PlainOldData::init(*this->getPod());
  PPQ_CSPRNG_init(&this->getPod()->rng);
}

FourCrypt::~FourCrypt()
{
  PlainOldData::del(*this->getPod());
  delete this->getPod();
}

void FourCrypt::PlainOldData::init(PlainOldData& pod)
{
  pod.tf_ctr = PPQ_THREEFISH512COUNTERMODE_NULL_LITERAL;
  pod.rng    = PPQ_CSPRNG_NULL_LITERAL;
  memset(pod.tf_key         , 0, sizeof(pod.tf_key));
  memset(pod.tf_tweak       , 0, sizeof(pod.tf_tweak));
  memset(pod.password_buffer, 0, sizeof(pod.password_buffer));
  memset(pod.verify_buffer  , 0, sizeof(pod.verify_buffer));
  memset(pod.entropy_buffer , 0, sizeof(pod.entropy_buffer));
  memset(pod.hash_buffer    , 0, sizeof(pod.hash_buffer));
  pod.input_map  = SSC_MEMMAP_NULL_LITERAL;
  pod.output_map = SSC_MEMMAP_NULL_LITERAL;
  pod.input_filename  = nullptr;
  pod.output_filename = nullptr;
  pod.ubi512 = &pod.rng.ubi512;
  pod.tf_ctr_idx = 0;
  pod.input_filename_size  = 0;
  pod.output_filename_size = 0;
  pod.password_size = 0;
  pod.entropy_size  = 0;
  pod.padding_size  = 0;
  pod.thread_count  = 1;
  pod.execute_mode = ExeMode::NONE;
  pod.padding_mode = PadMode::NONE;
  pod.memory_low  = MEM_DEFAULT;
  pod.memory_high = MEM_DEFAULT;
  pod.iterations = 1;
  pod.flags      = 0;
}

void FourCrypt::PlainOldData::del(PlainOldData& pod)
{
  delete pod.input_filename;
  delete pod.output_filename;
  SSC_secureZero(&pod, sizeof(pod));
}

PlainOldData* FourCrypt::getPod()
{
  return this->pod;
}

SSC_CodeError_t FourCrypt::encrypt()
{
  PlainOldData* mypod = this->getPod();
  // We require input and output filenames defined for ENCRYPT mode.
  if (mypod->input_filename == nullptr)
    return ERROR_NO_INPUT_FILENAME;
  if (mypod->output_filename == nullptr)
    return ERROR_NO_OUTPUT_FILENAME;
  int err_idx = 0;
  //TODO: Setup the output map's size to create and map a file of the right size.
  // Map the input and output files.
  SSC_CodeError_t err = this->mapFiles(&err_idx);
  const char* err_str;
  const char* err_map;
  const char* err_path;
  if (err) {
    switch (err) {
      case SSC_MEMMAP_INIT_CODE_ERR_FEXIST_NO:
        err_str = "Attempted to map %s filepath at %s, but it did not exist!\n";
        break;
      case SSC_MEMMAP_INIT_CODE_ERR_FEXIST_YES:
        err_str = "Attempted to create and map %s filepath at %s, but it already existed!\n";
        break;
      case SSC_MEMMAP_INIT_CODE_ERR_READONLY:
        err_str = "Attempted to map %s filepath at %s, but failed due to readonly!\n";
        break;
      case SSC_MEMMAP_INIT_CODE_ERR_SHRINK:
        err_str = "Attemped to map %s filepath at %s, but failed because shrinking is disallowed!\n";
        break;
      case SSC_MEMMAP_INIT_CODE_ERR_NOSIZE:
        err_str = "Attempted to map %s filepath at %s, but failed because no size was provided!\n";
        break;
      case SSC_MEMMAP_INIT_CODE_ERR_OPEN_FILEPATH:
        err_str = "Attempted to map %s filepath at %s, but failed to open the filepath!\n";
        break;
      case SSC_MEMMAP_INIT_CODE_ERR_CREATE_FILEPATH:
        err_str = "Attempted to create and map %s filepath at %s, but failed to create the filepath!\n";
        break;
      case SSC_MEMMAP_INIT_CODE_ERR_GET_FILE_SIZE:
        err_str = "Attempted to map %s filepath at %s, but failed to obtain the file size!\n";
        break;
      case SSC_MEMMAP_INIT_CODE_ERR_SET_FILE_SIZE:
        err_str = "Attempted to map %s filepath at %s, but failed to set the file size!\n";
        break;
      case SSC_MEMMAP_INIT_CODE_ERR_MAP:
        err_str = "Attempted to map %s filepath at %s, but failed the memory-map operation!\n";
        break;
      default:
        err_str = "Invalid memory-map error code while trying to map %s map at filepath %s!\n";
    }
    switch(err_idx) {
      case INPUT:
        err_map = "input";
        err_path = mypod->input_filename;
        break;
      case OUTPUT:
        err_map = "output";
        err_path = mypod->output_filename;
      default:
        SSC_errx("Invalid err_idx %d!\n", err_idx);
    }
    if (err_idx == OUTPUT && SSC_FilePath_exists(err_path))
      remove(err_path);
    SSC_errx(err_str, err_map, err_path);
  }
  // Get the encryption password.
  this->getPassword(true, false);
  if (mypod->flags & FourCrypt::SUPPLEMENT_ENTROPY)
    // Get the entropy password and hash it into the RNG.
    this->getPassword(false, true);
  uint8_t* in   = mypod->input_map.ptr;
  uint8_t* out  = mypod->output_map.ptr;
  size_t   n_in = mypod->input_map.size;
  out = this->writeHeader(out); // Write the header of the ciphertext file. TODO
  out = this->writeCiphertext(out, in, n_in); // Encrypt the input stream into the ciphertext file. TODO
  //TODO
  return 0;
}

SSC_CodeError_t FourCrypt::decrypt()
{
  //TODO
  return 0;
}

SSC_CodeError_t FourCrypt::describe()
{
  //TODO
  return 0;
}

uint64_t FourCrypt::getOutputSize()
{
  //TODO
  return 0;
}

constexpr uint64_t FourCrypt::getRealPaddingSize(uint64_t req_pad_bytes, uint64_t unpadded_size)
{
  //TODO
  return 0;
}

consteval uint64_t FourCrypt::getHeaderSize()
{
  uint64_t size = 0;
  size +=  4; // 4crypt magic bytes.
  size +=  4; // Mem Low, High, Iter count, Phi usage.
  size +=  8; // Size of the file, little-endian encoded.
  size += 16; // Threefish512 Tweak.
  size += 32; // CATENA salt.
  size += 32; // Threefish512 CTR IV.
  size +=  8; // Thread count, little-endian encoded.
  size +=  8; // Reserved.
  size +=  8; // Ciphered padding size, little-endian encoded.
  size +=  8; // Ciphered reserved.
  return size;
}

consteval uint64_t FourCrypt::getMinimumOutputSize()
{
  return FourCrypt::getHeaderSize() + FourCrypt::getMACSize() + 64;
}

consteval uint64_t FourCrypt::getMACSize()
{
  return PPQ_THREEFISH512_BLOCK_BYTES;
}

SSC_CodeError_t FourCrypt::mapFiles(int* map_err_idx, size_t input_size, size_t output_size)
{
  PlainOldData&   mypod = *this->getPod();
  SSC_CodeError_t err = 0;
  // Input and output filenames have been checked for NULL. Map these filepaths.
  err = SSC_MemMap_init(
   &mypod.input_map,
   mypod.input_filename,
   input_size,
   SSC_MEMMAP_INIT_READONLY |
   SSC_MEMMAP_INIT_FORCE_EXIST |
   SSC_MEMMAP_INIT_FORCE_EXIST_YES);
  if (err) {
    if (map_err_idx)
      *map_err_idx = INPUT;
    return err;
  }
  err = SSC_MemMap_init(
   &mypod.output_map,
   mypod.output_filename,
   output_size,
   SSC_MEMMAP_INIT_FORCE_EXIST);
  if (err) {
    if (map_err_idx)
      *map_err_idx = OUTPUT;
    return err;
  }
  return 0;
}

void FourCrypt::getPassword(bool enter_twice, bool entropy)
{
  PlainOldData* mypod = this->getPod();
  SSC_Terminal_init();
  if (enter_twice && !entropy) {
    mypod->password_size = static_cast<uint64_t>(SSC_Terminal_getPasswordChecked(
     mypod->password_buffer,
     mypod->verify_buffer,
     FourCrypt::password_prompt.c_str(),
     FourCrypt::reentry_prompt.c_str(),
     1,
     MAX_PW_BYTES,
     PW_BUFFER_BYTES));
    SSC_secureZero(mypod->verify_buffer, sizeof(mypod->verify_buffer));
    SSC_Terminal_end();
  }
  else {
    uint8_t*     p;
    std::string* str;
    uint64_t*    sz;
    if (entropy) {
      p   = mypod->entropy_buffer;
      str = &FourCrypt::entropy_prompt;
      sz  = &mypod->entropy_size;
    }
    else {
      p   = mypod->password_buffer;
      str = &FourCrypt::password_prompt;
      sz  = &mypod->password_size;
    }
    *sz = static_cast<uint64_t>(SSC_Terminal_getPassword(
     p,
     str->c_str(),
     1,
     MAX_PW_BYTES,
     PW_BUFFER_BYTES));
    SSC_Terminal_end();
    if (entropy) {
      PPQ_Skein512_hashNative(
       mypod->ubi512,
       mypod->hash_buffer,
       mypod->entropy_buffer,
       mypod->entropy_size);
      SSC_secureZero(mypod->entropy_buffer, sizeof(mypod->entropy_buffer));
      mypod->entropy_size = 0;
      PPQ_CSPRNG_reseed(&mypod->rng, mypod->hash_buffer);
      SSC_secureZero(mypod->hash_buffer, sizeof(mypod->hash_buffer));
    }
  }
}

uint8_t* FourCrypt::writeHeader(uint8_t* to)
{
  //TODO
  return nullptr;
}

uint8_t* FourCrypt::writePadding(uint8_t* to)
{
  //TODO
  return nullptr;
}

uint8_t* FourCrypt::writeCiphertext(uint8_t* to, const uint8_t* from, const size_t num)
{
  //TODO
  return nullptr;
}

void FourCrypt::writeMAC(uint8_t* to, const uint8_t* from, const size_t num)
{
  //TODO
}
