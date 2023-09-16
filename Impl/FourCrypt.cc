#include "FourCrypt.hh"
#define SSC_EXTERN_MEMLOCK // Enable memory locking.
#include <SSC/MemLock.h>
#include <SSC/Terminal.h>
#include <PPQ/Skein512.h>
#include <thread>
#include <vector>

#define R_ SSC_RESTRICT

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
  INPUT  = 1,
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

static void kdf(
 uint8_t*       R_ output,
 PlainOldData*  R_ pod,
 PPQ_Catena512* R_ catena,
 SSC_Error_t*   R_ err,
 uint64_t          thread_idx)
{
  uint8_t input    [sizeof(pod->catena_salt) + sizeof(thread_idx)];
  uint8_t new_salt [PPQ_THREEFISH512_BLOCK_BYTES];

  PPQ_Catena512_init(catena);
  memcpy(input, pod->catena_salt, sizeof(pod->catena_salt));
  {
    uint64_t ti;
    if constexpr(FourCrypt::is_little_endian)
      ti = thread_idx;
    else
      ti = SSC_swap64(thread_idx);
    memcpy(input + sizeof(pod->catena_salt), &ti, sizeof(ti));
  }

  // Hash the inputs into a unique salt.
  PPQ_Skein512_hashNative(
   &catena->ubi512,
   new_salt,
   input,
   sizeof(input));

  // Run the requested Catena KDF.
  if (pod->flags & FourCrypt::ENABLE_PHI)
    *err = PPQ_Catena512_usePhi(
     catena,
     output,
     pod->password_buffer,
     pod->password_size,
     pod->memory_low,
     pod->memory_high,
     pod->iterations);
  else
    *err = PPQ_Catena512_noPhi(
     catena,
     output,
     pod->password_buffer,
     pod->password_size,
     pod->memory_low,
     pod->memory_high,
     pod->iterations);
}

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

consteval uint64_t FourCrypt::getMetadataSize()
{
  return FourCrypt::getHeaderSize() + MAC_SIZE;
}

consteval uint64_t FourCrypt::getMinimumOutputSize()
{
  return FourCrypt::getMetadataSize() + PAD_FACTOR;
}
static_assert(FourCrypt::getMinimumOutputSize() % FourCrypt::PAD_FACTOR == 0);

void FourCrypt::PlainOldData::init(PlainOldData& pod)
{
  pod.tf_ctr    = PPQ_THREEFISH512COUNTERMODE_NULL_LITERAL;
  pod.rng       = PPQ_CSPRNG_NULL_LITERAL;
  memset(pod.hash_buffer    , 0, sizeof(pod.hash_buffer));
  memset(pod.tf_sec_key     , 0, sizeof(pod.tf_sec_key));
  memset(pod.tf_tweak       , 0, sizeof(pod.tf_tweak));
  memset(pod.mac_key        , 0, sizeof(pod.mac_key));
  memset(pod.catena_salt    , 0, sizeof(pod.catena_salt));
  memset(pod.tf_ctr_iv      , 0, sizeof(pod.tf_ctr_iv));
  memset(pod.password_buffer, 0, sizeof(pod.password_buffer));
  memset(pod.verify_buffer  , 0, sizeof(pod.verify_buffer));
  memset(pod.entropy_buffer , 0, sizeof(pod.entropy_buffer));
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
  pod.padding_mode = PadMode::ADD;
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
  // Get the size of the input file.
  size_t input_filesize;
  if (!SSC_FilePath_getSize(mypod->input_filename, &input_filesize))
    return ERROR_GETTING_INPUT_FILESIZE;
  // Normalize the padding.
  this->normalizePadding(input_filesize);
  int err_idx = 0;
  // Map the input and output files.
  SSC_CodeError_t err = this->mapFiles(
   &err_idx,
   0,
   input_filesize + mypod->padding_size + FourCrypt::getMetadataSize());
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
  this->genRandomElments();
  this->runKDF();//TODO
  uint8_t* in   = mypod->input_map.ptr;
  uint8_t* out  = mypod->output_map.ptr;
  size_t   n_in = mypod->input_map.size;
  out = this->writeHeader(out); // Write the header of the ciphertext file.
  out = this->writeCiphertext(out, in, n_in); // Encrypt the input stream into the ciphertext file.
  this->writeMAC(out, mypod->output_map.ptr, mypod->output_map.size - MAC_SIZE);
  return 0;
}


SSC_Error_t FourCrypt::normalizePadding(const uint64_t input_filesize)
{
  PlainOldData* mypod = this->getPod();
  const uint64_t size = input_filesize;
  uint64_t pad  = mypod->padding_size;
  switch (mypod->padding_mode) {
    // Add @pad to @size, then round up to be evenly divisible by PAD_FACTOR.
    case PadMode::ADD:
      if ((size + pad) % PAD_FACTOR)
        mypod->padding_size = pad + (PAD_FACTOR - ((size + pad) % PAD_FACTOR));
      break;
    // Goal: Output file is an exact, specific size specified in @pad.
    case PadMode::TARGET:
      if (pad < (size + FourCrypt::getMetadataSize()))
        return -1;
      mypod->padding_size = pad - (size + FourCrypt::getMetadataSize());
      mypod->padding_mode = PadMode::ADD;
      return this->normalizePadding(size);
    // Add padding as if @size were @pad.
    case PadMode::AS_IF:
      if (pad < size)
        return -1;
      mypod->padding_size = pad - size;
      mypod->padding_mode = PadMode::ADD;
      return this->normalizePadding(size);
    default:
      return -1;
  }
  return 0;
}

void FourCrypt::genRandomElments()
{
  PlainOldData* mypod = this->getPod();
  PPQ_CSPRNG*   myrng = &mypod->rng;

  // Threefish512 Tweak.
  PPQ_CSPRNG_get(
   myrng,
   mypod->tf_tweak,
   PPQ_THREEFISH512_TWEAK_BYTES);
  // Catena salt.
  PPQ_CSPRNG_get(
   myrng,
   mypod->catena_salt,
   sizeof(mypod->catena_salt));
  // Threefish512 CTR IV.
  PPQ_CSPRNG_get(
   myrng,
   mypod->tf_ctr_iv,
   sizeof(mypod->tf_ctr_iv));
  // Destroy the RNG after we're finished.
  SSC_secureZero(myrng, sizeof(*myrng));
}

SSC_Error_t FourCrypt::runKDF()
{
  PlainOldData*  mypod = this->getPod();
  const uint64_t num_threads = mypod->thread_count;
  const uint64_t output_bytes = num_threads * PPQ_THREEFISH512_BLOCK_BYTES;
  PPQ_Catena512* const catenas = new PPQ_Catena512[num_threads];
  SSC_Error_t* const   errors  = new SSC_Error_t[num_threads];
  uint8_t* const       outputs = new uint8_t[output_bytes];
  {
    std::vector<std::thread> threads;
    for (uint64_t i = 0; i < num_threads; ++i) {
      threads.emplace_back(
       kdf,
       outputs + (i * PPQ_THREEFISH512_BLOCK_BYTES),
       mypod,
       catenas + i,
       errors  + i,
       i);
    }
    for (uint64_t i = 0; i < num_threads; ++i)
      threads[i].join();
  }


  // TODO
  SSC_secureZero(catenas, sizeof(PPQ_Catena512) * num_threads);
  SSC_secureZero(outputs, output_bytes);
  delete[] catenas;
  delete[] outputs;
  delete[] errors;
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

SSC_CodeError_t FourCrypt::mapFiles(int* map_err_idx, size_t input_size, size_t output_size)
{
  constexpr const SSC_BitFlag_t input_flag = SSC_MEMMAP_INIT_READONLY |
   SSC_MEMMAP_INIT_FORCE_EXIST | SSC_MEMMAP_INIT_FORCE_EXIST_YES;
  constexpr const SSC_BitFlag_t output_flag = SSC_MEMMAP_INIT_FORCE_EXIST;
  PlainOldData&   mypod = *this->getPod();
  SSC_CodeError_t err = 0;
  // Input and output filenames have been checked for NULL. Map these filepaths.
  err = SSC_MemMap_init(
   &mypod.input_map,
   mypod.input_filename,
   input_size,
   input_flag);
  if (err) {
    if (map_err_idx)
      *map_err_idx = INPUT;
    return err;
  }
  err = SSC_MemMap_init(
   &mypod.output_map,
   mypod.output_filename,
   output_size,
   output_flag);
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
    uint8_t*    p;
    const char* str;
    uint64_t*   sz;
    if (entropy) {
      p   = mypod->entropy_buffer;
      str = FourCrypt::entropy_prompt.c_str();
      sz  = &mypod->entropy_size;
    }
    else {
      p   = mypod->password_buffer;
      str = FourCrypt::password_prompt.c_str();
      sz  = &mypod->password_size;
    }
    *sz = static_cast<uint64_t>(SSC_Terminal_getPassword(
     p,
     str,
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
  PlainOldData* mypod = this->getPod();
  // Magic bytes.
  memcpy(to, FourCrypt::magic, sizeof(FourCrypt::magic));
  to += sizeof(FourCrypt::magic);
  // Mem Low, High, Iteration Count, Phi usage.
  (*to++) = mypod->memory_low;
  (*to++) = mypod->memory_high;
  (*to++) = mypod->iterations;
  if (mypod->flags & ENABLE_PHI)
    (*to++) = 1;
  else
    (*to++) = 0;
  // Size of the file, little-endian encoded.
  {
    uint64_t size;
    if constexpr(FourCrypt::is_little_endian)
      size = mypod->output_map.size;
    else
      size = SSC_swap64(mypod->output_map.size);
    memcpy(to, &size, sizeof(size));
    to += sizeof(size);
  }
  // Threefish512 Tweak.
  memcpy(to, mypod->tf_tweak, PPQ_THREEFISH512_TWEAK_BYTES);
  to += PPQ_THREEFISH512_TWEAK_BYTES;
  // CATENA Salt.
  memcpy(to, mypod->catena_salt, sizeof(mypod->catena_salt));
  to += sizeof(mypod->catena_salt);
  // Threefish512 CTR IV.
  memcpy(to, mypod->tf_ctr_iv, sizeof(mypod->tf_ctr_iv));
  to += sizeof(mypod->tf_ctr_iv);
  // Thread count, little-endian encoded.
  {
    uint64_t tcount = mypod->thread_count;
    if constexpr(!FourCrypt::is_little_endian)
      tcount = SSC_swap64(tcount);
    memcpy(to, &tcount, sizeof(tcount));
    to += sizeof(tcount);
  }
  // 8 bytes reserved.
  memset(to, 0, 8);
  to += 8;
  // 8 Ciphered padding size bytes; 8 ciphered reserve bytes.
  {
    uint64_t tmp[2];
    if constexpr(FourCrypt::is_little_endian)
      tmp[0] = mypod->padding_size;
    else
      tmp[0] = SSC_swap64(mypod->padding_size);
    tmp[1] = 0;
    PPQ_Threefish512CounterMode_xorKeystream(
     &mypod->tf_ctr,
     to,
     tmp,
     sizeof(tmp),
     mypod->tf_ctr_idx);
    mypod->tf_ctr_idx += sizeof(tmp);
    to += sizeof(tmp);
  }
  return to;
}

uint8_t* FourCrypt::writeCiphertext(uint8_t* to, const uint8_t* from, const size_t num)
{
  PlainOldData* mypod = this->getPod();
  // Encipher padding bytes, if applicable.
  if (mypod->padding_size) {
    PPQ_Threefish512CounterMode_xorKeystream(
     &mypod->tf_ctr,
     to,
     to,
     mypod->padding_size,
     mypod->tf_ctr_idx);
    to                += mypod->padding_size;
    mypod->tf_ctr_idx += mypod->padding_size;
  }
  // Encipher the plaintext.
  PPQ_Threefish512CounterMode_xorKeystream(
   &mypod->tf_ctr,
   to,
   from,
   num,
   mypod->tf_ctr_idx);
  to += num;
  return to;
}

void FourCrypt::writeMAC(uint8_t* to, const uint8_t* from, const size_t num)
{
  PlainOldData* mypod = this->getPod();
  PPQ_Skein512_mac(
   mypod->ubi512,
   to,
   from,
   mypod->mac_key,
   num,
   PPQ_THREEFISH512_BLOCK_BYTES);
}
