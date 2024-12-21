#include "Core.hh"
#include "Util.hh"
// SSC
#include <SSC/Terminal.h>
#include <SSC/Print.h>
// PPQ TODO: Remove me!
#include <PPQ/Skein512.h>
// TSC
#include <TSC/Skein512.h>
#include <TSC/Catena512.h>
// C++ STL
#include <limits>
#include <thread>
#include <memory>
// C++ C Lib
#include <cinttypes>
using namespace fourcrypt;

#define R_ SSC_RESTRICT

static_assert(Core::MAX_PW_BYTES == 125, "MAX_PW_BYTES changed!");
#define MAX_PW_BYTES_STR "125"

#if   defined(SSC_OS_UNIXLIKE)
 #define NEWLINE_ "\n"
#elif defined(SSC_OS_WINDOWS)
 #define NEWLINE_ "\n\r"
#else
 #error "Invalid OS!"
#endif

using PlainOldData = Core::PlainOldData;
enum {
  INPUT  = 1,
  OUTPUT = 2
};

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

static void kdf(
 uint8_t*       R_ output,
 PlainOldData*  R_ pod,
 TSC_Catena512* R_ catena,
 SSC_Error_t*   R_ err,
 uint64_t          thread_idx)
{
  uint8_t input    [sizeof(pod->catena_salt) + sizeof(thread_idx)];
  uint8_t new_salt [TSC_CATENA512_SALT_BYTES];

  TSC_Catena512_init(catena, pod->memory_low);
  memcpy(input, pod->catena_salt, sizeof(pod->catena_salt));
  {
    uint64_t ti;
    if constexpr(Core::is_little_endian)
      ti = thread_idx;
    else
      ti = SSC_swap64(thread_idx);
    memcpy(input + sizeof(pod->catena_salt), &ti, sizeof(ti));
  }

  // Hash the inputs into a unique salt.
  TSC_Skein512_hash(
    &catena->skein512,
    new_salt,
    sizeof(new_salt),
    input,
    sizeof(input));
  // Copy that new salt into Catena.
  static_assert(sizeof(catena->salt) == sizeof(new_salt));
  memcpy(catena->salt, new_salt, sizeof(new_salt));

  // Run the requested Catena KDF.
  *err = TSC_Catena512_get(
    catena,
    output,
    pod->password_buffer,
    pod->password_size,
    pod->memory_low,
    pod->iterations,
    pod->flags & Core::ENABLE_PHI);
}

Core::Core()
{
  this->pod = new PlainOldData;
  PlainOldData::init(*this->getPod());
  TSC_CSPRNG_init(&this->getPod()->rng);
}

Core::~Core()
{
  PlainOldData::del(*this->getPod());
  delete this->getPod();
}

consteval uint64_t Core::getHeaderSize()
{
  uint64_t size = 0;
  static_assert(sizeof(Core::magic) == 4);
  static_assert(TSC_THREEFISH512_TWEAK_BYTES == 16);
  static_assert(TSC_CATENA512_SALT_BYTES == 32);
  static_assert(TSC_THREEFISH512CTR_IV_BYTES == 32);
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

consteval uint64_t Core::getMetadataSize()
{
  static_assert(MAC_SIZE == 64);
  return Core::getHeaderSize() + MAC_SIZE;
}

consteval uint64_t Core::getMinimumOutputSize()
{
  return Core::getMetadataSize() + PAD_FACTOR;
}
static_assert(Core::getMinimumOutputSize() % Core::PAD_FACTOR == 0);

void Core::PlainOldData::init(PlainOldData& pod)
{
  pod.tf_ctr    = TSC_THREEFISH512CTR_NULL_LITERAL;
  pod.rng       = TSC_CSPRNG_NULL_LITERAL;
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
  pod.ubi512 = &pod.rng.skein512;
  pod.tf_ctr_idx = 0;
  pod.input_filename_size  = 0;
  pod.output_filename_size = 0;
  pod.password_size = 0;
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

void Core::PlainOldData::del(PlainOldData& pod)
{
  delete[] pod.input_filename;
  delete[] pod.output_filename;
  SSC_secureZero(&pod, sizeof(pod));
}

void Core::PlainOldData::touchup(PlainOldData& pod)
{
  if (pod.thread_batch_size == 0 || pod.thread_batch_size > pod.thread_count)
    pod.thread_batch_size = pod.thread_count;
}

void Core::PlainOldData::set_fast(PlainOldData& pod)
{
  pod.memory_low  = MEM_FAST;
  pod.memory_high = MEM_FAST;
}

void Core::PlainOldData::set_normal(PlainOldData& pod)
{
  pod.memory_low  = MEM_NORMAL;
  pod.memory_high = MEM_NORMAL;
}

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

PlainOldData* Core::getPod()
{
  return this->pod;
}

SSC_CodeError_t Core::encrypt(
 ErrType*          err_typ,
 InOutDir*         err_dir,
 StatusCallback_f* status_callback,
 void*             status_callback_data)
{
  PlainOldData* mypod {this->getPod()};
  // We require input and output filenames defined for ENCRYPT mode.
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
     ".4c",
     sizeof(".4c"));
  }

  // Get the size of the input file.
  size_t input_filesize;
  if (SSC_FilePath_getSize(mypod->input_filename, &input_filesize))
    return ERROR_GETTING_INPUT_FILESIZE;

  // Normalize the padding.
  this->normalizePadding(input_filesize);
  InOutDir err_io_dir {InOutDir::NONE};

  if (status_callback != nullptr)
    status_callback(status_callback_data);
  // Map the input and output files.
  SSC_CodeError_t err {
   this->mapFiles(
    &err_io_dir,
    input_filesize,
    input_filesize + mypod->padding_size + Core::getMetadataSize(),
    InOutDir::NONE)};
  if (err) {
    *err_typ = ErrType::MEMMAP;
    *err_dir = err_io_dir;
    return err;
  }

  // If the password has not already been initialized, then initialize it.
  if (mypod->password_size == 0) {
    // Get the encryption password.
    this->getPassword(not (mypod->flags & Core::ENTER_PASS_ONCE), false);
    if (mypod->flags & Core::SUPPLEMENT_ENTROPY)
      // Get the entropy password and hash it into the RNG.
      this->getPassword(false, true);
  }
  if (status_callback != nullptr)
    status_callback(status_callback_data);
  // Generate pseudorandom values.
  this->genRandomElements();
  // Run the key derivation function and get our secret values.
  if (status_callback != nullptr)
    status_callback(status_callback_data);
  this->runKDF();
  const uint8_t* in   {mypod->input_map.ptr};
  uint8_t*       out  {mypod->output_map.ptr};
  size_t         n_in {mypod->input_map.size};
  if (status_callback != nullptr)
    status_callback(status_callback_data);
  out = this->writeHeader(out); // Write the header of the ciphertext file.
  out = this->writeCiphertext(out, in, n_in); // Encrypt the input stream into the ciphertext file.
  if (status_callback != nullptr)
    status_callback(status_callback_data);
  this->writeMAC(out, mypod->output_map.ptr, mypod->output_map.size - MAC_SIZE);
  if (status_callback != nullptr)
    status_callback(status_callback_data);
  this->syncMaps();
  this->unmapFiles();
  if (status_callback != nullptr)
    status_callback(status_callback_data);
  return 0;
}


SSC_Error_t Core::normalizePadding(const uint64_t input_filesize)
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
      if (pad < (size + Core::getMetadataSize()))
        return -1;
      mypod->padding_size = pad - (size + Core::getMetadataSize());
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

void Core::genRandomElements()
{
  PlainOldData* mypod = this->getPod();
  TSC_CSPRNG*   myrng = &mypod->rng;

  // Threefish512 Tweak.
  TSC_CSPRNG_getBytes(
   myrng,
   mypod->tf_tweak,
   TSC_THREEFISH512_TWEAK_BYTES);
  // Catena salt.
  TSC_CSPRNG_getBytes(
   myrng,
   mypod->catena_salt,
   sizeof(mypod->catena_salt));
  // Threefish512 CTR IV.
  TSC_CSPRNG_getBytes(
   myrng,
   mypod->tf_ctr_iv,
   sizeof(mypod->tf_ctr_iv));
  // Destroy the RNG after we're finished.
  SSC_secureZero(myrng, sizeof(*myrng));
}

SSC_Error_t Core::runKDF()
{
  PlainOldData*  mypod         {this->getPod()};
  const uint64_t num_threads   {mypod->thread_count};
  const uint64_t batch_size    {mypod->thread_batch_size};
  const uint64_t output_bytes  {num_threads * TSC_THREEFISH512_BLOCK_BYTES};
  TSC_Catena512* const catenas {new TSC_Catena512[num_threads]};
  SSC_Error_t* const   errors  {new SSC_Error_t[num_threads]};
  uint8_t* const       outputs {new uint8_t[output_bytes]};
  {
    std::thread* threads {new std::thread[num_threads]};
    uint64_t j_stop;

    for (uint64_t i {0}; i < num_threads; i += j_stop) {
      if (i + batch_size < num_threads)
        j_stop = batch_size;
      else
        j_stop = num_threads - i;
      for (uint64_t j {0}; j < j_stop; ++j) {
        const uint64_t offset {i + j};
        std::construct_at(
         threads + offset,
         kdf,
         outputs + (offset * TSC_THREEFISH512_BLOCK_BYTES),
         mypod,
         catenas + offset,
         errors  + offset,
         offset);
      }
      for (uint64_t j {0}; j < j_stop; ++j) {
        const uint64_t offset {i + j};
        threads[offset].join();
        std::destroy_at(threads + offset);
      }
    }
    delete[] threads;
  }
  SSC_secureZero(catenas, sizeof(TSC_Catena512) * num_threads);
  delete[] catenas;
  SSC_secureZero(mypod->password_buffer, sizeof(mypod->password_buffer));

  // Combine all the outputs into one.
  for (uint64_t i {1}; i < num_threads; ++i)
    SSC_xor64(outputs, outputs + (i * TSC_THREEFISH512_BLOCK_BYTES));
  // Hash into 128 bytes of output.
  TSC_Skein512_hash(
   mypod->ubi512,
   mypod->hash_buffer,
   sizeof(mypod->hash_buffer),
   outputs,
   TSC_THREEFISH512_BLOCK_BYTES);
  SSC_secureZero(outputs, output_bytes);
  delete[] outputs;
  // The first 64 become the secret encryption key; the latter 64 become the authentication key.
  memcpy(mypod->tf_sec_key, mypod->hash_buffer, TSC_THREEFISH512_BLOCK_BYTES);
  memcpy(mypod->mac_key   , mypod->hash_buffer + TSC_THREEFISH512_BLOCK_BYTES, TSC_THREEFISH512_BLOCK_BYTES);
  SSC_secureZero(mypod->hash_buffer, sizeof(mypod->hash_buffer));
  // Initialize TSC_Threefish512Ctr.
  TSC_Threefish512Ctr_init(
   &mypod->tf_ctr,
   mypod->tf_sec_key,
   mypod->tf_tweak,
   mypod->tf_ctr_iv);

  for (uint64_t i {0}; i < num_threads; ++i) {
    if (errors[i]) {
      delete[] errors;
      return -1;
    }
  }
  delete[] errors;
  return 0;
}

SSC_Error_t Core::verifyMAC(const uint8_t* R_ mac, const uint8_t* R_ begin, const uint64_t size)
{
  alignas(uint64_t) uint8_t tmp_mac [MAC_SIZE];
  PlainOldData* mypod {this->getPod()};
  TSC_Skein512_mac(
   mypod->ubi512,
   tmp_mac,
   sizeof(tmp_mac),
   begin,
   size,
   mypod->mac_key);
  if (SSC_constTimeMemDiff(tmp_mac, mac, MAC_SIZE))
    return -1;
  return 0;
}

SSC_CodeError_t Core::decrypt(
 ErrType*          err_type,
 InOutDir*         err_io_dir,
 StatusCallback_f* status_callback,
 void*             status_callback_data)
{
  PlainOldData* mypod {this->getPod()};
  // Ensure at least an input file path is provided.
  if (mypod->input_filename == nullptr) {
    *err_io_dir = InOutDir::INPUT;
    return ERROR_NO_INPUT_FILENAME;
  }
  if (mypod->output_filename == nullptr) {
    uint64_t size = mypod->input_filename_size;
    if (size >= 4 && memcmp(mypod->input_filename + (size - 3), ".4c", 3) == 0) {
      mypod->output_filename_size = size - 3;
      mypod->output_filename = new char[mypod->output_filename_size + 1];
      memcpy(mypod->output_filename, mypod->input_filename, mypod->output_filename_size);
      mypod->output_filename[mypod->output_filename_size] = '\0';
    }
    else {
      *err_io_dir = InOutDir::OUTPUT;
      return ERROR_NO_OUTPUT_FILENAME;
    }
  }
  // Get the size of the input file.
  size_t input_filesize;
  if (SSC_FilePath_getSize(mypod->input_filename, &input_filesize)) {
    *err_io_dir = InOutDir::INPUT;
    return ERROR_GETTING_INPUT_FILESIZE;
  }
  // Check to see if the input file is large enough.
  if (input_filesize < Core::getMinimumOutputSize()) {
    *err_io_dir = InOutDir::INPUT;
    return ERROR_INPUT_FILESIZE_TOO_SMALL;
  }
  // Do not proceed if a file already exists at the output filepath.
  if (SSC_FilePath_exists(mypod->output_filename)) {
    *err_io_dir = InOutDir::OUTPUT;
    return ERROR_OUTPUT_FILE_EXISTS;
  }
  // Map the input file.
  {
    if (status_callback != nullptr)
      status_callback(status_callback_data);
    SSC_Error_t err {this->mapFiles(
     nullptr,
     input_filesize,
     0,
     InOutDir::INPUT)};
    if (err) {
      *err_io_dir = InOutDir::INPUT;
      return ERROR_INPUT_MEMMAP_FAILED;
    }
  }
  if (!Core::verifyBasicMetadata(mypod, InOutDir::INPUT)) {
    *err_io_dir = InOutDir::INPUT;
    return ERROR_INVALID_4CRYPT_FILE;
  }
  // If the decryption password has not already been initialized, then initialize it.
  if (mypod->password_size == 0)
    this->getPassword(false, false);
  const uint8_t* in     {mypod->input_map.ptr};
  const size_t   num_in {mypod->input_map.size};
  SSC_CodeError_t err   {0};
  // Read the input file header's plaintext.
  in = this->readHeaderPlaintext(in, &err);
  if (err)
    return err;
  PlainOldData::touchup(*mypod);
  // Run the KDF to generate secret values.
  if (status_callback != nullptr)
    status_callback(status_callback_data);
  this->runKDF();
  // Check the MAC for integrity and authentication.
  if (status_callback != nullptr)
    status_callback(status_callback_data);
  err = this->verifyMAC(
   mypod->input_map.ptr + (num_in - MAC_SIZE),
   mypod->input_map.ptr,
   num_in - MAC_SIZE);
  if (err) {
    *err_io_dir = InOutDir::INPUT;
    return ERROR_MAC_VALIDATION_FAILED;
  }
  // Decipher the encrypted portion of the input file header.
  if (status_callback != nullptr)
    status_callback(status_callback_data);
  in = this->readHeaderCiphertext(in, &err);
  if (err)
    return err;
  // Map the output file
  const size_t num_out {num_in - Core::getMetadataSize() - mypod->padding_size};
  {
    if (status_callback != nullptr)
      status_callback(status_callback_data);
    SSC_Error_t err {this->mapFiles(
     nullptr,
     0,
     num_out,
     InOutDir::OUTPUT)};
    if (err) {
      *err_io_dir = InOutDir::OUTPUT;
      return ERROR_OUTPUT_MEMMAP_FAILED;
    }
  }
  // Decipher the encrypted payload into the mapped output file.
  if (status_callback != nullptr)
    status_callback(status_callback_data);
  this->writePlaintext(mypod->output_map.ptr, in, num_out);
  
  if (status_callback != nullptr)
    status_callback(status_callback_data);
  this->syncMaps();
  this->unmapFiles();
  return 0;
}

SSC_Error_t Core::syncMaps()
{
  PlainOldData* mypod {this->getPod()};
  if (mypod->input_map.ptr) {
    if (SSC_MemMap_sync(&mypod->input_map))
      return -1;
  }
  if (mypod->output_map.ptr) {
    if (SSC_MemMap_sync(&mypod->output_map))
      return -1;
  }
  return 0;
}

void Core::unmapFiles()
{
  PlainOldData* mypod {this->getPod()};
  if (mypod->input_map.ptr)
    SSC_MemMap_del(&mypod->input_map);
  if (mypod->output_map.ptr)
    SSC_MemMap_del(&mypod->output_map);
}

const uint8_t* Core::readHeaderPlaintext(
 const uint8_t* R_   from,
 SSC_CodeError_t* R_ err)
{
  PlainOldData* mypod {this->getPod()};
  // Check the magic bytes.
  if (memcmp(from, Core::magic, sizeof(Core::magic))) {
    *err = ERROR_INVALID_4CRYPT_FILE;
    return from;
  }
  from += sizeof(Core::magic);
  // Mem Low, High, Iteration Count, Phi usage.
  mypod->memory_low  = (*from++);
  mypod->memory_high = (*from++);
  mypod->iterations  = (*from++);
  {
    uint8_t phi {*from++};
    if (phi)
      mypod->flags |= ENABLE_PHI;
  }
  // Size of the file, little-endian encoded.
  {
    uint64_t size;
    memcpy(&size, from, sizeof(size));
    from += sizeof(size);
    if constexpr(not Core::is_little_endian)
      size = SSC_swap64(size);
    if (mypod->input_map.size != size) {
      *err = ERROR_INPUT_SIZE_MISMATCH;
      return from;
    }
  }
  // Threefish512 Tweak.
  memcpy(mypod->tf_tweak, from, TSC_THREEFISH512_TWEAK_BYTES);
  from += TSC_THREEFISH512_TWEAK_BYTES;
  // CATENA Salt.
  memcpy(mypod->catena_salt, from, sizeof(mypod->catena_salt));
  from += sizeof(mypod->catena_salt);
  // Threefish512 CTR IV.
  memcpy(mypod->tf_ctr_iv, from, sizeof(mypod->tf_ctr_iv));
  from += sizeof(mypod->tf_ctr_iv);
  // Thread count, little-endian encoded.
  {
    uint64_t tcount;
    memcpy(&tcount, from, sizeof(tcount));
    from += sizeof(tcount);
    if constexpr(Core::is_little_endian)
      mypod->thread_count = tcount;
    else
      mypod->thread_count = SSC_swap64(tcount);
  }
  // 8 bytes reserved.
  if (!SSC_isZero(from, 8)) {
    *err = ERROR_RESERVED_BYTES_USED;
    return from;
  }
  from += 8;
  return from;
}

const uint8_t* Core::readHeaderCiphertext(const uint8_t* R_ from, SSC_CodeError_t* R_ err)
{
  PlainOldData* mypod {this->getPod()};
  // 8 Ciphered padding size bytes; 8 ciphered reserve bytes.
  {
    uint64_t tmp[2];
    TSC_Threefish512Ctr_xor_2(
      &mypod->tf_ctr,
      reinterpret_cast<uint8_t*>(tmp),
      from,
      sizeof(tmp),
      mypod->tf_ctr_idx);
    mypod->tf_ctr_idx += sizeof(tmp);
    from += sizeof(tmp);
    if constexpr(Core::is_little_endian)
      mypod->padding_size = tmp[0];
    else
      mypod->padding_size = SSC_swap64(tmp[0]);
    if (tmp[1] != 0) {
      *err = ERROR_RESERVED_BYTES_USED;
      return from;
    }
  }
  // Skip past the ciphertext padding bytes.
  from              += mypod->padding_size;
  // Increment the keystream counter past the padding bytes.
  mypod->tf_ctr_idx += mypod->padding_size;
  return from;
}

SSC_CodeError_t Core::describe(
 ErrType*          errtype,
 InOutDir*         errdir,
 StatusCallback_f* status_callback,
 void*             status_callback_data)
{
  PlainOldData* mypod {this->getPod()};
  if (mypod->input_filename == nullptr) {
    *errdir = InOutDir::INPUT;
    *errtype = ErrType::CORE;
    return ERROR_NO_INPUT_FILENAME;
  }
  SSC_CodeError_t err     {0};
  InOutDir        err_dir {InOutDir::NONE};
  err = this->mapFiles(
   &err_dir,
   0,
   0,
   InOutDir::INPUT);
  if (err) {
    *errdir = err_dir;
    *errtype = ErrType::MEMMAP;
    return err;
  }
  const uint8_t* in     {mypod->input_map.ptr};
  const uint64_t num_in {mypod->input_map.size};
  in = this->readHeaderPlaintext(in, &err);
  if (err) {
    *errdir = InOutDir::NONE;
    *errtype = ErrType::CORE;
    return err;
  }
  if (not Core::verifyBasicMetadata(mypod, InOutDir::INPUT)) {
    *errdir = InOutDir::INPUT;
    *errtype = ErrType::CORE;
    return ERROR_METADATA_VALIDATION_FAILED;
  }

  alignas(uint64_t) uint8_t mac [TSC_THREEFISH512_BLOCK_BYTES];
  memcpy(mac, mypod->input_map.ptr + num_in - sizeof(mac), sizeof(mac));

  // Print plaintext header information from beginning to end.
  if (mypod->flags & Core::ENABLE_PHI)
    puts("The Phi function IS USED! Beware cache-timing attacks!");
  printf(
   "The file size is................%s.\n",
   Core::makeMemoryString(mypod->input_map.size).c_str());
  if (mypod->memory_low == mypod->memory_high) {
    printf(
     "The KDF Memory Bound is.........%s\n",
     Core::makeMemoryStringBitShift(mypod->memory_low).c_str());
  }
  else {
    printf("The KDF Lower Memory Bound is...%s\n", Core::makeMemoryStringBitShift(mypod->memory_low).c_str());
    printf("The KDF Upper Memory Bound is...%s\n", Core::makeMemoryStringBitShift(mypod->memory_high).c_str());
  }
  printf("The KDF Thread Count is.........%" PRIu64 " thread(s).\n", mypod->thread_count);
  printf("Each KDF thread iterates........%" PRIu8 " time(s).\n", mypod->iterations);

  printf("The Threefish512 Tweak is.......0x");
  SSC_printBytes(mypod->tf_tweak, TSC_THREEFISH512_TWEAK_BYTES);

  printf("\nThe Catena512 Salt is...........0x");
  SSC_printBytes(mypod->catena_salt, sizeof(mypod->catena_salt));

  printf("\nThreefish512 CTR-Mode's IV is...0x");
  SSC_printBytes(mypod->tf_ctr_iv, sizeof(mypod->tf_ctr_iv));
  putchar('\n');
  return 0;
}

SSC_CodeError_t Core::mapFiles(InOutDir* map_err_idx, size_t input_size, size_t output_size, InOutDir only_map)
{
  constexpr const SSC_BitFlag_t input_flag {
   SSC_MEMMAP_INIT_READONLY | SSC_MEMMAP_INIT_FORCE_EXIST | SSC_MEMMAP_INIT_FORCE_EXIST_YES};
  constexpr const SSC_BitFlag_t output_flag {SSC_MEMMAP_INIT_FORCE_EXIST};

  PlainOldData*   mypod {this->getPod()};
  SSC_CodeError_t err   {0};
  // Input and output filenames have been checked for NULL. Map these filepaths.
  if (only_map != InOutDir::OUTPUT) {
    err = SSC_MemMap_init(
     &mypod->input_map,
     mypod->input_filename,
     input_size,
     input_flag);
    if (err) {
      if (map_err_idx)
        *map_err_idx = InOutDir::INPUT;
      return err;
    }
  }
  if (only_map != InOutDir::INPUT) {
    err = SSC_MemMap_init(
     &mypod->output_map,
     mypod->output_filename,
     output_size,
     output_flag);
    if (err) {
      if (map_err_idx)
        *map_err_idx = InOutDir::OUTPUT;
      return err;
    }
  }
  return 0;
}

void Core::getPassword(bool enter_twice, bool entropy)
{
  PlainOldData* mypod {this->getPod()};
  SSC_Terminal_init();
  if (enter_twice && !entropy) {
    mypod->password_size = static_cast<uint64_t>(SSC_Terminal_getPasswordChecked(
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
    if (entropy) {
      TSC_Skein512_hashNative(
        mypod->ubi512,
        mypod->hash_buffer,
        mypod->entropy_buffer,
        mypod->entropy_size);
      SSC_secureZero(mypod->entropy_buffer, sizeof(mypod->entropy_buffer));
      mypod->entropy_size = 0;
      TSC_CSPRNG_reseedFromBytes(&mypod->rng, mypod->hash_buffer);
      SSC_secureZero(mypod->hash_buffer, TSC_THREEFISH512_BLOCK_BYTES);
    }
  }
}

uint8_t* Core::writeHeader(uint8_t* to)
{
  PlainOldData* mypod {this->getPod()};
  // Magic bytes.
  memcpy(to, Core::magic, sizeof(Core::magic));
  to += sizeof(Core::magic);
  // Mem Low, High, Iteration Count, Phi usage.
  (*to++) = mypod->memory_low;
  (*to++) = mypod->memory_high;
  (*to++) = mypod->iterations;
  if (mypod->flags & Core::ENABLE_PHI)
    (*to++) = 0x01;
  else
    (*to++) = 0x00;
  // Size of the file, little-endian encoded.
  {
    uint64_t size;
    if constexpr(Core::is_little_endian)
      size = mypod->output_map.size;
    else
      size = SSC_swap64(mypod->output_map.size);
    memcpy(to, &size, sizeof(size));
    to += sizeof(size);
  }
  // Threefish512 Tweak.
  memcpy(to, mypod->tf_tweak, TSC_THREEFISH512_TWEAK_BYTES);
  to += TSC_THREEFISH512_TWEAK_BYTES;
  // CATENA Salt.
  memcpy(to, mypod->catena_salt, sizeof(mypod->catena_salt));
  to += sizeof(mypod->catena_salt);
  // Threefish512 CTR IV.
  memcpy(to, mypod->tf_ctr_iv, sizeof(mypod->tf_ctr_iv));
  to += sizeof(mypod->tf_ctr_iv);
  // Thread count, little-endian encoded.
  {
    uint64_t tcount;
    if constexpr(Core::is_little_endian)
      tcount = mypod->thread_count;
    else
      tcount = SSC_swap64(mypod->thread_count);
    memcpy(to, &tcount, sizeof(tcount));
    to += sizeof(tcount);
  }
  // 8 bytes reserved.
  memset(to, 0, 8);
  to += 8;
  // 8 Ciphered padding size bytes; 8 ciphered reserve bytes.
  {
    uint64_t tmp[2];
    if constexpr(Core::is_little_endian)
      tmp[0] = mypod->padding_size;
    else
      tmp[0] = SSC_swap64(mypod->padding_size);
    tmp[1] = 0;
    TSC_Threefish512Ctr_xor_2(
      &mypod->tf_ctr,
      to,
      reinterpret_cast<uint8_t*>(tmp),
      sizeof(tmp),
      mypod->tf_ctr_idx);
    mypod->tf_ctr_idx += sizeof(tmp);
    to += sizeof(tmp);
  }
  return to;
}

uint8_t* Core::writeCiphertext(uint8_t* R_ to, const uint8_t* R_ from, const size_t num)
{
  PlainOldData* mypod {this->getPod()};
  // Encipher padding bytes, if applicable.
  if (mypod->padding_size) {
    TSC_Threefish512Ctr_xor_1(
      &mypod->tf_ctr,
      to,
      mypod->padding_size,
      mypod->tf_ctr_idx);
    to                += mypod->padding_size;
    mypod->tf_ctr_idx += mypod->padding_size;
  }
  // Encipher the plaintext.
  TSC_Threefish512Ctr_xor_2(
    &mypod->tf_ctr,
    to,
    from,
    num,
    mypod->tf_ctr_idx);
  to                += num;
  mypod->tf_ctr_idx += num;
  return to;
}

void Core::writePlaintext(uint8_t* R_ to, const uint8_t* R_ from, const size_t num)
{
  PlainOldData* mypod {this->getPod()};
  TSC_Threefish512Ctr_xor_2(
    &mypod->tf_ctr,
    to,
    from,
    num,
    mypod->tf_ctr_idx);
  to += num;
  mypod->tf_ctr_idx += num;
}

void Core::writeMAC(uint8_t* R_ to, const uint8_t* R_ from, const size_t num)
{
  PlainOldData* mypod {this->getPod()};
  TSC_Skein512_mac(
    mypod->ubi512,
    to,
    sizeof(mypod->mac_key),
    from,
    num,
    mypod->mac_key);
}

bool Core::verifyBasicMetadata(
 PlainOldData* mypod,
 InOutDir      dir)
{
  const char* fpath;
  SSC_MemMap* map;
  switch (dir) {
    case InOutDir::INPUT:
      fpath = mypod->input_filename;
      map   = &mypod->input_map;
      break;
    case InOutDir::OUTPUT:
      fpath = mypod->output_filename;
      map   = &mypod->output_map;
      break;
    default:
      return false;
  }
  if (map->size < Core::getMinimumOutputSize())
    return false;
  if (memcmp(map->ptr, Core::magic, sizeof(Core::magic)) != 0)
    return false;
  size_t fp_sz;
  if (SSC_FilePath_getSize(fpath, &fp_sz))
    return false;
  if (map->size != fp_sz)
    return false;
  if (map->size % PAD_FACTOR)
    return false;
  return true;
}

std::string Core::makeMemoryStringBitShift(const uint8_t mem_bitshift)
{
  return Core::makeMemoryString(static_cast<uint64_t>(1) << (mem_bitshift + 6));
}

std::string Core::makeMemoryString(const uint64_t value)
{
  constexpr const uint64_t kibibyte {1024};
  constexpr const uint64_t mebibyte {kibibyte * kibibyte};
  constexpr const uint64_t gibibyte {mebibyte * kibibyte};
  constexpr const uint64_t tebibyte {gibibyte * kibibyte};
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

uint8_t
Core::getDefaultMemoryUsageBitShift(void)
{
#ifdef SSC_HAS_GETAVAILABLESYSTEMMEMORY
  const uint64_t available {static_cast<uint64_t>(SSC_getAvailableSystemMemory())};

  // Scan through all the bits until the highest bit is detected. Determine the equivalent bit shift from 0.
  {
    uint64_t i     {0x80'00'00'00'00'00'00'00};
    uint8_t  shift {0};

    while (not (i & available))
      i >>= 1;
    while (i != 1) {
      i >>= 1;
      ++shift;
    }
    if (shift >= 6)
      shift -= 6; // Later multiplied by 64 i.e. 2^6. Decrement by 6 here.

    return shift;
  }
#else
  return MEM_NORMAL;
#endif
}
