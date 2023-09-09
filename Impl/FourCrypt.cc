#include "FourCrypt.hh"
#define SSC_EXTERN_MEMLOCK // Enable memory locking.
#include <SSC/MemLock.h>

#if defined(SSC_OS_UNIXLIKE)
 #define NEWLINE_ std::string{"\n"}
#elif defined(SSC_OS_WINDOWS)
 #define NEWLINE_ std::string{"\n\r"}
#else
 #error "Invalid OS!"
#endif

using PlainOldData = FourCrypt::PlainOldData;

// FourCrypt static variable initialization.
bool FourCrypt::memlock_initialized = false;
std::string FourCrypt::password_prompt{};
std::string FourCrypt::reentry_prompt{};
std::string FourCrypt::entropy_prompt{};

FourCrypt::FourCrypt()
{
  if (!FourCrypt::memlock_initialized) {
    SSC_MemLock_Global_initHandled();
    FourCrypt::memlock_initialized = true;
  }
  if (FourCrypt::password_prompt.empty()) {
    FourCrypt::password_prompt = 
      std::string{"Please input a password (max length "} +
      std::string{MAX_PW_BYTES_STR} +
      std::string{" characters)."} + NEWLINE_;
    FourCrypt::reentry_prompt =
      std::string{"Please input the same password again."} + NEWLINE_;
    FourCrypt::entropy_prompt = 
      std::string{"Please input up to "} +
      std::string{MAX_PW_BYTES_STR} +
      std::string{" random characters)."} +  NEWLINE_;
  }

  this->pod = new PlainOldData;
  PlainOldData::init(this->getPod());
  PPQ_CSPRNG_init(&this->getPod()->rng);
}

FourCrypt::~FourCrypt()
{
  PlainOldData::del(this->getPod());
  delete this->getPod();
}

PlainOldData* FourCrypt::getPod()
{
  return this->pod;
}

SSC_CodeError_t FourCrypt::encrypt()
{
  PlainOldData* mypod = this->getPod();
  if (mypod->input_filename == nullptr)
    return ERROR_NO_INPUT_FILENAME;
  if (mypod->output_filename == nullptr)
    return ERROR_NO_OUTPUT_FILENAME;
  SSC_CodeError_t err = this->mapFiles();
  if (err)
    return err;
  this->getPassword(true);
  if (mypod->flags & FourCrypt::SUPPLEMENT_ENTROPY)
    this->getEntropy();
  uint8_t* in   = mypod->input_map.ptr;
  uint8_t* out  = mypod->output_map.ptr;
  size_t   n_in = mypod->input_map.size;
  out = this->writeHeader(out); // Write the header of the ciphertext file.
  out = this->writeCiphertext(out, in, n_in); // Encrypt the input stream into the ciphertext file.
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

SSC_CodeError_t FourCrypt::mapFiles()
{
  //TODO
  return 0;
}

void FourCrypt::getPassword(bool enter_twice)
{
  //TODO
}

uint8_t* FourCrypt::writeHeader(uint8_t* to)
{
  //TODO
  return nullptr;
}

uint8_t* FourCrypt::writeCiphertext(uint8_t* to, const uint8_t* from, const size_t num)
{
  //TODO
  return nullptr;
}

void FourCrypt::getEntropy()
{
  //TODO
}
