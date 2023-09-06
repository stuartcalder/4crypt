#include "FourCrypt.hh"

#include <SSC/MemLock.h>

#if defined(SSC_OS_UNIXLIKE)
 #define NEWLINE_ "\n"
#elif defined(SSC_OS_WINDOWS)
 #define NEWLINE_ "\n\r"
#else
 #error "Invalid OS!"
#endif

FourCrypt::FourCrypt()
{
  if (!FourCrypt::memlock_initialized) {
    SSC_MemLock_Global_initHandled();
    FourCrypt::memlock_initialized = true;
  }
  if (FourCrypt::password_prompt.empty()) {
    FourCrypt::password_prompt = 
      "Please input a password (max length " +
      MAX_PW_BYTES_STR +
      " characters)." NEWLINE_;
    FourCrypt::reentry_prompt =
      "Please input the same password again." NEWLINE_;
    FourCrypt::entropy_prompt = 
      "Please input up to " +
      MAX_PW_BYTES_STR +
      " random characters)." NEWLINE_;
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
  if (mypod->flags & FLAG_SUPPLEMENT_ENTROPY)
    this->getEntropy();
  uint8_t* in   = mypod->input_map.ptr;
  uint8_t* out  = mypod->output_map.ptr;
  size_t   n_in = mypod->input_map.size;
  out = this->writeHeader(out); // Write the header of the ciphertext file.
  out = this->writeCiphertext(out, in, n_in); // Encrypt the input stream into the ciphertext file.
  //TODO
}

SSC_CodeError_t FourCrypt::decrypt()
{
  //TODO
}

SSC_CodeError_t FourCrypt::describe()
{
  //TODO
}
