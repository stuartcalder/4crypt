#ifndef COMMANDLINEARG_HH
#define COMMANDLINEARG_HH

#include <SSC/CommandLineArg.h>
#include "Core.hh"
#define ARGS_ const int argc, char** SSC_RESTRICT argv, const int offset, void* SSC_RESTRICT data

// Set the number of KDF threads to process simultaneously.
int batch_size_argproc(ARGS_);
// Set the mode to Decrypt, and provide the path to the encrypted file.
int decrypt_argproc(ARGS_);
// Set the mode to Describe, and provide the path to the encrypted file.
int describe_argproc(ARGS_);
// Set the mode to Encrypt, and provide the path to the plaintext file.
int encrypt_argproc(ARGS_);
// Disable password re-entry during encryption; not applicable to decryption.
int enter_password_once_argproc(ARGS_);
// Enable entering an 'entropy password' to harden the CSPRNG.
int entropy_argproc(ARGS_);
// Print help output and exit successfully.
int help_argproc(ARGS_);
// Set the higher memory bound for the KDF.
int high_mem_argproc(ARGS_);
// Set the number of KDF iterations per thread.
int iterations_argproc(ARGS_);
// Set the lower memory bound for the KDF.
int low_mem_argproc(ARGS_);
// Set the output file path.
int output_argproc(ARGS_);
// Pad the output ciphertext as if it was an unpadded ciphertext of the provided size, rounded up to be divisible by 64.
int pad_as_if_argproc(ARGS_);
// Pad the output ciphertext by the provided number of bytes, round up to be divisible by 64.
int pad_by_argproc(ARGS_);
// Pad the output ciphertext up to the provided target size in bytes, rounded up to be divisible by 64.
int pad_to_argproc(ARGS_);
// Set the number of KDF threads.
int threads_argproc(ARGS_);
// Set the low and high KDF memory bounds to the same provided value.
int use_mem_argproc(ARGS_);
// Enable usage of the Phi function in the KDF.
int use_phi_argproc(ARGS_);

#undef ARGS_
#endif
