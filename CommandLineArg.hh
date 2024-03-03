#ifndef COMMANDLINEARG_HH
#define COMMANDLINEARG_HH

#include <SSC/CommandLineArg.h>
#include "FourCrypt.hh"
#define ARGS_ const int argc, char** SSC_RESTRICT argv, const int offset, void* SSC_RESTRICT data

int decrypt_argproc(ARGS_);
int describe_argproc(ARGS_);
int encrypt_argproc(ARGS_);
int enter_password_once_argproc(ARGS_);
int entropy_argproc(ARGS_);
int help_argproc(ARGS_);
int high_mem_argproc(ARGS_);
int iterations_argproc(ARGS_);
int low_mem_argproc(ARGS_);
int output_argproc(ARGS_);
int pad_as_if_argproc(ARGS_);
int pad_by_argproc(ARGS_);
int pad_to_argproc(ARGS_);
int threads_argproc(ARGS_);
int use_mem_argproc(ARGS_);
int use_phi_argproc(ARGS_);

#undef ARGS_
#endif
