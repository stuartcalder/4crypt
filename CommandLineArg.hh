#ifndef COMMANDLINEARG_HH
#define COMMANDLINEARG_HH

#include <SSC/CommandLineArg.h>
#include "FourCrypt.hh"
#define R_ SSC_RESTRICT

int decrypt_argproc(const int, char** R_, const int, void* R_);
int describe_argproc(const int, char** R_, const int, void* R_);
int encrypt_argproc(const int, char** R_, const int, void* R_);
int enter_password_once_argproc(const int, char** R_, const int, void* R_);
int entropy_argproc(const int, char** R_, const int, void* R_);
int help_argproc(const int, char** R_, const int, void* R_);
int high_mem_argproc(const int, char** R_, const int, void* R_);
int iterations_argproc(const int, char** R_, const int, void* R_);
int low_mem_argproc(const int, char** R_, const int, void* R_);
int output_argproc(const int, char** R_, const int, void* R_);
int pad_as_if_argproc(const int, char** R_, const int, void* R_);
int pad_by_argproc(const int, char** R_, const int, void* R_);
int pad_to_argproc(const int, char** R_, const int, void* R_);
int threads_argproc(const int, char** R_, const int, void* R_);
int use_mem_argproc(const int, char** R_, const int, void* R_);
int use_phi_argproc(const int, char** R_, const int, void* R_);

#undef R_
#endif
