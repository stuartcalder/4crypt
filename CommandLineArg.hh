#ifndef COMMANDLINEARG_HH
#define COMMANDLINEARG_HH

#include <SSC/CommandLineArg.h>
#include "FourCrypt.hh"
#define R_ SSC_RESTRICT

int decrypt_argproc(const int, char** R_, const int, void* R_);
int describe_argproc(const int, char** R_, const int, void* R_);
int encrypt_argproc(const int, char** R_, const int, void* R_);
int entropy_argproc(const int, char** R_, const int, void* R_);
int help_argproc(const int, char** R_, const int, void* R_);
int highmem_argproc(const int, char** R_, const int, void* R_);
int input_argproc(const int, char** R_, const int, void* R_);
int iterations_argproc(const int, char** R_, const int, void* R_);
int lowmem_argproc(const int, char** R_, const int, void* R_);
int output_argproc(const int, char** R_, const int, void* R_);
int padasif_argproc(const int, char** R_, const int, void* R_);
int padby_argproc(const int, char** R_, const int, void* R_);
int padto_argproc(const int, char** R_, const int, void* R_);
int threads_argproc(const int, char** R_, const int, void* R_);
int usemem_argproc(const int, char** R_, const int, void* R_);
int usephi_argproc(const int, char** R_, const int, void* R_);

#undef R_
#endif
