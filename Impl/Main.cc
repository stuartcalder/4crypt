#include <SSC/Macro.h>
#include <SSC/CommandLineArg.h>

#include "FourCrypt.hh"

const std::array<SSC_ArgShort, 14> shorts = {
  SSC_ARGSHORT_LITERAL(describe_argproc  , 'D'),
  SSC_ARGSHORT_LITERAL(entropy_argproc   , 'E'),
  SSC_ARGSHORT_LITERAL(highmem_argproc   , 'H'),
  SSC_ARGSHORT_LITERAL(iterations_argproc, 'I'),
  SSC_ARGSHORT_LITERAL(lowmem_argproc    , 'L'),
  SSC_ARGSHORT_LITERAL(usephi_argproc    , 'P'),
  SSC_ARGSHORT_LITERAL(threads_argproc   , 'T'),
  SSC_ARGSHORT_LITERAL(usemem_argproc    , 'U'),
  SSC_ARGSHORT_LITERAL(decrypt_argproc   , 'd'),
  SSC_ARGSHORT_LITERAL(encrypt_argproc   , 'e'),
  SSC_ARGSHORT_LITERAL(help_argproc      , 'h'),
  SSC_ARGSHORT_LITERAL(input_argproc     , 'i'),
  SSC_ARGSHORT_LITERAL(output_argproc    , 'o'),
  SSC_ARGSHORT_NULL_LITERAL
};

const std::array<SSC_ArgLong, 14> longs = {
  SSC_ARGLONG_LITERAL(decrypt_argproc   , "decrypt"),
  SSC_ARGLONG_LITERAL(describe_argproc  , "describe"),
  SSC_ARGLONG_LITERAL(encrypt_argproc   , "encrypt"),
  SSC_ARGLONG_LITERAL(entropy_argproc   , "entropy"),
  SSC_ARGLONG_LITERAL(help_argproc      , "help"),
  SSC_ARGLONG_LITERAL(highmem_argproc   , "highmem"),
  SSC_ARGLONG_LITERAL(input_argproc     , "input"),
  SSC_ARGLONG_LITERAL(iterations_argproc, "iterations"),
  SSC_ARGLONG_LITERAL(lowmem_argproc    , "lowmem"),
  SSC_ARGLONG_LITERAL(output_argproc    , "output"),
  SSC_ARGLONG_LITERAL(threads_argproc   , "threads"),
  SSC_ARGLONG_LITERAL(usemem_argproc    , "usemem"),
  SSC_ARGLONG_LITERAL(usephi_argproc    , "usephi"),
  SSC_ARGLONG_NULL_LITERAL
};

int main(int argc, char* argv[])
{
  FourCrypt fc;
  PlainOldData* pod = fc.getPod();
  SSC_assertMsg(argc >= 2, "Invalid number of command-line arguments.\n");
  SSC_processCommandLineArgs(
   argc - 1,
   argv + 1,
   shorts.size() - 1,
   shorts.data(),
   longs.size() - 1,
   longs.data(),
   pod,
   nullptr);
  SSC_BitError_t biterror = 0;
  switch (pod->execute_mode) {
    case ExeMode::ENCRYPT:
      biterror = fc.encrypt(); //TODO: Implement.
    case ExeMode::DECRYPT:
      biterror = fc.decrypt(); //TODO: Implement.
    case ExeMode::DESCRIBE:
      biterror = fc.describe(); //TODO: Implement.
    default:
      SSC_errx("Invalid execute_mode in pod.\n");
  }
  //TODO: Check @biterror to see if anything went wrong.
  return EXIT_SUCCESS;
}
