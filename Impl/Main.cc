#include <array>
#include <SSC/Macro.h>
#include <SSC/CommandLineArg.h>

#include "FourCrypt.hh"
#include "CommandLineArg.hh"

using PlainOldData = FourCrypt::PlainOldData;
using ErrType = FourCrypt::ErrType;
using InOutDir = FourCrypt::InOutDir;
using ExeMode  = FourCrypt::ExeMode;
using PadMode  = FourCrypt::PadMode;

const std::array<SSC_ArgShort, 14> shorts = {{
  SSC_ARGSHORT_LITERAL(enter_password_once_argproc, '1'),
  SSC_ARGSHORT_LITERAL(batch_size_argproc         , 'B'),
  SSC_ARGSHORT_LITERAL(describe_argproc           , 'D'),
  SSC_ARGSHORT_LITERAL(entropy_argproc            , 'E'),
  SSC_ARGSHORT_LITERAL(high_mem_argproc           , 'H'),
  SSC_ARGSHORT_LITERAL(iterations_argproc         , 'I'),
  SSC_ARGSHORT_LITERAL(low_mem_argproc            , 'L'),
  SSC_ARGSHORT_LITERAL(use_mem_argproc            , 'M'),
  SSC_ARGSHORT_LITERAL(use_phi_argproc            , 'P'),
  SSC_ARGSHORT_LITERAL(threads_argproc            , 'T'),
  SSC_ARGSHORT_LITERAL(decrypt_argproc            , 'd'),
  SSC_ARGSHORT_LITERAL(encrypt_argproc            , 'e'),
  SSC_ARGSHORT_LITERAL(help_argproc               , 'h'),
  SSC_ARGSHORT_LITERAL(output_argproc             , 'o'),
}};

const std::array<SSC_ArgLong, 21> longs = {{
  SSC_ARGLONG_LITERAL(batch_size_argproc         , "batch-size"),
  SSC_ARGLONG_LITERAL(decrypt_argproc            , "decrypt"),
  SSC_ARGLONG_LITERAL(describe_argproc           , "describe"),
  SSC_ARGLONG_LITERAL(describe_argproc           , "dump"),
  SSC_ARGLONG_LITERAL(encrypt_argproc            , "encrypt"),
  SSC_ARGLONG_LITERAL(enter_password_once_argproc, "enter-password-once"),
  SSC_ARGLONG_LITERAL(entropy_argproc            , "entropy"),
  SSC_ARGLONG_LITERAL(help_argproc               , "help"),
  SSC_ARGLONG_LITERAL(high_mem_argproc           , "high-mem"),
  SSC_ARGLONG_LITERAL(high_mem_argproc           , "high-memory"),
  SSC_ARGLONG_LITERAL(iterations_argproc         , "iterations"),
  SSC_ARGLONG_LITERAL(low_mem_argproc            , "low-mem"),
  SSC_ARGLONG_LITERAL(low_mem_argproc            , "low-memory"),
  SSC_ARGLONG_LITERAL(output_argproc             , "output"),
  SSC_ARGLONG_LITERAL(pad_as_if_argproc          , "pad-as-if"),
  SSC_ARGLONG_LITERAL(pad_by_argproc             , "pad-by"),
  SSC_ARGLONG_LITERAL(pad_to_argproc             , "pad-to"),
  SSC_ARGLONG_LITERAL(threads_argproc            , "threads"),
  SSC_ARGLONG_LITERAL(use_mem_argproc            , "use-mem"),
  SSC_ARGLONG_LITERAL(use_mem_argproc            , "use-memory"),
  SSC_ARGLONG_LITERAL(use_phi_argproc            , "use-phi"),
}};

static void handle_fourcrypt_errors(PlainOldData* pod, SSC_CodeError_t err, InOutDir err_io_dir)
{
  switch (err) {
    case (FourCrypt::ERROR_NO_INPUT_FILENAME):
      SSC_errx("No input filename provided!\n");
      break;
    case (FourCrypt::ERROR_NO_OUTPUT_FILENAME):
      SSC_errx("No output filename provided!\n");
      break;
    case (FourCrypt::ERROR_INPUT_MEMMAP_FAILED):
      SSC_errx("Failed while mapping the input file!\n");
      break;
    case (FourCrypt::ERROR_OUTPUT_MEMMAP_FAILED):
      SSC_errx("Failed while mapping the output file!\n");
      break;
    case (FourCrypt::ERROR_GETTING_INPUT_FILESIZE):
      SSC_errx("Failed while getting the size of the input file!\n");
      break;
    case (FourCrypt::ERROR_INPUT_FILESIZE_TOO_SMALL):
      SSC_errx("The input file is too small!\n");
      break;
    case (FourCrypt::ERROR_INVALID_4CRYPT_FILE):
      SSC_errx("The input file is an invalid 4crypt file!\n");
      break;
    case (FourCrypt::ERROR_INPUT_SIZE_MISMATCH):
      SSC_errx("The input file's header size field doesn't match the size of the file!\n");
      break;
    case (FourCrypt::ERROR_RESERVED_BYTES_USED):
      SSC_errx("Reserved bytes of the file were improperly used!\n");
      break;
    case (FourCrypt::ERROR_OUTPUT_FILE_EXISTS):
      SSC_errx("The output file already exists!\n");
      break;
    case (FourCrypt::ERROR_MAC_VALIDATION_FAILED):
      SSC_errx("Failed to validate the MAC!\n");
      break;
    default:
      SSC_errx("Unaccounted for code_error code in pod, %d.\n", err);
  }
}
static void handle_memmap_errors(PlainOldData* pod, SSC_CodeError_t err, InOutDir err_io_dir)
{
  const char* err_str;
  const char* err_map;
  const char* err_path;
  switch (err) {
    case SSC_MEMMAP_INIT_CODE_ERR_FEXIST_NO:
      err_str = "Attempted to map %s filepath at %s, but it already existed!\n";
      break;
    case SSC_MEMMAP_INIT_CODE_ERR_FEXIST_YES:
      err_str = "Attempted to create and map %s filepath at %s, but it didn't exist!\n";
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
  switch(err_io_dir) {
    case InOutDir::INPUT:
      err_map = "input";
      err_path = pod->input_filename;
      break;
    case InOutDir::OUTPUT:
      err_map = "output";
      err_path = pod->output_filename;
    default:
      SSC_errx("Invalid err_io_dir %d in handle_memmap_errors!\n", err_io_dir);
  }
  if (err_io_dir == InOutDir::OUTPUT && SSC_FilePath_exists(err_path))
    remove(err_path);
  SSC_errx(err_str, err_map, err_path);
}

int main(int argc, char* argv[])
{
  FourCrypt fc{};
  PlainOldData* pod = fc.getPod();
  SSC_assertMsg(argc >= 2, "Invalid number of command-line arguments.\n");
  SSC_processCommandLineArgs(
   argc - 1,
   argv + 1,
   shorts.size(),
   shorts.data(),
   longs.size(),
   longs.data(),
   pod,
   nullptr);
  SSC_CodeError_t code_error  = 0;
  ErrType         code_type   = ErrType::FOURCRYPT;
  InOutDir        code_io_dir = InOutDir::NONE;
  
  switch (pod->execute_mode) {
    case ExeMode::ENCRYPT:
      PlainOldData::touchup(*pod);
      code_error = fc.encrypt(&code_type, &code_io_dir);
      break;
    case ExeMode::DECRYPT:
      code_error = fc.decrypt(&code_type, &code_io_dir);
      break;
    case ExeMode::DESCRIBE:
      code_error = fc.describe(&code_type, &code_io_dir);
      break;
    default:
      SSC_errx("Invalid execute_mode in pod.\n");
  }
  if (code_error == 0)
    return EXIT_SUCCESS;
  switch (code_type) {
    case ErrType::FOURCRYPT:
      handle_fourcrypt_errors(pod, code_error, code_io_dir);
      break;
    case ErrType::MEMMAP:
      handle_memmap_errors(pod, code_error, code_io_dir);
      break;
    default:
      SSC_errx("Invalid ErrType %d in %s!\n", code_type, __FILE__);
  }
  #if 0
  switch (code_error) {
    case (FourCrypt::ERROR_NO_INPUT_FILENAME):
      SSC_errx("No input filename provided!\n");
      break;
    case (FourCrypt::ERROR_NO_OUTPUT_FILENAME):
      SSC_errx("No output filename provided!\n");
      break;
    case (FourCrypt::ERROR_INPUT_MEMMAP_FAILED):
      SSC_errx("Failed while mapping the input file!\n");
      break;
    case (FourCrypt::ERROR_OUTPUT_MEMMAP_FAILED):
      SSC_errx("Failed while mapping the output file!\n");
      break;
    case (FourCrypt::ERROR_GETTING_INPUT_FILESIZE):
      SSC_errx("Failed while getting the size of the input file!\n");
      break;
    case (FourCrypt::ERROR_INPUT_FILESIZE_TOO_SMALL):
      SSC_errx("The input file is too small!\n");
      break;
    case (FourCrypt::ERROR_INVALID_4CRYPT_FILE):
      SSC_errx("The input file is an invalid 4crypt file!\n");
      break;
    case (FourCrypt::ERROR_INPUT_SIZE_MISMATCH):
      SSC_errx("The input file's header size field doesn't match the size of the file!\n");
      break;
    case (FourCrypt::ERROR_RESERVED_BYTES_USED):
      SSC_errx("Reserved bytes of the file were improperly used!\n");
      break;
    case (FourCrypt::ERROR_OUTPUT_FILE_EXISTS):
      SSC_errx("The output file already exists!\n");
      break;
    case (FourCrypt::ERROR_MAC_VALIDATION_FAILED):
      SSC_errx("Failed to validate the MAC!\n");
      break;
    default:
      SSC_errx("Unaccounted for code_error code in pod.\n");
  }
  #endif
}
