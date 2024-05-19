// Local
#include "Core.hh"
#include "CommandLineArg.hh"
// SSC
#include <SSC/Macro.h>
#include <SSC/CommandLineArg.h>
// C++ STL
#include <array>
using namespace fourcrypt;


using PlainOldData = Core::PlainOldData;
using ErrType = Core::ErrType;
using InOutDir = Core::InOutDir;
using ExeMode  = Core::ExeMode;
using PadMode  = Core::PadMode;

const std::array<SSC_ArgShort, 14> shorts = {{
  SSC_ARGSHORT_LITERAL(ArgProc::enter_password_once, '1'),
  SSC_ARGSHORT_LITERAL(ArgProc::batch_size,          'B'),
  SSC_ARGSHORT_LITERAL(ArgProc::describe,            'D'),
  SSC_ARGSHORT_LITERAL(ArgProc::entropy,             'E'),
  SSC_ARGSHORT_LITERAL(ArgProc::high_mem,            'H'),
  SSC_ARGSHORT_LITERAL(ArgProc::iterations,          'I'),
  SSC_ARGSHORT_LITERAL(ArgProc::low_mem,             'L'),
  SSC_ARGSHORT_LITERAL(ArgProc::use_mem,             'M'),
  SSC_ARGSHORT_LITERAL(ArgProc::use_phi,             'P'),
  SSC_ARGSHORT_LITERAL(ArgProc::threads,             'T'),
  SSC_ARGSHORT_LITERAL(ArgProc::decrypt,             'd'),
  SSC_ARGSHORT_LITERAL(ArgProc::encrypt,             'e'),
  SSC_ARGSHORT_LITERAL(ArgProc::help,                'h'),
  SSC_ARGSHORT_LITERAL(ArgProc::output,              'o'),
}};

const std::array<SSC_ArgLong, 21> longs = {{
  SSC_ARGLONG_LITERAL(ArgProc::batch_size,          "batch-size"),
  SSC_ARGLONG_LITERAL(ArgProc::decrypt,             "decrypt"),
  SSC_ARGLONG_LITERAL(ArgProc::describe,            "describe"),
  SSC_ARGLONG_LITERAL(ArgProc::describe,            "dump"),
  SSC_ARGLONG_LITERAL(ArgProc::encrypt,             "encrypt"),
  SSC_ARGLONG_LITERAL(ArgProc::enter_password_once, "enter-password-once"),
  SSC_ARGLONG_LITERAL(ArgProc::entropy,             "entropy"),
  SSC_ARGLONG_LITERAL(ArgProc::help,                "help"),
  SSC_ARGLONG_LITERAL(ArgProc::high_mem,            "high-mem"),
  SSC_ARGLONG_LITERAL(ArgProc::high_mem,            "high-memory"),
  SSC_ARGLONG_LITERAL(ArgProc::iterations,          "iterations"),
  SSC_ARGLONG_LITERAL(ArgProc::low_mem,             "low-mem"),
  SSC_ARGLONG_LITERAL(ArgProc::low_mem,             "low-memory"),
  SSC_ARGLONG_LITERAL(ArgProc::output,              "output"),
  SSC_ARGLONG_LITERAL(ArgProc::pad_as_if,           "pad-as-if"),
  SSC_ARGLONG_LITERAL(ArgProc::pad_by,              "pad-by"),
  SSC_ARGLONG_LITERAL(ArgProc::pad_to,              "pad-to"),
  SSC_ARGLONG_LITERAL(ArgProc::threads,             "threads"),
  SSC_ARGLONG_LITERAL(ArgProc::use_mem,             "use-mem"),
  SSC_ARGLONG_LITERAL(ArgProc::use_mem,             "use-memory"),
  SSC_ARGLONG_LITERAL(ArgProc::use_phi,             "use-phi"),
}};

static void handle_core_errors(PlainOldData* pod, SSC_CodeError_t err, InOutDir err_io_dir)
{
  switch (err) {
    case (Core::ERROR_NO_INPUT_FILENAME):
      SSC_errx("No input filename provided!\n");
      break;
    case (Core::ERROR_NO_OUTPUT_FILENAME):
      SSC_errx("No output filename provided!\n");
      break;
    case (Core::ERROR_INPUT_MEMMAP_FAILED):
      SSC_errx("Failed while mapping the input file!\n");
      break;
    case (Core::ERROR_OUTPUT_MEMMAP_FAILED):
      SSC_errx("Failed while mapping the output file!\n");
      break;
    case (Core::ERROR_GETTING_INPUT_FILESIZE):
      SSC_errx("Failed while getting the size of the input file!\n");
      break;
    case (Core::ERROR_INPUT_FILESIZE_TOO_SMALL):
      SSC_errx("The input file is too small!\n");
      break;
    case (Core::ERROR_INVALID_4CRYPT_FILE):
      SSC_errx("The input file is an invalid 4crypt file!\n");
      break;
    case (Core::ERROR_INPUT_SIZE_MISMATCH):
      SSC_errx("The input file's header size field doesn't match the size of the file!\n");
      break;
    case (Core::ERROR_RESERVED_BYTES_USED):
      SSC_errx("Reserved bytes of the file were improperly used!\n");
      break;
    case (Core::ERROR_OUTPUT_FILE_EXISTS):
      SSC_errx("The output file already exists!\n");
      break;
    case (Core::ERROR_MAC_VALIDATION_FAILED):
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
  Core core{};
  PlainOldData* pod = core.getPod();
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
  ErrType         code_type   = ErrType::CORE;
  InOutDir        code_io_dir = InOutDir::NONE;
  
  switch (pod->execute_mode) {
    case ExeMode::ENCRYPT:
      PlainOldData::touchup(*pod);
      code_error = core.encrypt(&code_type, &code_io_dir);
      break;
    case ExeMode::DECRYPT:
      code_error = core.decrypt(&code_type, &code_io_dir);
      break;
    case ExeMode::DESCRIBE:
      code_error = core.describe(&code_type, &code_io_dir);
      break;
    default:
      SSC_errx("Invalid execute_mode in pod.\n");
  }
  if (code_error == 0)
    return EXIT_SUCCESS;
  switch (code_type) {
    case ErrType::CORE:
      handle_core_errors(pod, code_error, code_io_dir);
      break;
    case ErrType::MEMMAP:
      handle_memmap_errors(pod, code_error, code_io_dir);
      break;
    default:
      SSC_errx("Invalid ErrType %d in %s!\n", code_type, __FILE__);
  }
}
