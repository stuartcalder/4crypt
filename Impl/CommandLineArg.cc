#include "CommandLineArg.hh"
#include <inttypes.h>
using ExeMode = FourCrypt::ExeMode;
using PadMode = FourCrypt::PadMode;
using PlainOldData = FourCrypt::PlainOldData;
#define R_ SSC_RESTRICT

static const char* mode_strings[] = {
  "NONE", "ENCRYPT", "DECRYPT", "DESCRIBE"
};

static int
set_exemode(
 PlainOldData* R_ ctx,
 ExeMode          em,
 char* R_         str,
 const int        off)
{
  SSC_assertMsg(
   ctx->execute_mode == ExeMode::NONE,
   "Execute mode already set to %s!\n", mode_strings[static_cast<int>(ctx->execute_mode)]);
  ctx->execute_mode = em;
  return SSC_1opt(str[off]); // Continue processing if invoked by a short op, otherwise terminate.
}

static SSC_Error_t
input_argproc_processor(SSC_ArgParser* R_ ap, void* R_ dt)
{
  PlainOldData* pod = static_cast<PlainOldData*>(dt);
  pod->input_filename = new char[ap->size + 1];
  pod->input_filename_size = ap->size;
  memcpy(pod->input_filename, ap->to_read, ap->size + 1);
  return 0;
}

static void
set_padmode(
 PlainOldData* R_ ctx,
 PadMode          pm)
{
  static const char* mode_strings[] = {
    "NONE", "ADD", "TARGET", "AS_IF"
  };
  SSC_assertMsg(
   ctx->padding_mode == PadMode::ADD,
   "Padding mode already set to %s!\n", mode_strings[static_cast<int>(ctx->padding_mode)]);
  ctx->padding_mode = pm;
}

constexpr uint64_t KIBIBYTE = 1024;
constexpr uint64_t MEBIBYTE = KIBIBYTE * KIBIBYTE;
constexpr uint64_t GIBIBYTE = MEBIBYTE * KIBIBYTE;

static uint8_t
parse_memory(const char* R_ str, const size_t len)
{
  uint64_t requested_bytes = 0;
  uint64_t multiplier = 1;
  uint64_t num_digits = 0;
  char* const temp = new char[len + 1];
  memcpy(temp, str, len + 1);
  for (size_t i = 0; i < len; ++i) {
    switch (toupper(static_cast<unsigned char>(str[i]))) {
      case 'K':
        multiplier = KIBIBYTE / 64;
      	goto have_multiplier;
      case 'M':
	      multiplier = MEBIBYTE / 64;
	      goto have_multiplier;
      case 'G':
	      multiplier = GIBIBYTE / 64;
	      goto have_multiplier;
      default:
	      SSC_assertMsg(isdigit(static_cast<unsigned char>(str[i])), "Invalid memory string '%s'!\n", str);
    }
  }
have_multiplier:
  /* Shift all the digits to the beginning of @temp and store the number
   * of digits in @num_digits. */
  num_digits = static_cast<uint64_t>(SSC_Cstr_shiftDigitsToFront(temp, len));
  SSC_assertMsg(num_digits, "No number supplied with memory specification!\n");

  constexpr uint64_t BYTE_MAX = 10000;
  constexpr uint64_t KIBIBYTE_MAX = 17592186044416;
  constexpr uint64_t MEBIBYTE_MAX = 17179869184;
  constexpr uint64_t GIBIBYTE_MAX = 16777216;
  uint64_t num_digit_limit = 0;
  switch (multiplier) {
    case 1:
      num_digit_limit = BYTE_MAX;
      break;
    case KIBIBYTE / 64:
      num_digit_limit = KIBIBYTE_MAX;
      break;
    case MEBIBYTE / 64:
      num_digit_limit = MEBIBYTE_MAX;
      break;
    case GIBIBYTE / 64:
      num_digit_limit = GIBIBYTE_MAX;
      break;
  }
  SSC_assertMsg(num_digits > 0 && num_digits < num_digit_limit, "Specified memory parameter digits (%" PRIu64 ")\n", num_digits);
  requested_bytes = static_cast<uint64_t>(strtoumax(temp, nullptr, 10));
  delete temp;
  requested_bytes *= multiplier;
  SSC_assertMsg(requested_bytes, "Zero memory requested!\n");
  uint64_t mask = UINT64_C(0x80'00'00'00'00'00'00'00);
  uint8_t mem = 63;
  while (!(mask & requested_bytes)) {
    mask >>= 1;
    --mem;
  }
  return mem;
}

static uint8_t
parse_iterations(const char* R_ str, const size_t len)
{
  char* const temp = new char[len + 1];
  memcpy(temp, str, len + 1);
  uint64_t num_digits = static_cast<uint64_t>(SSC_Cstr_shiftDigitsToFront(temp, len));
  SSC_assertMsg(num_digits >= 1 && num_digits <= 3, "Invalid iteration count!\n");
  int it = atoi(temp);
  delete temp;
  SSC_assertMsg(it >= 1 && it <= 255, "Invalid iteration count!\n");
  return static_cast<uint8_t>(it);
}

static uint64_t
parse_threads(const char* R_ str, const size_t len)
{
  char* const temp = new char[len + 1];
  memcpy(temp, str, len + 1);
  SSC_Cstr_shiftDigitsToFront(temp, len);
  uint64_t threads = static_cast<uint64_t>(strtoumax(temp, nullptr, 10));
  delete temp;
  return threads;
}

static uint64_t
parse_padding(const char* R_ str, const size_t len)
{
  char* const temp = new char[len + 1];
  memcpy(temp, str, len + 1);
  uint64_t multiplier = 1;
  for (size_t i = 0; i < len; ++i) {
    switch (toupper(static_cast<unsigned char>(str[i]))) {
      case 'K':
        multiplier = KIBIBYTE;
        goto have_multiplier;
      case 'M':
        multiplier = MEBIBYTE;
        goto have_multiplier;
      case 'G':
        multiplier = GIBIBYTE;
        goto have_multiplier;
    }
  }
  uint64_t num_digits;
have_multiplier:
  num_digits = SSC_Cstr_shiftDigitsToFront(temp, len);
  SSC_assertMsg(num_digits > 0, "Asked for 0 padding?");
  uint64_t padding = static_cast<uint64_t>(strtoumax(temp, nullptr, 10));
  delete temp;
  SSC_assertMsg((padding * multiplier) >= padding, "padding < padding * multiplier... Overflow?\n");
  return padding * multiplier;
}

static void
print_help()
{
  puts(
   ".------.\n"
   "|4crypt|\n"
   "'------'\n"
   "-h, --help                  Print help output.\n"
   "-e, --encrypt=<filepath>    Encrypt the file at the filepath.\n"
   "-d, --decrypt=<filepath>    Decrypt the file at the filepath.\n"
   "-D, --describe=<filepath>   Describe the header of encrypted file at the filepath.\n"
   "-o, --output=<filepath>     Specify an output filepath.\n"
   "-E, --entropy               Provide addition entropy to the RNG from stdin.\n"
   "-H, --high-mem=<mem[K|M|G]> Provide an upper memory bound for key derivation.\n"
   "-L, --low-mem=<mem[K|M|G]>  Provide a lower memory bound for key derivation.\n"
   "-M, --use-mem=<mem[K|M|G]>  Set the lower and upper memory bounds to the same value.\n"
   "-I, --iterations=<num>      Set the number of times to iterate the KDF.\n"
   "-T, --threads=<num>         Set the degree of parallelism for the KDF.\n"
   "-1, --enter-password-once   Disable password-reentry for correctness verification during encryption.\n"
   "-P, --use-phi               Enable the Phi function for each KDF thread.\n"
   "WARNING: The phi function hardens the key-derivation function against\n"
   "parallel adversaries, greatly increasing the work necessary to brute-force\n"
   "your password, but introduces the potential for cache-timing attacks.\n"
   "Do NOT use this feature unless you understand the security implications!");
}

int
decrypt_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  SSC_assertMsg(
   pod->execute_mode == ExeMode::NONE,
   "Execute mode already set to %s!\n", mode_strings[static_cast<int>(pod->execute_mode)]);
  pod->execute_mode = ExeMode::DECRYPT;
  SSC_ArgParser parser;
  return SSC_ArgParser_process(
   &parser,
   argc,
   argv,
   offset,
   data,
   nullptr,
   &input_argproc_processor);
}

int
describe_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  SSC_assertMsg(
   pod->execute_mode == ExeMode::NONE,
   "Execute mode already set to %s!\n", mode_strings[static_cast<int>(pod->execute_mode)]);
  pod->execute_mode = ExeMode::DESCRIBE;
  SSC_ArgParser parser;
  return SSC_ArgParser_process(
   &parser,
   argc,
   argv,
   offset,
   data,
   nullptr,
   &input_argproc_processor);
}

int
encrypt_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  SSC_assertMsg(
   pod->execute_mode == ExeMode::NONE,
   "Execute mode already set to %s!\n", mode_strings[static_cast<int>(pod->execute_mode)]);
  pod->execute_mode = ExeMode::ENCRYPT;
  SSC_ArgParser parser;
  return SSC_ArgParser_process(
   &parser,
   argc,
   argv,
   offset,
   data,
   nullptr,
   &input_argproc_processor);
}

int
enter_password_once_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  pod->flags |= FourCrypt::ENTER_PASS_ONCE;
  return SSC_1opt(argv[0][offset]);
}

int
entropy_argproc(const int, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  pod->flags |= FourCrypt::SUPPLEMENT_ENTROPY;
  return SSC_1opt(argv[0][offset]);
}

int
help_argproc(const int, char** R_, const int, void* R_)
{
  print_help();
  exit(EXIT_SUCCESS);
  return 0; // Suppress compiler warnings.
}

int
high_mem_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  SSC_ArgParser parser;
  return SSC_ArgParser_process(
   &parser,
   argc,
   argv,
   offset,
   data,
   nullptr,
   [](SSC_ArgParser* R_ ap, void* R_ dt) -> SSC_Error_t {
     PlainOldData* pod = static_cast<PlainOldData*>(dt);
     pod->memory_high = parse_memory(ap->to_read, ap->size);
     if (pod->memory_low > pod->memory_high)
       pod->memory_low = pod->memory_high;
     return 0;
   });
}

int
iterations_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  SSC_ArgParser parser;
  return SSC_ArgParser_process(
   &parser,
   argc,
   argv,
   offset,
   data,
   nullptr,
   [](SSC_ArgParser* R_ ap, void* R_ dt) -> SSC_Error_t {
     PlainOldData* pod = static_cast<PlainOldData*>(dt);
     pod->iterations = parse_iterations(ap->to_read, ap->size);
     return 0;
   });
}

int
low_mem_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  SSC_ArgParser parser;
  return SSC_ArgParser_process(
   &parser,
   argc,
   argv,
   offset,
   data,
   nullptr,
   [](SSC_ArgParser* R_ ap, void* R_ dt) -> SSC_Error_t {
     PlainOldData* pod = static_cast<PlainOldData*>(dt);
     pod->memory_low = parse_memory(ap->to_read, ap->size);
     if (pod->memory_high < pod->memory_low)
       pod->memory_high = pod->memory_low;
     return 0;
   });
}

int
output_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  SSC_ArgParser parser;
  return SSC_ArgParser_process(
   &parser,
   argc,
   argv,
   offset,
   data,
   nullptr,
   [](SSC_ArgParser* R_ ap, void* R_ dt) -> SSC_Error_t {
     PlainOldData* pod = static_cast<PlainOldData*>(dt);
     pod->output_filename = new char[ap->size + 1];
     pod->output_filename_size = ap->size;
     memcpy(pod->output_filename, ap->to_read, ap->size + 1);
     return 0;
   });
}

int
pad_as_if_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  set_padmode(pod, PadMode::AS_IF);
  return pad_by_argproc(argc, argv, offset, data);
}

int
pad_by_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  SSC_ArgParser parser;
  return SSC_ArgParser_process(
   &parser,
   argc,
   argv,
   offset,
   data,
   nullptr,
   [](SSC_ArgParser* R_ ap, void* R_ dt) -> SSC_Error_t {
     PlainOldData* pod = static_cast<PlainOldData*>(dt);
     pod->padding_size = parse_padding(ap->to_read, ap->size);
     return 0;
   });
}

int
pad_to_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  set_padmode(pod, PadMode::TARGET);
  return pad_by_argproc(argc, argv, offset, data);
}

int
threads_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  SSC_ArgParser parser;
  return SSC_ArgParser_process(
   &parser,
   argc,
   argv,
   offset,
   data,
   nullptr,
   [](SSC_ArgParser* R_ ap, void* R_ dt) -> SSC_Error_t {
     PlainOldData* pod = static_cast<PlainOldData*>(dt);
     pod->thread_count = parse_threads(ap->to_read, ap->size);
     return 0;
   });
}

int
use_mem_argproc(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  SSC_ArgParser parser;
  return SSC_ArgParser_process(
   &parser,
   argc,
   argv,
   offset,
   data,
   nullptr,
   [](SSC_ArgParser* R_ ap, void* R_ dt) -> SSC_Error_t {
     PlainOldData* pod = static_cast<PlainOldData*>(dt);
     uint8_t mem = parse_memory(ap->to_read, ap->size);
     pod->memory_high = mem;
     pod->memory_low = mem;
     return 0;
   });
}

int
use_phi_argproc(const int, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  pod->flags |= FourCrypt::ENABLE_PHI;
  return SSC_1opt(argv[0][offset]);
}
