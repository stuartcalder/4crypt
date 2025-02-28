#include "CommandLineArg.hh"
#include "Util.hh"
// C++ C Lib
#include <cinttypes>
#define R_ SSC_RESTRICT
using namespace fourcrypt;


using ExeMode = Core::ExeMode;
using PadMode = Core::PadMode;
using PlainOldData = Core::PlainOldData;

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
  return SSC_OK;
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

#if 0
static uint64_t
parse_integer(const char* R_ str, const size_t len)
{
  char* const temp = new char[len + 1];
  memcpy(temp, str, len + 1);
  SSC_Cstr_shiftDigitsToFront(temp, len);
  uint64_t integer = static_cast<uint64_t>(strtoumax(temp, nullptr, 10));
  delete temp;
  return integer;
}
#endif

SSC_INLINE uint64_t
parse_threads(const char* R_ str, const size_t len)
{
  return parse_integer(str, len);
}

SSC_INLINE uint64_t
parse_batch(const char* R_ str, const size_t len)
{
  return parse_integer(str, len);
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
   "-B, --batch-size=<num>      Set the number of KDF threads to execute concurrently.\n"
   "-1, --enter-password-once   Disable password-reentry for correctness verification during encryption.\n"
   "-P, --use-phi               Enable the Phi function for each KDF thread.\n"
   "--pad-as-if=<size>          Pad the output ciphertext as if it were an unpadded encrypted file of this size.\n"
   "--pad-by=<size>             Pad the output ciphertext by this many bytes, rounded up such that the produced\n"
   "                              ciphertext is evenly divisible by 64.\n"
   "--pad-to=<size>             Pad the output ciphertext to the target size, rounded up such that the produced\n"
   "                              ciphertext is evenly divisible by 64.\n"
   "WARNING: The phi function hardens the key-derivation function against\n"
   "parallel adversaries, greatly increasing the work necessary to brute-force\n"
   "your password, but introduces the potential for cache-timing attacks.\n"
   "Do NOT use this feature unless you understand the security implications!");
}

int
ArgProc::decrypt(const int argc, char** R_ argv, const int offset, void* R_ data)
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
ArgProc::describe(const int argc, char** R_ argv, const int offset, void* R_ data)
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
ArgProc::encrypt(const int argc, char** R_ argv, const int offset, void* R_ data)
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
ArgProc::enter_password_once(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  pod->flags |= Core::ENTER_PASS_ONCE;
  return SSC_1opt(argv[0][offset]);
}

int
ArgProc::entropy(const int, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  pod->flags |= Core::SUPPLEMENT_ENTROPY;
  return SSC_1opt(argv[0][offset]);
}

int
ArgProc::help(const int, char** R_, const int, void* R_)
{
  print_help();
  exit(EXIT_SUCCESS);
  return 0; // Suppress compiler warnings.
}

int
ArgProc::high_mem(const int argc, char** R_ argv, const int offset, void* R_ data)
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
     return SSC_OK;
   });
}

int
ArgProc::iterations(const int argc, char** R_ argv, const int offset, void* R_ data)
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
     SSC_assertMsg(pod->iterations > 0, "Error: Invalid iteration count %d!\n", static_cast<int>(pod->iterations));
     return SSC_OK;
   });
}

int
ArgProc::low_mem(const int argc, char** R_ argv, const int offset, void* R_ data)
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
     return SSC_OK;
   });
}

int
ArgProc::output(const int argc, char** R_ argv, const int offset, void* R_ data)
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
     return SSC_OK;
   });
}

int
ArgProc::pad_as_if(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  set_padmode(pod, PadMode::AS_IF);
  return ArgProc::pad_by(argc, argv, offset, data);
}

int
ArgProc::pad_by(const int argc, char** R_ argv, const int offset, void* R_ data)
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
     return SSC_OK;
   });
}

int
ArgProc::pad_to(const int argc, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  set_padmode(pod, PadMode::TARGET);
  return ArgProc::pad_by(argc, argv, offset, data);
}

int
ArgProc::threads(const int argc, char** R_ argv, const int offset, void* R_ data)
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
     return SSC_OK;
   });
}

int
ArgProc::use_mem(const int argc, char** R_ argv, const int offset, void* R_ data)
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
     return SSC_OK;
   });
}

int
ArgProc::use_phi(const int, char** R_ argv, const int offset, void* R_ data)
{
  PlainOldData* pod = static_cast<PlainOldData*>(data);
  pod->flags |= Core::ENABLE_PHI;
  return SSC_1opt(argv[0][offset]);
}

int
ArgProc::batch_size(const int argc, char** R_ argv, const int offset, void* R_ data)
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
     pod->thread_batch_size = parse_batch(ap->to_read, ap->size);
     return SSC_OK;
   });
}
