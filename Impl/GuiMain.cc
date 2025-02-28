#include "Gui.hh"
#include "Util.hh"
// GTK4
#include <gio/gio.h>
// C++ STL
#include <algorithm>
#include <chrono>
#include <map>
#include <string>
#include <thread>
#include <utility>
// C++ C Lib
#include <cstring>
#include <cstdlib>
#include <cstdio>
// SSC
#include <SSC/Process.h>
#ifdef FOURCRYPT_IS_PORTABLE
 #ifndef SSC_HAS_GETEXECUTABLEPATH
  #warning "Trying to build a portable 4crypt while SSC does not support SSC_getExecutablePath()!"
  #error   "Unsatisfiable build requirements."
 #endif
#endif

#if !defined(SSC_LANG_CPP)
 #error "We need C++!"
#elif SSC_LANG_CPP < SSC_CPP_17
 #error "We need at least C++17!"
#endif
using namespace fourcrypt;

using Pod_t = Gui::Pod_t;
constexpr int FOURCRYPT_IMG_WIDTH_ORIGINAL {300};
constexpr int FOURCRYPT_IMG_WIDTH    {FOURCRYPT_IMG_WIDTH_ORIGINAL - 100};
constexpr int FOURCRYPT_IMG_HEIGHT   {300};

constexpr int FOURCRYPT_TITLE_WIDTH  {309};
constexpr int FOURCRYPT_TITLE_HEIGHT {195};

constexpr int WINDOW_WIDTH  {FOURCRYPT_IMG_WIDTH  * 2};
constexpr int WINDOW_HEIGHT {FOURCRYPT_IMG_HEIGHT * 2}; 

constexpr bool Debug {true};

static const char* const memoryUsageStrings[] {
   "128M", "256M" , "512M",
   "1G"  , "2G"   , "4G",
   "8G"  , "16G"  , "32G",
   "64G" , "128G" , "256G",
   nullptr
};

static const std::map<SSC_CodeError_t, const char*> error_msg {
  {Core::ERROR_NO_INPUT_FILENAME         , "No input file provided!"},
  {Core::ERROR_NO_OUTPUT_FILENAME        , "No output file provided!"},
  {Core::ERROR_INPUT_MEMMAP_FAILED       , "Failed to memory-map the input file!"},
  {Core::ERROR_OUTPUT_MEMMAP_FAILED      , "Failed to memory-map the output file!"},
  {Core::ERROR_GETTING_INPUT_FILESIZE    , "Failed to get the size of the input file!"},
  {Core::ERROR_INPUT_FILESIZE_TOO_SMALL  , "The input file is too small to be a 4crypt-encrypted file!"},
  {Core::ERROR_INVALID_4CRYPT_FILE       , "The input file is NOT a 4crypt-encrypted file!"},
  {Core::ERROR_INPUT_SIZE_MISMATCH       , "The size field of the input file does not match the file's size!"},
  {Core::ERROR_RESERVED_BYTES_USED       , "Reserved bytes of the input file were used!"},
  {Core::ERROR_OUTPUT_FILE_EXISTS        , "The output file already exists!"},
  {Core::ERROR_MAC_VALIDATION_FAILED     , "Failed to validate the Message Authentication Code. The input file may be corrupted or may have been maliciously modified!"},
  {Core::ERROR_KDF_FAILED                , "Failed to compute cryptographic keys! For encryption try a lesser mode; for decryption lower the thread batch size!"},
  {Core::ERROR_METADATA_VALIDATION_FAILED, "Failed to validate the input file's metadata!"}
};

static bool
str_ends_with(const std::string& str, const std::string& with)
 {
  std::string::size_type position {
   str.rfind(
    with.c_str(),
    std::string::npos,
    with.size())};
  return position != std::string::npos;
 }

void
fourcrypt::make_os_path(std::string& str)
 {
  for (char& c : str)
   {
   #if   defined(SSC_OS_UNIXLIKE)
    if (c == FOURCRYPT_SLASH_CHAR_WINDOWS)
      c = FOURCRYPT_SLASH_CHAR_UNIXLIKE;
   #elif defined(SSC_OS_WINDOWS)
    if (c == FOURCRYPT_SLASH_CHAR_UNIXLIKE)
      c = FOURCRYPT_SLASH_CHAR_WINDOWS;
   #else
    #error "Unsupported!"
   #endif
   }
 }

#ifdef FOURCRYPT_IS_PORTABLE
std::string
Gui::getExecutablePath(void)
 {
  char* c_execpath {SSC_getExecutablePath(nullptr)};
  SSC_assertMsg(c_execpath != nullptr, "Error: getExecutablePath(): c_execpath was NULL!\n");
  std::string s {c_execpath};
  free(c_execpath);
  return s;
 }

std::string
Gui::getExecutableDirPath(void)
 {
  std::string str  {getExecutablePath()};
  auto        size {str.size()};
  SSC_assertMsg(size > FOURCRYPT_GUI_BINARY_LENGTH, "Error: ExecutableDirPath invalid size!\n");

  SSC_assertMsg(
   str_ends_with(str, FOURCRYPT_GUI_BINARY),
   "Error: " FOURCRYPT_GUI_BINARY "was not found at the end of the path!\n");

  str.erase(
   str.end() - (FOURCRYPT_GUI_BINARY_LENGTH + 1), // Also erase the trailing '/'.
   str.end());
  // Consider the possibility that the executable dir is somehow a root directory.
  if (str.size() == 0)
    str += FOURCRYPT_SLASH_CHAR_OS
  return str;
 }
#endif

std::string
Gui::getResourcePath(void)
 {
 #if   defined(FOURCRYPT_IS_PORTABLE)
  return getExecutableDirPath();
 #elif defined(__gnu_linux__)
  return std::string{"/usr/share/4crypt"};
 #else
  #error "Unsupported!"
 #endif
 }

Gui::Gui(Core* param_core, int param_argc, char** param_argv)
: mCore{param_core}, mArgc{param_argc}, mArgv{param_argv}, mNumberProcessors{SSC_getNumberProcessors()}
 {
  mPod = mCore->getPod();
  gtk_init();

  mFileDialog  = gtk_file_dialog_new();
  mAlertDialog = gtk_alert_dialog_new("ALERT!");
  gtk_alert_dialog_set_modal(mAlertDialog, TRUE);

  // Initialize some CSS stuff.
  SSC_assertMsg(gdk_display_get_default(), "DEFAULT DISPLAY IS NULL\n");
  GtkCssProvider* provider  {gtk_css_provider_new()};
  std::string provider_path {getResourcePath() + "/style.css"};
  make_os_path(provider_path);
  gtk_css_provider_load_from_path(provider, provider_path.c_str());
  gtk_style_context_add_provider_for_display(
   gdk_display_get_default(),
   GTK_STYLE_PROVIDER(provider),
   GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
 }

Gui::~Gui()
 {
  g_object_unref(mFileDialog);
  g_object_unref(mAlertDialog);
 }

void
Gui::onEncryptButtonClicked(GtkWidget* button, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  std::puts("Encrypt button was pushed.");
  gui->clearPasswordEntries();
  if (gui->mMode != Mode::ENCRYPT)
    gui->setMode(Mode::ENCRYPT);
  else
    gui->setMode(Mode::NONE);
 }

void
Gui::onDecryptButtonClicked(GtkWidget* button, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  std::puts("Decrypt button was pushed.");
  gui->clearPasswordEntries();
  if (gui->mMode != Mode::DECRYPT)
    gui->setMode(Mode::DECRYPT);
  else
    gui->setMode(Mode::NONE);
 }

void
Gui::onInputButtonClicked(GtkWidget* button, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  std::puts("Input button was pushed.");
  gtk_file_dialog_open(
   gui->mFileDialog,
   GTK_WINDOW(gui->mApplicationWindow),
   nullptr, // (GCancellable*)
   static_cast<GAsyncReadyCallback>([]
    (GObject*      fdialog,
     GAsyncResult* result,
     void*         void_self) -> void
    {
     Gui*    lambda_self {static_cast<Gui*>(void_self)};
    /* This function initiates a file selection operation by presenting a file chooser
     * dialog to the user.The callback will be called when the dialog is dismissed.
     * It should call gtk_file_dialog_open_finish() to obtain
     * the result. */
     GFile* file {
      gtk_file_dialog_open_finish(
       GTK_FILE_DIALOG(fdialog),
       result,
       nullptr)};
     if (file != nullptr)
      {
       lambda_self->mInputFilepath = g_file_get_path(file);
       lambda_self->onInputFilepathUpdated();
      }
    }),
   gui); // (gpointer)
 }

void
Gui::onOutputButtonClicked(GtkWidget* button, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  std::puts("Output button was pushed.");
  gtk_file_dialog_save(
   gui->mFileDialog,
   GTK_WINDOW(gui->mApplicationWindow),
   nullptr, // (GCancellable*)
   static_cast<GAsyncReadyCallback>([]
    (GObject*      fdialog,
     GAsyncResult* result,
     void*         void_self)
    {
     Gui* lambda_self {static_cast<Gui*>(void_self)};
     
     GFile* file {
      gtk_file_dialog_save_finish(
       GTK_FILE_DIALOG(fdialog),
       result,
       nullptr)};
     if (file != nullptr)
      {
       lambda_self->mOutputFilepath = g_file_get_path(file);
      }
    }),
   gui);
 }

using ExeMode  = Core::ExeMode;
using PadMode  = Core::PadMode;
using InOutDir = Core::InOutDir;
using ErrType  = Core::ErrType;

void
Gui::updateProgressCallback(void* v_gui)
 {
  g_idle_add(
   static_cast<GSourceFunc>([](void* vgui) -> gboolean
    {
     Gui*            gui {static_cast<Gui*>(vgui)};
     GtkProgressBar* pb  {GTK_PROGRESS_BAR(gui->mProgressBar)};
     double old_fraction {gtk_progress_bar_get_fraction(pb)};
     double new_fraction {old_fraction + PROGRESS_PULSE_STEP};
     if (new_fraction > 1.0)
       new_fraction = 1.0;
     gtk_progress_bar_set_fraction(pb, new_fraction);
     return G_SOURCE_REMOVE;
    }),
   v_gui);
 }

gboolean
Gui::endOperation(void* vgui)
 {
  Gui* g {static_cast<Gui*>(vgui)};
  gtk_widget_set_visible(g->mProgressBox, FALSE);
  gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(g->mProgressBar), 0.0);
  g->mOperationIsOngoingMtx.lock();
  g->mOperationIsOngoing = false;
  g->mOperationIsOngoingMtx.unlock();
  return G_SOURCE_REMOVE;
 }

gboolean
Gui::makeStatusVisible(void* vgui)
 {
  Gui* g {static_cast<Gui*>(vgui)};
  gtk_widget_set_visible(g->mStatusBox, TRUE);
  return G_SOURCE_REMOVE;
 }

gboolean
Gui::makeStatusInvisible(void* vgui)
 {
  Gui* g {static_cast<Gui*>(vgui)};
  gtk_widget_set_visible(g->mStatusBox, FALSE);
  return G_SOURCE_REMOVE;
 }

void
Gui::statusThread(void* vgui)
 {
  Gui* gui {static_cast<Gui*>(vgui)};
  gui->mStatusIsBlinkingMtx.lock();
  if (not gui->mStatusIsBlinking)
   {
    gui->mStatusIsBlinking = true;
    gui->mStatusIsBlinkingMtx.unlock();
    bool is_blinking {true};
    while (is_blinking)
     {
      g_idle_add(&makeStatusVisible, gui);
      std::this_thread::sleep_for(std::chrono::milliseconds(750));
      g_idle_add(&makeStatusInvisible, gui);
      std::this_thread::sleep_for(std::chrono::milliseconds(750));
      gui->mStatusIsBlinkingMtx.lock();
      is_blinking = gui->mStatusIsBlinking;
      gui->mStatusIsBlinkingMtx.unlock();
     }
   }
  else
    gui->mStatusIsBlinkingMtx.unlock();
 }

void
Gui::encryptThread(
 Core::StatusCallback_f* status_callback,
 void*                   status_callback_data)
 {
  Gui*   gui  {static_cast<Gui*>(status_callback_data)};
  Core*  core {gui->mCore};
  Pod_t* pod  {gui->mPod};
  {
    std::lock_guard lg {gui->mOperationMtx};

    // Expert mode parameter selection.
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(gui->mStrengthExpertCheckbutton)))
     {
      // Phi.
      if (gtk_check_button_get_active(GTK_CHECK_BUTTON(gui->mEncryptParamPhiCheckbutton)))
        pod->flags |= Core::ENABLE_PHI;
      // Memory Usage.
      const auto mem_usage_idx {gtk_drop_down_get_selected(GTK_DROP_DOWN(gui->mEncryptParamMemoryDropdown))};
      if (mem_usage_idx != GTK_INVALID_LIST_POSITION)
       {
        const char* mem_usage {memoryUsageStrings[mem_usage_idx]};
        if (mem_usage != nullptr)
         {
          uint8_t mem {parse_memory(mem_usage, std::strlen(mem_usage))};
          pod->memory_low  = mem;
          pod->memory_high = mem;
         }
       }
      // Iterations.
      GtkEntryBuffer* ebuf     {gtk_text_get_buffer(GTK_TEXT(gui->mEncryptParamIterationsText))};
      const char* ebuf_cstr    {gtk_entry_buffer_get_text(ebuf)};
      const uint8_t iterations {parse_iterations(ebuf_cstr, std::strlen(ebuf_cstr))};
      if (iterations > 0)
        pod->iterations = iterations;
      // Threads Count.
      ebuf             = gtk_text_get_buffer(GTK_TEXT(gui->mEncryptParamThreadText));
      ebuf_cstr        = gtk_entry_buffer_get_text(ebuf);
      uint64_t threads {parse_integer(ebuf_cstr, std::strlen(ebuf_cstr))};
      pod->thread_count = threads;
      // Thread Batch Size.
      ebuf      = gtk_text_get_buffer(GTK_TEXT(gui->mEncryptParamBatchSizeText));
      ebuf_cstr = gtk_entry_buffer_get_text(ebuf);
      uint64_t batch_size {parse_integer(ebuf_cstr, std::strlen(ebuf_cstr))};
      if (batch_size <= pod->thread_count)
        pod->thread_batch_size = batch_size;
     }
    else if (gtk_check_button_get_active(GTK_CHECK_BUTTON(gui->mStrengthStrongCheckbutton)))
     {
      Pod_t::set_strong(*pod);
     }
    else if (gtk_check_button_get_active(GTK_CHECK_BUTTON(gui->mStrengthStandardCheckbutton)))
     {
      Pod_t::set_normal(*pod); //TODO: Rename normal to standard or vice-versa.
     }
    else // (Assume fast parameter selection.)
     {
      Pod_t::set_fast(*pod);
     }

    gui->mOperationData.code_error = core->encrypt(
     &gui->mOperationData.error_type,
     &gui->mOperationData.in_out_dir,
     status_callback,
     gui);
    if (gui->mOperationData.code_error == 0)
     {
      g_idle_add([](void* vgui) -> gboolean
       {
        static_cast<Gui*>(vgui)->setStatusLabelSuccess(true);
        return G_SOURCE_REMOVE;
       },
       gui);
     }
    else
     {
      g_idle_add([](void* vgui) -> gboolean
       {
        Gui* g {static_cast<Gui*>(vgui)};
        g->setStatusLabelSuccess(false);
        gtk_alert_dialog_set_detail(g->mAlertDialog, error_msg.at(g->mOperationData.code_error));
        gtk_alert_dialog_show(g->mAlertDialog, nullptr);
        return G_SOURCE_REMOVE;
       },
       gui);
     }
    Pod_t::del(*pod);
    Pod_t::init(*pod);
    TSC_CSPRNG_init(&pod->rng);

    std::thread th {&statusThread, gui};
    th.detach();

    std::this_thread::sleep_for(std::chrono::seconds(1));
    g_idle_add(&endOperation, gui);
  }
 }

void
Gui::encrypt(void)
 {
  mOperationIsOngoingMtx.lock();
  if (not mOperationIsOngoing)
   {
    mOperationIsOngoing = true;
    mOperationIsOngoingMtx.unlock();
    mPod->execute_mode = ExeMode::ENCRYPT;
    Pod_t::touchup(*mPod);
    gtk_widget_set_visible(mProgressBox, TRUE);

    std::thread th {&encryptThread, &updateProgressCallback, this};
    th.detach();
   }
  else
    mOperationIsOngoingMtx.unlock();
 }

void
Gui::decryptThread(
 Core::StatusCallback_f* status_callback,
 void*                   status_callback_data)
 {
  Gui*   gui  {static_cast<Gui*>(status_callback_data)};
  Core*  core {gui->mCore};
  Pod_t* pod  {gui->mPod};
  {
    std::lock_guard lg {gui->mOperationMtx};
    gui->mOperationData.code_error = core->decrypt(
     &gui->mOperationData.error_type,
     &gui->mOperationData.in_out_dir,
     status_callback,
     gui);
    Pod_t::del(*pod);
    Pod_t::init(*pod);
    TSC_CSPRNG_init(&pod->rng);
    if (gui->mOperationData.code_error == 0)
     {
      g_idle_add([](void* vgui) -> gboolean
       {
        static_cast<Gui*>(vgui)->setStatusLabelSuccess(true);
        return G_SOURCE_REMOVE;
       },
       gui);
     }
    else
     {
      g_idle_add([](void *vgui) -> gboolean
       {
        Gui* g {static_cast<Gui*>(vgui)};
        g->setStatusLabelSuccess(false);
        gtk_alert_dialog_set_detail(g->mAlertDialog, error_msg.at(g->mOperationData.code_error));
        gtk_alert_dialog_show(g->mAlertDialog, nullptr);
        return G_SOURCE_REMOVE;
       },
       gui);
     }

    std::thread th {&statusThread, gui};
    th.detach();

    std::this_thread::sleep_for(std::chrono::seconds(1));
    g_idle_add(&endOperation, gui);
  }
 }

void
Gui::decrypt(void)
 {
  mOperationIsOngoingMtx.lock();
  if (not mOperationIsOngoing)
   {
    mOperationIsOngoing = true;
    mOperationIsOngoingMtx.unlock();
    mPod->execute_mode = ExeMode::DECRYPT;
    gtk_widget_set_visible(mProgressBox, TRUE);

    std::thread th {&decryptThread, &updateProgressCallback, this};
    th.detach();
   }
  else
    mOperationIsOngoingMtx.unlock();
 }

void
Gui::onStartButtonClicked(GtkWidget* button, void* self)
 {
  Gui*   gui {static_cast<Gui*>(self)};
  Pod_t* pod {gui->mPod};

  std::puts("Start button was pushed.");
  if (not gui->verifyInputs())
    return;

  // Reset the POD if it's been initialized.
  if (pod->input_filename)
   {
    Pod_t::del(*pod);
    Pod_t::init(*pod);
    TSC_CSPRNG_init(&pod->rng);
   }

  if (not gui->getPassword())
    return;

  pod->input_filename = new char [gui->mInputFilepath.size() + 1];
  memcpy(pod->input_filename, gui->mInputFilepath.c_str(), gui->mInputFilepath.size() + 1);
  pod->output_filename = new char [gui->mOutputFilepath.size() + 1];
  memcpy(pod->output_filename, gui->mOutputFilepath.c_str(), gui->mOutputFilepath.size() + 1);

  pod->input_filename_size  = gui->mInputFilepath.size();
  pod->output_filename_size = gui->mOutputFilepath.size();

  switch (gui->mMode)
   {
    case Mode::ENCRYPT:
      gui->encrypt();
      break;
    case Mode::DECRYPT:
      gui->decrypt();
      break;
   }
 }

void
Gui::onPasswordEntryActivate(GtkWidget* pwe, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  if (gui->mMode == Mode::DECRYPT)
    g_signal_emit_by_name(
     gui->mStartButton,
     "clicked",
     gui);
 }

void
Gui::onReentryEntryActivate(GtkWidget* ree, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  if (gui->mMode == Mode::ENCRYPT)
    g_signal_emit_by_name(
     gui->mStartButton,
     "clicked",
     gui);
 }

void
Gui::onExpertModeCheckbuttonToggled(GtkWidget* emc, void* self)
 {
  Gui*           gui       {static_cast<Gui*>(self)};
  const gboolean is_active {gtk_check_button_get_active(GTK_CHECK_BUTTON(emc))};
  switch (gui->mMode)
   {
    case Mode::ENCRYPT:
      gtk_widget_set_visible(gui->mEncryptParamBox, is_active);
      gtk_widget_set_visible(gui->mDecryptParamBox, FALSE);
      break;
    case Mode::DECRYPT:
      gtk_widget_set_visible(gui->mEncryptParamBox, FALSE);
      gtk_widget_set_visible(gui->mDecryptParamBox, is_active);
      break;
   }
 }

void
Gui::onInputTextActivate(GtkWidget* text, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};

  GtkEntryBuffer* buffer {gtk_text_get_buffer(GTK_TEXT(text))};
  gui->mInputFilepath = gtk_entry_buffer_get_text(buffer);
  gui->onInputFilepathUpdated();
 }

void
Gui::onOutputTextActivate(GtkWidget* text, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};

  GtkEntryBuffer* buffer {gtk_text_get_buffer(GTK_TEXT(text))};
  gui->mOutputFilepath = gtk_entry_buffer_get_text(buffer);
  gui->mOutputTextActivated = true;
 }

bool
Gui::verifyInputs(void)
 {
  mStatusIsBlinkingMtx.lock();
  mStatusIsBlinking = false;
  mStatusIsBlinkingMtx.unlock();
  // Get the input text data.
  GtkEntryBuffer* text_buffer {
   gtk_text_get_buffer(GTK_TEXT(mInputText))
  };
  const char* filepath_cstr {
   gtk_entry_buffer_get_text(text_buffer)
  };
  std::string filepath {filepath_cstr};
  make_os_path(filepath);
  mInputFilepath = filepath;

  //TODO: Explain to the user that it's invalid for the input file to not exist.
  if (!SSC_FilePath_exists(filepath.c_str()))
   {
    std::fprintf(stderr, "%s did not exist!\n", filepath.c_str());
    return false;
   }

  // Get the output text data.
  text_buffer   = gtk_text_get_buffer(GTK_TEXT(mOutputText));
  filepath_cstr = gtk_entry_buffer_get_text(text_buffer);
  filepath      = filepath_cstr;
  make_os_path(filepath);
  mOutputFilepath = filepath;

  //TODO: Explain to the user that it's invalid for the output file to already exist.
  if (SSC_FilePath_exists(filepath.c_str()))
   {
    std::fprintf(stderr, "%s already exists!\n", filepath.c_str());
    return false;
   }
  return true;
 }

void
Gui::onInputFilepathUpdated(void)
 {
   bool output_filepath_updated {};
   std::printf("onInputFilepathUpdated() called with mode %i\n", (int)mMode);
   switch (mMode)
    {
     case Mode::NONE:
      {
       // The user has chosen an input filepath before selecting a mode.
       // Assume the mode will be ENCRYPT when the filepath doesn't end in ".4c".
       // Assume the mode will be DECRYPT when the filepath does end in ".4c".
       // Do not make an assumption if the user has specified an output filepath.
       if (not mOutputTextActivated)
        {
         if (str_ends_with(mInputFilepath, ".4c"))
           setMode(Mode::DECRYPT);
         else
           setMode(Mode::ENCRYPT);
         onInputFilepathUpdated();
        }
      } break;
     case Mode::ENCRYPT:
      {
       // The input filepath was set during encrypt mode. Assume that the output filepath
       // will be the same as the input filepath, but with ".4c" appended.
       std::string ofp {mInputFilepath + ".4c"};
       if (not SSC_FilePath_exists(ofp.c_str()))
        {
         mOutputFilepath = std::move(ofp);
         output_filepath_updated = true;
        }
      } break;
     case Mode::DECRYPT:
      {
       //TODO: The input filepath was set during decrypt mode. Assume that the output filepath
       // will be the same as the input filepath, but with ".4c" removed. (Assuming it ended in ".4c").
       if (str_ends_with(mInputFilepath, ".4c"))
        {
         std::string ofp {mInputFilepath};
         ofp.erase(ofp.end() - 3, ofp.end());
         if (not SSC_FilePath_exists(ofp.c_str()))
          {
           mOutputFilepath = std::move(ofp);
           output_filepath_updated = true;
          }
        }
      } break;
    }
   // After mode-specific updates, update the text in the text boxes.
   std::printf("input_filepath was %s\n", mInputFilepath.c_str());
   std::printf("output_filepath was %s\n", mOutputFilepath.c_str());
   GtkEntryBuffer* buffer {gtk_text_get_buffer(GTK_TEXT(mInputText))};
   gtk_entry_buffer_set_text(
    buffer,
    mInputFilepath.c_str(),
    mInputFilepath.size());
   if (output_filepath_updated)
     onOutputFilepathUpdated();
 }

void
Gui::onOutputFilepathUpdated(void)
 {
  std::printf("onOutputFilepathUpdated() called with mode %i\n", (int)mMode);
  GtkEntryBuffer* buffer {gtk_text_get_buffer(GTK_TEXT(mOutputText))};
  gtk_entry_buffer_set_text(buffer, mOutputFilepath.c_str(), mOutputFilepath.size());
 }

bool
Gui::getPassword(void)
 {
  const char* pw_0 {gtk_editable_get_text(GTK_EDITABLE(mPasswordEntry))};
  const char* pw_1 {gtk_editable_get_text(GTK_EDITABLE(mReentryEntry))};
  size_t pw_0_len {std::strlen(pw_0)};
  size_t pw_1_len {std::strlen(pw_1)};
  if (pw_0_len >= Core::MAX_PW_BYTES)
   {
    std::fprintf(stderr, "Error: Input password length %zu exceeds maximum, %zu.\n", pw_0_len, Core::MAX_PW_BYTES);
    return false;
   }
  if (pw_1_len >= Core::MAX_PW_BYTES)
   {
    std::fprintf(stderr, "Error: Password Re-Entry length %zu exceeds maximum, %zu.\n", pw_1_len, Core::MAX_PW_BYTES);
    return false;
   }
  bool equal {(pw_0_len == pw_1_len) and (not std::strcmp(pw_0, pw_1))};
  memset(mPod->password_buffer, 0, sizeof(mPod->password_buffer));

  if (pw_0_len == 0)
    return false;
  switch (mMode)
   {
    case Mode::ENCRYPT:
      // ENCRYPT mode requires that we get the same password input at least twice.
      if (not equal)
        return false;
      memcpy(mPod->password_buffer, pw_0, pw_0_len);
      mPod->password_size = pw_0_len;
      break;
    case Mode::DECRYPT:
      memcpy(mPod->password_buffer, pw_0, pw_0_len);
      mPod->password_size = pw_0_len;
      break;
   }
  return true;
 }

void
Gui::clearPasswordEntries(void)
 {
  GtkEditable* e {GTK_EDITABLE(mPasswordEntry)};
  gtk_editable_delete_text(e, 0, -1);
  e = GTK_EDITABLE(mReentryEntry);
  gtk_editable_delete_text(e, 0, -1);
 }

void
Gui::setStatusLabelSuccess(bool is_successful)
 {
  if (is_successful)
   {
    gtk_label_set_text(GTK_LABEL(mStatusLabel), "Success!");
    if (gtk_widget_has_css_class(mStatusLabel, "failure"))
      gtk_widget_remove_css_class(mStatusLabel, "failure");
    gtk_widget_add_css_class(mStatusLabel, "success");
   }
  else
   {
    gtk_label_set_text(GTK_LABEL(mStatusLabel), "Failure!");
    if (gtk_widget_has_css_class(mStatusLabel, "success"))
      gtk_widget_remove_css_class(mStatusLabel, "success");
    gtk_widget_add_css_class(mStatusLabel, "failure");
   }
 }

void
Gui::onApplicationActivate(GtkApplication* gtk_app, void* self)
 {
  // Create the application window.
  Gui* gui {static_cast<Gui*>(self)};
  gui->initApplicationWindow();
  
  // Create the grid and configure it.
  gui->initGrid();

  // Add the Core dragon logo.
  gui->initLogoImage();

  // Create the Encrypt and Decrypt buttons.
  gui->initCryptButtons();

  gui->initStrengthBox();

  gui->mExpertModeCheckbutton = gtk_check_button_new();
  gtk_check_button_set_label(GTK_CHECK_BUTTON(gui->mExpertModeCheckbutton), "Expert Mode");
  gtk_widget_set_tooltip_text(
   gui->mExpertModeCheckbutton,
   "Enables Expert Mode, where you may get specific with your selection of encryption/decryption parameters.");
  g_signal_connect(gui->mExpertModeCheckbutton, "toggled", G_CALLBACK(onExpertModeCheckbuttonToggled), gui);


  // Create a Box for input.
  gui->initInputBox();

  // Create a Box for output.
  gui->initOutputBox();

  // Create a Box for encryption parameter entry.
  gui->initEncryptParamBox();

  // Create a Box for decryption parameter entry.
  gui->initDecryptParamBox();

  // Create a Box for passwords.
  gui->initPasswordBox();

  // Create a Box for re-entering passwords.
  gui->initReentryBox();

  gui->initStatusBox();

  // Initialize the start button.
  gui->mStartButton= gtk_button_new_with_label("Start");
  g_signal_connect(gui->mStartButton, "clicked", G_CALLBACK(onStartButtonClicked), gui);

  // Initialize the progress box and its bar.
  gui->initProgressBox();

  // Initialize the grid.
  gui->attachGrid();

  gtk_window_present(GTK_WINDOW(gui->mApplicationWindow));
 }

int
Gui::run(void)
 {
  mApplication = gtk_application_new("cc.calder.fourcrypt", G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect(mApplication, "activate", G_CALLBACK(onApplicationActivate), this);
  int run_result {g_application_run(G_APPLICATION(mApplication), mArgc, mArgv)};
  if (run_result != 0)
    fprintf(stderr, "Error: g_application_run() returned %i!\n", run_result);
  return run_result;
 }

void
Gui::initApplicationWindow(void)
 {
  mApplicationWindow = gtk_application_window_new(mApplication);
  gtk_window_set_title(GTK_WINDOW(mApplicationWindow), "4crypt");
  gtk_widget_set_size_request(mApplicationWindow, WINDOW_WIDTH, WINDOW_HEIGHT);
  gtk_widget_set_hexpand(mApplicationWindow, FALSE);
  gtk_widget_set_vexpand(mApplicationWindow, FALSE);
 }

void
Gui::initGrid(void)
 {
  mGrid = gtk_grid_new();
  gtk_widget_set_valign(mGrid, GTK_ALIGN_START);
  gtk_window_set_child(GTK_WINDOW(mApplicationWindow), mGrid);
  gtk_grid_set_column_homogeneous(GTK_GRID(mGrid), TRUE);
 }

void
Gui::initLogoImage(void)
 {
  std::string logo_path {getResourcePath() + "/logo.png"};
  make_os_path(logo_path);
  mLogoImage = gtk_image_new_from_file(logo_path.c_str());
  gtk_image_set_icon_size(GTK_IMAGE(mLogoImage), GTK_ICON_SIZE_LARGE);
  gtk_widget_set_size_request(mLogoImage, FOURCRYPT_IMG_WIDTH, FOURCRYPT_IMG_HEIGHT);
  gtk_widget_set_hexpand(mLogoImage, TRUE);
  gtk_widget_set_vexpand(mLogoImage, TRUE);
  gtk_widget_set_tooltip_text(mLogoImage, "4crypt");
 }

void
Gui::initCryptButtons(void)
 {
  mEncryptButton = gtk_button_new_with_label("Encrypt");
  g_signal_connect(mEncryptButton, "clicked", G_CALLBACK(onEncryptButtonClicked), this);
  gtk_widget_set_tooltip_text(mEncryptButton, "Encrypt a file using a password.");

  mDecryptButton = gtk_button_new_with_label("Decrypt");
  g_signal_connect(mDecryptButton, "clicked", G_CALLBACK(onDecryptButtonClicked), this);
  gtk_widget_set_tooltip_text(mDecryptButton, "Decrypt a file using a password.");
 }

void
Gui::initStrengthBox(void)
 {
  mStrengthBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);

  mStrengthFastCheckbutton = gtk_check_button_new();
  gtk_check_button_set_label(GTK_CHECK_BUTTON(mStrengthFastCheckbutton), "Fast");
  gtk_widget_set_tooltip_text(
   mStrengthFastCheckbutton,
   "Choose Fast encryption parameters.");
  g_signal_connect(mStrengthFastCheckbutton, "toggled", G_CALLBACK(onStrengthFastCheckbuttonToggled), this);
  gtk_widget_set_visible(mStrengthFastCheckbutton, FALSE);

  mStrengthStandardCheckbutton = gtk_check_button_new();
  gtk_check_button_set_label(GTK_CHECK_BUTTON(mStrengthStandardCheckbutton), "Standard");
  gtk_widget_set_tooltip_text(
   mStrengthStandardCheckbutton,
   "Choose Standard encryption parameters.");
  g_signal_connect(mStrengthStandardCheckbutton, "toggled", G_CALLBACK(onStrengthStandardCheckbuttonToggled), this);
  gtk_widget_set_visible(mStrengthStandardCheckbutton, FALSE);
  gtk_check_button_set_active(GTK_CHECK_BUTTON(mStrengthStandardCheckbutton), TRUE);

  mStrengthStrongCheckbutton = gtk_check_button_new();
  gtk_check_button_set_label(GTK_CHECK_BUTTON(mStrengthStrongCheckbutton), "Strong");
  gtk_widget_set_tooltip_text(
   mStrengthStrongCheckbutton,
   "Choose Strong encryption parameters.");
  g_signal_connect(mStrengthStrongCheckbutton, "toggled", G_CALLBACK(onStrengthStrongCheckbuttonToggled), this);
  gtk_widget_set_visible(mStrengthStrongCheckbutton, FALSE);

  mStrengthExpertCheckbutton = gtk_check_button_new();
  gtk_check_button_set_label(GTK_CHECK_BUTTON(mStrengthExpertCheckbutton), "Expert Mode");
  gtk_widget_set_tooltip_text(
   mStrengthExpertCheckbutton,
   "Enables Expert Mode, where you may get specific with your selection of encryption/decryption parameters.");
  g_signal_connect(mStrengthExpertCheckbutton, "toggled", G_CALLBACK(onStrengthExpertCheckbuttonToggled), this);

  gtk_box_append(GTK_BOX(mStrengthBox), mStrengthFastCheckbutton);
  gtk_box_append(GTK_BOX(mStrengthBox), mStrengthStandardCheckbutton);
  gtk_box_append(GTK_BOX(mStrengthBox), mStrengthStrongCheckbutton);
  gtk_box_append(GTK_BOX(mStrengthBox), mStrengthExpertCheckbutton);
 }

void
Gui::onStrengthFastCheckbuttonToggled(GtkWidget* sfc, void* vgui)
 {
  Gui*           gui       {static_cast<Gui*>(vgui)};
  const gboolean is_active {gtk_check_button_get_active(GTK_CHECK_BUTTON(sfc))};

  if constexpr(Debug)
   {
    if (is_active and gui->mMode != Mode::ENCRYPT)
      std::fprintf(stderr, "Error: strength_fast_checkbutton activated and it's not encrypt mode!");
   }
  if (is_active)
   {
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthStandardCheckbutton), FALSE);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthStrongCheckbutton),   FALSE);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthExpertCheckbutton),   FALSE);
    gtk_widget_set_visible(gui->mEncryptParamBox, FALSE);
   }
 }
void
Gui::onStrengthStandardCheckbuttonToggled(GtkWidget* ssc, void* vgui)
 {
  Gui*           gui       {static_cast<Gui*>(vgui)};
  const gboolean is_active {gtk_check_button_get_active(GTK_CHECK_BUTTON(ssc))};

  if constexpr(Debug)
   {
    static int num {};
    if (is_active and gui->mMode != Mode::ENCRYPT)
     {
      ++num;
      if (num > 1)
       {
        std::fprintf(stderr, "Error: strength_standard_checkbutton activated and it's not encrypt mode!");
       }
     }
   }

  if (is_active)
   {
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthFastCheckbutton)  , FALSE);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthStrongCheckbutton), FALSE);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthExpertCheckbutton), FALSE);
    gtk_widget_set_visible(gui->mEncryptParamBox, FALSE);
   }
 }
void
Gui::onStrengthStrongCheckbuttonToggled(GtkWidget* ssc, void* vgui)
 {
  Gui*           gui       {static_cast<Gui*>(vgui)};
  const gboolean is_active {gtk_check_button_get_active(GTK_CHECK_BUTTON(ssc))};

  if constexpr(Debug)
   {
    if (is_active and gui->mMode != Mode::ENCRYPT)
      std::fprintf(stderr, "Error: strength_strong_checkbutton activated and it's not encrypt mode!");
   }
  if (is_active)
   {
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthFastCheckbutton)    , FALSE);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthStandardCheckbutton), FALSE);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthExpertCheckbutton)  , FALSE);
    gtk_widget_set_visible(gui->mEncryptParamBox, FALSE);
   }
 }
void
Gui::onStrengthExpertCheckbuttonToggled(GtkWidget* sec, void* vgui)
 {
  Gui*           gui       {static_cast<Gui*>(vgui)};
  const gboolean is_active {gtk_check_button_get_active(GTK_CHECK_BUTTON(sec))};

  if (is_active)
   {
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthFastCheckbutton)    , FALSE);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthStandardCheckbutton), FALSE);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(gui->mStrengthStrongCheckbutton)  , FALSE);
   }
  switch (gui->mMode)
   {
    case Mode::ENCRYPT:
      gtk_widget_set_visible(gui->mEncryptParamBox, is_active);
      gtk_widget_set_visible(gui->mDecryptParamBox, FALSE);
      break;
    case Mode::DECRYPT:
      gtk_widget_set_visible(gui->mEncryptParamBox, FALSE);
      gtk_widget_set_visible(gui->mDecryptParamBox, is_active);
      break;
   }
 }

void
Gui::initInputBox(void)
 {
  mInputBox    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  mInputLabel  = gtk_label_new(" Input:");
  mInputText   = gtk_text_new();
  gtk_widget_add_css_class(mInputText, "basic");
  gtk_widget_set_tooltip_text(mInputText, "Enter an input file path.");
  mInputButton = gtk_button_new_with_label("Pick File");
  gtk_widget_set_tooltip_text(mInputButton, "Choose an input file path from the filesystem.");
  g_signal_connect(mInputText  , "activate", G_CALLBACK(onInputTextActivate) , this);
  g_signal_connect(mInputButton, "clicked" , G_CALLBACK(onInputButtonClicked), this);
  // Fill the box with a label and text.
  gtk_box_append(GTK_BOX(mInputBox), mInputLabel);
  gtk_box_append(GTK_BOX(mInputBox), mInputText);
  gtk_box_append(GTK_BOX(mInputBox), mInputButton);
  gtk_widget_set_size_request(mInputBox, -1, TEXT_HEIGHT);
  gtk_widget_set_hexpand(mInputText, TRUE);
 }

void
Gui::initOutputBox(void)
 {
  mOutputBox    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  mOutputLabel  = gtk_label_new("Output:");
  mOutputText   = gtk_text_new();
  gtk_widget_add_css_class(mOutputText, "basic");
  gtk_widget_set_tooltip_text(mOutputText, "Enter an output file path.");
  mOutputButton = gtk_button_new_with_label("Pick File");
  gtk_widget_set_tooltip_text(mOutputButton, "Choose an output file path from the filesystem.");
  g_signal_connect(mOutputText  , "activate", G_CALLBACK(onOutputTextActivate) , this);
  g_signal_connect(mOutputButton, "clicked" , G_CALLBACK(onOutputButtonClicked), this);
  // Fill the box with a label and text.
  gtk_box_append(GTK_BOX(mOutputBox), mOutputLabel);
  gtk_box_append(GTK_BOX(mOutputBox), mOutputText);
  gtk_box_append(GTK_BOX(mOutputBox), mOutputButton);
  gtk_widget_set_size_request(mOutputBox, -1, TEXT_HEIGHT);
  gtk_widget_set_hexpand(mOutputText, TRUE);
 }

void
Gui::initEncryptParamBox(void)
 {
  mEncryptParamBox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
  mEncryptParamPhiCheckbutton = gtk_check_button_new();
  gtk_check_button_set_label(GTK_CHECK_BUTTON(mEncryptParamPhiCheckbutton), "Enable Phi");
  gtk_widget_set_tooltip_text(
   mEncryptParamPhiCheckbutton,
   "WARNING: This enables the Phi function. "
   "Enabling the Phi function hardens 4crypt's Key Derivation Function, "
   "greatly increasing the work necessary to attack your password with "
   "brute force, but introduces the potential for cache-timing attacks. "
   "Do NOT use this feature unless you understand the security implications!");
  mEncryptParamMemoryDropdown = gtk_drop_down_new_from_strings(memoryUsageStrings);
  gtk_widget_set_tooltip_text(
   mEncryptParamMemoryDropdown,
   "Choose how much RAM each thread of the Key Derivation Function should consume on Encrypt/Decrypt operations. "
   "Choosing more RAM will make the operation slower, but provide more security against brute force attacks.");
  // Iterations Box.
  mEncryptParamIterationsBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  mEncryptParamIterationsLabel = gtk_label_new("   Iterations:      ");
  mEncryptParamIterationsText = gtk_text_new();
  gtk_widget_add_css_class(mEncryptParamIterationsText, "basic");
  gtk_widget_set_tooltip_text(
   mEncryptParamIterationsText,
   "Choose how many times each thread of the Key Derivation Function will iterate. "
   "Increasing this value will linearly increase the amount of time and work necessary "
   "for each Key Derivation Function thread, linearly increasing the cost of a brute "
   "force attack.");
  gtk_box_append(GTK_BOX(mEncryptParamIterationsBox), mEncryptParamIterationsLabel);
  gtk_box_append(GTK_BOX(mEncryptParamIterationsBox), mEncryptParamIterationsText);

  GtkEntryBuffer* entry {gtk_text_get_buffer(GTK_TEXT(mEncryptParamIterationsText))};
  gtk_entry_buffer_set_text(entry, "1", 1);

  // Threads Box.
  mEncryptParamThreadBox   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  mEncryptParamThreadLabel = gtk_label_new(" Thread Count:      ");
  mEncryptParamThreadText  = gtk_text_new();
  gtk_widget_add_css_class(mEncryptParamThreadText, "basic");
  gtk_widget_set_tooltip_text(
   mEncryptParamThreadText,
   "Choose how many parallel threads the Key Derivation Function will use. "
   "Increasing this value will multiply the amount of RAM used for key "
   "derivation. Be aware.");
  gtk_box_append(GTK_BOX(mEncryptParamThreadBox), mEncryptParamThreadLabel);
  gtk_box_append(GTK_BOX(mEncryptParamThreadBox), mEncryptParamThreadText);

  entry = gtk_text_get_buffer(GTK_TEXT(mEncryptParamThreadText));
  gtk_entry_buffer_set_text(entry, "1", 1);

  // Batch size.
  mEncryptParamBatchSizeBox   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  mEncryptParamBatchSizeLabel = gtk_label_new(" Thread Batch Size: ");
  mEncryptParamBatchSizeText  = gtk_text_new();
  gtk_widget_add_css_class(mEncryptParamBatchSizeText, "basic");
  gtk_widget_set_tooltip_text(
   mEncryptParamBatchSizeText,
   "Choose how many Key Derivation Function threads shall be executed in parallel."
   "If this number is less than the total number of KDF threads to execute, said "
   "threads shall be executed sequentially in batches.");
  gtk_box_append(GTK_BOX(mEncryptParamBatchSizeBox), mEncryptParamBatchSizeLabel);
  gtk_box_append(GTK_BOX(mEncryptParamBatchSizeBox), mEncryptParamBatchSizeText);

  entry = gtk_text_get_buffer(GTK_TEXT(mEncryptParamBatchSizeText));
  gtk_entry_buffer_set_text(entry, "1", 1);

  // Fill the box.
  gtk_box_append(GTK_BOX(mEncryptParamBox), mEncryptParamPhiCheckbutton);
  gtk_box_append(GTK_BOX(mEncryptParamBox), mEncryptParamMemoryDropdown);
  gtk_box_append(GTK_BOX(mEncryptParamBox), mEncryptParamIterationsBox);
  gtk_box_append(GTK_BOX(mEncryptParamBox), mEncryptParamThreadBox);
  gtk_box_append(GTK_BOX(mEncryptParamBox), mEncryptParamBatchSizeBox);
  gtk_widget_set_visible(mEncryptParamBox, FALSE);
 }

void
Gui::initDecryptParamBox(void)
 {
  mDecryptParamBox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
  mDecryptParamBatchSizeBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  mDecryptParamBatchSizeLabel = gtk_label_new(" TBS: ");
  mDecryptParamBatchSizeText  = gtk_text_new();
  gtk_widget_add_css_class(mDecryptParamBatchSizeText, "basic");
  gtk_widget_set_tooltip_text(
   mDecryptParamBatchSizeText,
   "Choose how many Key Derivation Function threads shall be executed in parallel."
   "If this number is less than the total number of KDF threads to execute, said "
   "threads shall be executed sequentially in batches.");

  GtkEntryBuffer* eb {gtk_text_get_buffer(GTK_TEXT(mDecryptParamBatchSizeText))};
  gtk_entry_buffer_set_text(eb, "1", 1);

  gtk_box_append(GTK_BOX(mDecryptParamBox),          mDecryptParamBatchSizeBox);
  gtk_box_append(GTK_BOX(mDecryptParamBatchSizeBox), mDecryptParamBatchSizeLabel);
  gtk_box_append(GTK_BOX(mDecryptParamBatchSizeBox), mDecryptParamBatchSizeText);
  gtk_widget_set_visible(mDecryptParamBox, FALSE);
 }

void
Gui::initPasswordBox(void)
 {
  mPasswordBox   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  mPasswordLabel = gtk_label_new("Password:");
  mPasswordEntry = gtk_password_entry_new();
  gtk_widget_set_tooltip_text(mPasswordEntry, "Enter the password here.");
  g_signal_connect(mPasswordEntry, "activate", G_CALLBACK(onPasswordEntryActivate), this);
  gtk_box_append(GTK_BOX(mPasswordBox), mPasswordLabel);
  gtk_box_append(GTK_BOX(mPasswordBox), mPasswordEntry);
  gtk_widget_set_size_request(mPasswordBox, -1, TEXT_HEIGHT);
  gtk_widget_set_hexpand(mPasswordBox,   TRUE);
  gtk_widget_set_hexpand(mPasswordEntry, TRUE);
  gtk_widget_set_visible(mPasswordBox,   FALSE);
  gtk_editable_set_max_width_chars(GTK_EDITABLE(mPasswordEntry), Core::MAX_PW_BYTES);
 }

void
Gui::initReentryBox(void)
 {
  mReentryBox   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  mReentryLabel = gtk_label_new("Re-Entry:");
  mReentryEntry = gtk_password_entry_new();
  gtk_widget_set_tooltip_text(mReentryEntry, "Re-enter the password here, to check for consistency.");
  g_signal_connect(mReentryEntry, "activate", G_CALLBACK(onReentryEntryActivate), this);
  gtk_box_append(GTK_BOX(mReentryBox), mReentryLabel);
  gtk_box_append(GTK_BOX(mReentryBox), mReentryEntry);
  gtk_widget_set_size_request(mReentryBox, -1, TEXT_HEIGHT);
  gtk_widget_set_hexpand(mReentryBox,   TRUE);
  gtk_widget_set_hexpand(mReentryEntry, TRUE);
  gtk_widget_set_visible(mReentryBox,   FALSE);
  gtk_editable_set_max_width_chars(GTK_EDITABLE(mReentryEntry), Core::MAX_PW_BYTES);
 }

void
Gui::initStatusBox(void)
 {
  mStatusBox   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  mStatusLabel = gtk_label_new("Success!");
  gtk_box_append(GTK_BOX(mStatusBox), mStatusLabel);
  gtk_widget_add_css_class(mStatusLabel, "success");
  gtk_widget_set_hexpand(mStatusBox, TRUE);
  gtk_widget_set_hexpand(mStatusLabel, TRUE);
  gtk_widget_set_valign(mStatusBox, GTK_ALIGN_CENTER);
  gtk_widget_set_halign(mStatusBox, GTK_ALIGN_CENTER);
  gtk_widget_set_visible(mStatusBox, FALSE);
 }

void
Gui::initProgressBox(void)
 {
  mProgressBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  mProgressBar = gtk_progress_bar_new();
  gtk_widget_set_hexpand(mProgressBar, TRUE);
  gtk_box_append(GTK_BOX(mProgressBox), mProgressBar);
  // Set the pulse of progress for each step of progress
  gtk_progress_bar_set_pulse_step(GTK_PROGRESS_BAR(mProgressBar), PROGRESS_PULSE_STEP);
  gtk_widget_set_hexpand(mProgressBox, TRUE);
  gtk_widget_set_vexpand(mProgressBox, TRUE);
  gtk_widget_set_visible(mProgressBox, FALSE);
 }

void
Gui::attachGrid(void)
 {
  int gridIdx_Y {0};
  GtkGrid* grid {GTK_GRID(mGrid)};

  // Attach the widgets to the grid according to the following syntax:
  gtk_grid_attach(grid, mLogoImage, 0, gridIdx_Y, 4, 1);
  ++gridIdx_Y;

  gtk_grid_attach(grid, mEncryptButton, 0, gridIdx_Y, 2, 1);
  gtk_grid_attach(grid, mDecryptButton, 2, gridIdx_Y, 2, 1);
  ++gridIdx_Y;

  gtk_grid_attach(grid, mStrengthBox, 0, gridIdx_Y, 4, 1);
  ++gridIdx_Y;

  gtk_grid_attach(grid, mEncryptParamBox, 0, gridIdx_Y, 4, 1);
  ++gridIdx_Y;
  
  gtk_grid_attach(grid, mDecryptParamBox, 0, gridIdx_Y, 4, 1);
  ++gridIdx_Y;

  gtk_grid_attach(grid, mInputBox  , 0, gridIdx_Y, 4, 1);
  ++gridIdx_Y;

  gtk_grid_attach(grid, mOutputBox  , 0, gridIdx_Y, 4, 1);
  ++gridIdx_Y;

  gtk_grid_attach(grid, mPasswordBox, 0, gridIdx_Y, 4, 1);
  ++gridIdx_Y;

  gtk_grid_attach(grid, mReentryBox, 0, gridIdx_Y, 4, 1);
  ++gridIdx_Y;

  gtk_grid_attach(grid, mStartButton, 0, gridIdx_Y, 4, 1);
  ++gridIdx_Y;

  gtk_grid_attach(grid, mProgressBox, 0, gridIdx_Y, 4, 1);
  ++gridIdx_Y;

  gtk_grid_attach(grid, mStatusBox, 0, gridIdx_Y, 4, 1);
  ++gridIdx_Y;

  // Set the grid as a child of the application window, then present the application window.
  gtk_window_set_child(GTK_WINDOW(mApplicationWindow), mGrid);
 }

void
Gui::setMode(Mode m)
 {
  mStatusIsBlinkingMtx.lock();
  mStatusIsBlinking = false;
  mStatusIsBlinkingMtx.unlock();
  if (gtk_widget_has_css_class(mEncryptButton, "highlight"))
    gtk_widget_remove_css_class(mEncryptButton, "highlight");
  if (gtk_widget_has_css_class(mDecryptButton, "highlight"))
    gtk_widget_remove_css_class(mDecryptButton, "highlight");
  mMode = m;
  const gboolean expert_mode {gtk_check_button_get_active(GTK_CHECK_BUTTON(mStrengthExpertCheckbutton))};
  switch (mMode)
   {
    case Mode::ENCRYPT:
      gtk_widget_add_css_class(mEncryptButton, "highlight");
      gtk_widget_set_visible(mPasswordBox,      TRUE);
      gtk_widget_set_visible(mReentryBox,       TRUE);
      gtk_widget_set_visible(mEncryptParamBox,  expert_mode);
      gtk_widget_set_visible(mStrengthStrongCheckbutton,   TRUE);
      gtk_widget_set_visible(mStrengthStandardCheckbutton, TRUE);
      gtk_widget_set_visible(mStrengthFastCheckbutton, TRUE);
      gtk_widget_set_visible(mDecryptParamBox, FALSE);
      break;
    case Mode::DECRYPT:
      gtk_widget_add_css_class(mDecryptButton, "highlight");
      gtk_widget_set_visible(mPasswordBox,     TRUE);
      gtk_widget_set_visible(mReentryBox,      FALSE);
      gtk_widget_set_visible(mEncryptParamBox, FALSE);
      gtk_widget_set_visible(mStrengthStrongCheckbutton,   FALSE);
      gtk_widget_set_visible(mStrengthStandardCheckbutton, FALSE);
      gtk_widget_set_visible(mStrengthFastCheckbutton, FALSE);
      gtk_widget_set_visible(mDecryptParamBox, expert_mode);
      break;
    case Mode::NONE:
      mOutputTextActivated = false;
      gtk_widget_set_visible(mPasswordBox,     FALSE);
      gtk_widget_set_visible(mReentryBox,      FALSE);
      gtk_widget_set_visible(mEncryptParamBox, FALSE);
      gtk_widget_set_visible(mStrengthStrongCheckbutton, FALSE);
      gtk_widget_set_visible(mStrengthStandardCheckbutton, FALSE);
      gtk_widget_set_visible(mStrengthFastCheckbutton, FALSE);
      gtk_widget_set_visible(mDecryptParamBox, FALSE);

      GtkEntryBuffer* eb {gtk_text_get_buffer(GTK_TEXT(mInputText))};
      gtk_entry_buffer_delete_text(eb, 0, -1); // Delete all text.
      eb = gtk_text_get_buffer(GTK_TEXT(mOutputText));
      gtk_entry_buffer_delete_text(eb, 0, -1); // Delete all text.

      GtkEditable* editable {GTK_EDITABLE(mPasswordEntry)};
      gtk_editable_delete_text(editable, 0, -1); // Delete all text.
      editable = GTK_EDITABLE(mReentryEntry);
      gtk_editable_delete_text(editable, 0, -1); // Delete all text.

      gtk_widget_set_visible(GTK_WIDGET(mPasswordBox), FALSE);
      gtk_widget_set_visible(GTK_WIDGET(mReentryBox),  FALSE);
      break;
   }
 }

int main(
 int   argc,
 char* argv[])
 {
  Core core {};
  Gui  gui  {&core, argc, argv};

  return gui.run();
 }
