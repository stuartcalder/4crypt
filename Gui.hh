/* *
 * 4crypt - Memory-Hard Symmetric File Encryption Program
 * Copyright (C) 2025 Stuart Calder
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#ifndef FOURCRYPT_GUI_HH
#define FOURCRYPT_GUI_HH

// Local
#include "Core.hh"
// GTK4
#include <gtk/gtk.h>
// C++ STL
#include <mutex>
#include <string>

#define FOURCRYPT_SLASH_CHAR_UNIXLIKE '/'
#define FOURCRYPT_SLASH_CHAR_WINDOWS  '\\'

// OS-specific binary names.
#if   defined(SSC_OS_UNIXLIKE)
 #define FOURCRYPT_GUI_BINARY        "g4crypt"
 #define FOURCRYPT_GUI_BINARY_LENGTH 7
 #define FOURCRYPT_SLASH_CHAR_OS     FOURCRYPT_SLASH_CHAR_UNIXLIKE
#elif defined(SSC_OS_WINDOWS)
 #define FOURCRYPT_GUI_BINARY        "g4crypt.exe"
 #define FOURCRYPT_GUI_BINARY_LENGTH 11
 #define FOURCRYPT_SLASH_CHAR_OS     FOURCRYPT_SLASH_CHAR_WINDOWS
#else
 #error "Unsupported OS".
#endif

#if !defined(FOURCRYPT_IS_PORTABLE) && !defined(__gnu_linux__)
 #error "Unsupported! Not Portable or GNU/Linux!"
#endif

namespace fourcrypt {

void make_os_path(std::string& str);

class Gui
 {
 public:
 // Public Types //
  using Pod_t = Core::PlainOldData;
 // Public Constants //
  enum class Mode
   {
    NONE, ENCRYPT, DECRYPT
   };
  static constexpr double PROGRESS_PULSE_STEP {0.14285714285714285}; //FIXME: Fraction of total number of steps.
  static constexpr int    TEXT_HEIGHT {20};
 // Public Static Procedures //
  #ifdef FOURCRYPT_IS_PORTABLE
  static std::string getExecutablePath(void);
  static std::string getExecutableDirPath(void);
  #endif
  static std::string getResourcePath(void);
 // Constructors //
  Gui(Core* param_core, int param_argc, char** param_argv);
 // Destructor //
  ~Gui();
 // Public Methods //
  int run(void);
 private:
 // Private Data //
  std::string      mInputFilepath  {};
  std::string      mOutputFilepath {};
  std::mutex       mOperationIsOngoingMtx {};
  std::mutex       mStatusIsBlinkingMtx   {};
  std::mutex       mOperationMtx        {};
  bool             mOperationIsOngoing  {};
  bool             mStatusIsBlinking    {};
  struct OpData {
    SSC_CodeError_t code_error {0};
    Core::ErrType   error_type {Core::ErrType::CORE};
    Core::InOutDir  in_out_dir {Core::InOutDir::NONE};
  } mOperationData {};

  GtkApplication* mApplication {};
  GtkFileDialog*  mFileDialog  {};       // Input & Output file dialogs.
  GtkAlertDialog* mAlertDialog {};       // Dialog for errors.

  GtkWidget*      mApplicationWindow {}; // Main window for displaying stuff.
  GtkWidget*      mGrid {};              // Organize UI elements using cells.
  GtkWidget*      mLogoImage {};         // Blue Dragon.
  GtkWidget*      mEncryptButton {};     // Click me to switch to encrypt mode.
  GtkWidget*      mDecryptButton {};     // Click me to switch to decrypt mode.

  GtkWidget*      mStrengthBox   {};
  GtkWidget*      mStrengthFastCheckbutton     {};
  GtkWidget*      mStrengthStandardCheckbutton {};
  GtkWidget*      mStrengthStrongCheckbutton   {};
  GtkWidget*      mStrengthExpertCheckbutton   {};
  GtkWidget*      mExpertModeCheckbutton       {}; // Click me to enable/disable expert-level parameter selection.
  GtkWidget*      mStartButton {};     // Click me to begin encrypting/decrypting.

  GtkWidget*      mProgressBox {};     // Contain the progress bar.
  GtkWidget*      mProgressBar {};     // I track the progress of encryption/decryption.

  GtkWidget*      mInputBox    {};       // Contain the Label, Text, & Button for input.
  GtkWidget*      mInputLabel  {};
  GtkWidget*      mInputText   {};
  GtkWidget*      mInputButton {};

  GtkWidget*      mOutputBox    {};      // Contain the Label, Text, & Button for output.
  GtkWidget*      mOutputLabel  {};
  GtkWidget*      mOutputText   {};
  GtkWidget*      mOutputButton {};

  GtkWidget*      mEncryptParamBox {};
  GtkWidget*      mEncryptParamPhiCheckbutton    {};
  GtkWidget*      mEncryptParamMemoryDropdown    {};
  GtkWidget*      mEncryptParamIterationsBox     {};
  GtkWidget*      mEncryptParamIterationsLabel   {};
  GtkWidget*      mEncryptParamIterationsText    {};
  GtkWidget*      mEncryptParamThreadBox         {};
  GtkWidget*      mEncryptParamThreadLabel       {};
  GtkWidget*      mEncryptParamThreadText        {};
  GtkWidget*      mEncryptParamBatchSizeBox      {};
  GtkWidget*      mEncryptParamBatchSizeLabel    {};
  GtkWidget*      mEncryptParamBatchSizeText     {};

  GtkWidget*      mDecryptParamBox            {};
  GtkWidget*      mDecryptParamBatchSizeBox   {};
  GtkWidget*      mDecryptParamBatchSizeLabel {};
  GtkWidget*      mDecryptParamBatchSizeText  {};

  GtkWidget*      mPasswordBox   {};
  GtkWidget*      mPasswordLabel {};
  GtkWidget*      mPasswordEntry {};

  GtkWidget*      mReentryBox   {};
  GtkWidget*      mReentryLabel {};
  GtkWidget*      mReentryEntry {};

  GtkWidget*      mStatusBox   {};
  GtkWidget*      mStatusLabel {};

  Core*           mCore {};                // Access the primary 4crypt methods through me.
  Pod_t*          mPod  {};                // Access the primary 4crypt data through me.
  Mode            mMode {Mode::NONE};      // Encrypt mode? Decrypt mode?
  int             mArgc {};                // "argc" passed in from main(int argc, char* argv[])
  char**          mArgv {};                // "argv" passed in from main(int argc, char* argv[])
  bool            mOutputTextActivated {}; // Has the user pressed "enter" on the output text at least once?
  int             mNumberProcessors    {}; // How many processors does the executing user have on their machine?
 // Private Methods //
  void initApplicationWindow(void);
  void initGrid(void);
  void initLogoImage(void);
  void initCryptButtons(void);
  void initStrengthBox(void);
  void initInputBox(void);
  void initOutputBox(void);
  void initEncryptParamBox(void);
  void initDecryptParamBox(void);
  void initPasswordBox(void);
  void initReentryBox(void);
  void initStatusBox(void);
  void initProgressBox(void);

  void attachGrid(void);
  void setMode(Mode);
  bool verifyInputs(void);
  void encrypt(void);
  void decrypt(void);
  void onInputFilepathUpdated(void);
  void onOutputFilepathUpdated(void);
  bool getPassword(void);
  void clearPasswordEntries(void);
  void setStatusLabelSuccess(bool);

  // Update progress bar percentage until it's full.
  static void updateProgressCallback(void* cb_data);
  // Encryption happens in a separate thread, and we pass in a progress bar update function and a Gui* as its callback data.
  static void encryptThread(Core::StatusCallback_f* status_callback, void* status_callback_data);
  // Decryption happens in a separate thread, and we pass in a progress bar update function and a Gui* as its callback data.
  static void decryptThread(Core::StatusCallback_f* status_callback, void* status_callback_data);
  // Update the status text and blink it on-screen until dismissed by falsifying @mStatusIsBlinking.
  static void statusThread(void* vgui);

  static gboolean endOperation(void* vgui);
  static gboolean makeStatusVisible(void* vgui);
  static gboolean makeStatusInvisible(void* vgui);
 //// Private Static Pseudo-Methods.
  static void onApplicationActivate(GtkApplication*,        void*);
  static void onEncryptButtonClicked(GtkWidget*,           void*);
  static void onDecryptButtonClicked(GtkWidget*,           void*);
  static void onInputButtonClicked(GtkWidget*,             void*);
  static void onInputTextActivate(GtkWidget*,              void*);
  static void onOutputButtonClicked(GtkWidget*,            void*);
  static void onOutputTextActivate(GtkWidget*,             void*);
  static void onStartButtonClicked(GtkWidget*,             void*);
  static void onPasswordEntryActivate(GtkWidget*,          void*);
  static void onReentryEntryActivate(GtkWidget*,           void*);
  static void onExpertModeCheckbuttonToggled(GtkWidget*,  void*);
  static void onStrengthFastCheckbuttonToggled(GtkWidget*    , void*);
  static void onStrengthStandardCheckbuttonToggled(GtkWidget*, void*);
  static void onStrengthStrongCheckbuttonToggled(GtkWidget*  , void*);
  static void onStrengthExpertCheckbuttonToggled(GtkWidget*  , void*);
 };

} // ! namespace fourcrypt
#endif
