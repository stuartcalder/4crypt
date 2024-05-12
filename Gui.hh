#ifndef FOURCRYPT_GUI_HH
#define FOURCRYPT_GUI_HH

#include "FourCrypt.hh"
#include <gtk/gtk.h>
#include <string>

#if   defined(SSC_OS_UNIXLIKE)
 #define FOURCRYPT_GUI_BINARY        "g4crypt"
 #define FOURCRYPT_GUI_BINARY_LENGTH 7
#elif defined(SSC_OS_WINDOWS)
 #define FOURCRYPT_GUI_BINARY        "g4crypt.exe"
 #define FOURCRYPT_GUI_BINARY_LENGTH 11
#else
 #error "Unsupported OS".
#endif

#if defined(FOURCRYPT_IS_PORTABLE)
#elif defined(__gnu_linux__)
#else
 #error "Unsupported!"
#endif

void make_os_path(std::string& str);

class Gui
 {
 public:
 // Public Types //
  using Pod_t = FourCrypt::PlainOldData;
 // Public Constants //
  enum class Mode
   {
    NONE, ENCRYPT, DECRYPT
   };
 // Public Static Procedures //
  #ifdef FOURCRYPT_IS_PORTABLE
  static std::string getExecutablePath(void);
  static std::string getExecutableDirPath(void);
  #endif
  static std::string getResourcePath(void);
 // Constructors //
  Gui(Pod_t* param_pod, int param_argc, char** param_argv);
 // Destructor //
  ~Gui();
 // Public Methods //
  int run(void);
 private:
 // Private Data //
  std::string     input_filepath {};
  std::string     output_filepath {};
  GtkApplication* application {nullptr};
  GtkFileDialog*  file_dialog {nullptr};        // Input & Output file dialogs.
  GtkWidget*      application_window {nullptr}; // Main window for displaying stuff.
  GtkWidget*      grid {nullptr};               // Organize UI elements using cells.
  GtkWidget*      logo_image {nullptr};         // Blue Dragon.
  GtkWidget*      encrypt_button {nullptr};     // Click me to switch to encrypt mode.
  GtkWidget*      decrypt_button {nullptr};     // Click me to switch to decrypt mode.
  GtkWidget*      input_box {nullptr};          // Contain the Label, Text, & Button for input.
  GtkWidget*      input_label {nullptr};
  GtkWidget*      input_text {nullptr};
  GtkWidget*      input_button {nullptr};
  GtkWidget*      output_box {nullptr};         // Contain the Label, Text, & Button for output.
  GtkWidget*      output_label {nullptr};
  GtkWidget*      output_text {nullptr};
  GtkWidget*      output_button {nullptr};
  GtkWidget*      start_button {nullptr};       // Click me to begin encrypting/decrypting.
  Pod_t*          pod {nullptr};                // Access the primary 4crypt data through me.
  Mode            mode {Mode::NONE};            // Encrypt mode? Decrypt mode?
  int             argc {};                      // "argc" passed in from main(int argc, char* argv[])
  char**          argv {};                      // "argv" passed in from main(int argc, char* argv[])
  bool            output_text_activated {};     // Has the user pressed "enter" on the output text at least once?
 // Private Methods //
  void set_mode(Mode);
  bool verify_inputs(void);
  void on_input_filepath_updated(void);
  void on_output_filepath_updated(void);
 //// Private Static Pseudo-Methods.
  static void on_application_activate(GtkApplication*, void*);
  static void on_encrypt_button_clicked(GtkWidget*,    void*);
  static void on_decrypt_button_clicked(GtkWidget*,    void*);
  static void on_input_button_clicked(GtkWidget*,      void*);
  static void on_input_text_activate(GtkWidget*,       void*);
  static void on_output_button_clicked(GtkWidget*,     void*);
  static void on_output_text_activate(GtkWidget*,      void*);
  static void on_start_button_clicked(GtkWidget*,      void*);
 };

#endif
