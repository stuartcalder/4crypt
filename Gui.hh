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
  Gui(FourCrypt* param_fc, int param_argc, char** param_argv);
 // Destructor //
  ~Gui();
 // Public Methods //
  int run(void);
 private:
 // Private Data //
  std::string     input_filepath  {};
  std::string     output_filepath {};

  GtkApplication* application {};
  GtkFileDialog*  file_dialog {};        // Input & Output file dialogs.
  GtkWidget*      application_window {}; // Main window for displaying stuff.
  GtkWidget*      grid {};               // Organize UI elements using cells.

  GtkWidget*      logo_image {};         // Blue Dragon.

  GtkWidget*      encrypt_button {};     // Click me to switch to encrypt mode.
  GtkWidget*      decrypt_button {};     // Click me to switch to decrypt mode.
  GtkWidget*      start_button   {};     // Click me to begin encrypting/decrypting.

  GtkWidget*      input_box    {};       // Contain the Label, Text, & Button for input.
  GtkWidget*      input_label  {};
  GtkWidget*      input_text   {};
  GtkWidget*      input_button {};

  GtkWidget*      output_box    {};      // Contain the Label, Text, & Button for output.
  GtkWidget*      output_label  {};
  GtkWidget*      output_text   {};
  GtkWidget*      output_button {};

  GtkWidget*      password_box   {};
  GtkWidget*      password_label {};
  GtkWidget*      password_entry {};

  GtkWidget*      reentry_box   {};
  GtkWidget*      reentry_label {};
  GtkWidget*      reentry_entry {};

  FourCrypt*      fourcrypt {};          // Access the primary 4crypt methods through me.
  Pod_t*          pod  {};               // Access the primary 4crypt data through me.
  Mode            mode {Mode::NONE};        // Encrypt mode? Decrypt mode?
  int             argc {};                  // "argc" passed in from main(int argc, char* argv[])
  char**          argv {};                  // "argv" passed in from main(int argc, char* argv[])
  bool            output_text_activated {}; // Has the user pressed "enter" on the output text at least once?
 // Private Methods //
  void set_mode(Mode);
  bool verify_inputs(void);
  void encrypt(void);
  void decrypt(void);
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
  static void on_password_entry_activate(GtkWidget*,   void*);
  static void on_reentry_entry_activate(GtkWidget*,    void*);
 };

#endif
