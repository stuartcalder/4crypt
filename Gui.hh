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
  GtkApplication* application;
  GtkFileDialog*  file_dialog;
  GtkWidget*      application_window;
  GtkWidget*      password_window;
  GtkWidget*      grid;
  GtkWidget*      logo_image;
  GtkWidget*      encrypt_button;
  GtkWidget*      decrypt_button;
  GtkWidget*      input_box;
  GtkWidget*      input_label;
  GtkWidget*      input_text;
  GtkWidget*      input_button;
  GtkWidget*      output_box;
  GtkWidget*      output_label;
  GtkWidget*      output_text;
  GtkWidget*      output_button;
  GtkWidget*      start_button;
  Pod_t*          pod;
  Mode            mode;
  int             argc;
  char**          argv;
 // Private Methods //
  void set_mode(Mode);//TODO
  bool verify_inputs(void);
 //// Private Static Pseudo-Methods.
  static void on_application_activate(GtkApplication*, void*);
  static void on_encrypt_button_clicked(GtkWidget*,    void*);
  static void on_decrypt_button_clicked(GtkWidget*,    void*);
  static void on_input_button_clicked(GtkWidget*,      void*);
  static void on_output_button_clicked(GtkWidget*,     void*);
  static void on_start_button_clicked(GtkWidget*,      void*);
 };

#endif
