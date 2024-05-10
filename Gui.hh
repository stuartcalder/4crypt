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

class Gui
 {
 public:
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
  Gui(int param_argc, char** param_argv);
 // Public Methods //
 int run(void);
 private:
 // Private Data //
  GtkApplication* application;
  GtkWidget* application_window;
  GtkWidget* password_window;
  GtkWidget* grid;
  GtkWidget* logo_image;
  GtkWidget* title_image;
  GtkWidget* encrypt_button;
  GtkWidget* decrypt_button;
  GtkWidget* input_label;
  GtkWidget* input_text;
  GtkWidget* output_label;
  GtkWidget* output_text;
  GtkWidget* go_button;
  GtkWidget* password_entry;
  Mode       mode;
  int        argc;
  char**     argv;
 // Private Methods //
  void set_mode(Mode);//TODO
 //// Private Static Pseudo-Methods.
  static void on_application_activate(GtkApplication*, gpointer);
  static void on_encrypt_button_clicked(GtkWidget*,    gpointer);
  static void on_decrypt_button_clicked(GtkWidget*,    gpointer);
  static void on_go_button_clicked(GtkWidget*, gpointer);
 };

#endif
