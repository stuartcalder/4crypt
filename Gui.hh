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

class Gui
 {
 public:
 // Public Constants //
 enum class Mode
  {
   NONE, ENCRYPT, DECRYPT
  }
 // Public Static Procedures //
  static std::string getExecutablePath(void)
  static std::string getExecutableDirPath(void)
 //// Public Static Pseudo-Methods.
  static void on_application_activate(GtkApplication*, gpointer);
  static void on_encrypt_button_clicked(GtkWidget*, gpointer);
  static void on_decrypt_button_clicked(GtkWidget*, gpointer);
 // Constructors //
  Gui();
 // Public Methods //
 // (TODO)
 private:
 // Private Data //
  GtkApplication* app;
  GtkWidget* app_window;
  GtkWidget* password_window;
  GtkWidget* grid;
  GtkWidget* logo_image;
  GtkWidget* title_image;
  GtkWidget* encrypt_button;
  GtkWidget* decrypt_button;
  GtkWidget* password_entry;
  Mode       mode;
 // Private Methods //
  void set_mode(Mode);
 };

#endif
