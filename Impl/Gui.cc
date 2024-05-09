#include "Gui.hh"
#include <gtk/gtk.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include <SSC/Process.h>

#ifndef SSC_HAS_GETEXECUTABLEPATH
 #warning "This SSC implementation does not provide SSC_getExecutablePath()!"
 #warning "Therefore this file cannot be compiled!"
 #error   "Unsatisfied SSC requirements."
#endif

#if !defined(SSC_LANG_CPP)
 #error "We need C++!"
#elif SSC_LANG_CPP < SSC_CPP_17
 #error "We need at least C++17!"
#endif

#define FOURCRYPT_ART_PFX "/home/u/4crypt_artwork/"

static const char* FOURCRYPT_IMG_FPATH = FOURCRYPT_ART_PFX "4crypt_cutout_export.png";
constexpr int FOURCRYPT_IMG_WIDTH_ORIGINAL  = 309;
constexpr int FOURCRYPT_IMG_WIDTH = FOURCRYPT_IMG_WIDTH_ORIGINAL - 100;
constexpr int FOURCRYPT_IMG_HEIGHT = 195;

static const char* FOURCRYPT_TITLE_FPATH = FOURCRYPT_ART_PFX "4crypt_title.png";
constexpr int FOURCRYPT_TITLE_WIDTH  = 309;
constexpr int FOURCRYPT_TITLE_HEIGHT = 195;

constexpr int WINDOW_WIDTH  = FOURCRYPT_IMG_WIDTH;
constexpr int WINDOW_HEIGHT = FOURCRYPT_IMG_HEIGHT * 3; 

std::string
Gui::getExecutablePath(void)
 {
  size_t pathsize;
  char* c_execpath = SSC_getExecutablePath(nullptr);
  SSC_assertMsg(c_execpath != nullptr, "Error: getExecutablePath(): c_execpath was NULL!\n");
  std::string s{c_execpath};
  free(c_execpath);
  return s;
 }

std::string
Gui::getExecutableDirPath(void)
 {
  std::string str{getExecutablePath()};
  auto size{str.size()};
  SSC_assertMsg(size > FOURCRYPT_GUI_BINARY_LENGTH, "Error: ExecutableDirPath invalid size!\n");

  auto pos{str.rfind(
   FOURCRYPT_GUI_BINARY,
   std::string::npos, 
   FOURCRYPT_GUI_BINARY_LENGTH)};
  SSC_assertMsg(
   pos != std::string::npos,
   "Error: %s was not found at the end of the path!\n",
   FOURCRYPT_GUI_BINARY);

  str.erase(str.end() - FOURCRYPT_GUI_BINARY_LENGTH, str.end());
  return str;
 }

Gui::Gui(int param_argc, char** param_argv)
: application{nullptr},
  application_window{nullptr}, password_window{nullptr}, 
  grid{nullptr},               logo_image{nullptr},
  title_image{nullptr},        encrypt_button{nullptr},
  decrypt_button{nullptr},     password_entry{nullptr},
  mode{Mode::NONE},
  argc{param_argc},            argv{param_argv}
 {
  application = gtk_application_new("cc.calder.fourcrypt", G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect(application, "activate", G_CALLBACK(on_application_activate), this);
  int run_result = g_application_run(G_APPLICATION(application), argc, argv);
  if (run_result != 0)
    fprintf(stderr, "Error: g_application_run() returned %i!\n", run_result);
 }

void
Gui::on_encrypt_button_clicked(GtkWidget* button, gpointer self)
 {
  Gui* myself = static_cast<Gui*>(self);
  #if 1
  std::puts("Encrypt button was pushed.");
  #else
  myself->password_window = gtk_window_new();
  myself->password_entry  = gtk_password_entry_new();
  gtk_window_set_child(GTK_WINDOW(myself->password_window), myself->password_entry)
  gtk_window_present(GTK_WINDOW(myself->password_window));
  #endif
 }

void
Gui::on_decrypt_button_clicked(GtkWidget* button, gpointer self)
 {
  Gui* myself = static_cast<Gui*>(self);
  std::puts("Decrypt button was pushed.");
  //TODO
 }

void
Gui::on_application_activate(GtkApplication* gtk_app, gpointer self)
 {
  Gui* myself = static_cast<Gui*>(self);
  myself->application_window = gtk_application_window_new(myself->application);
  gtk_window_set_title(GTK_WINDOW(myself->application_window), "4crypt");
  gtk_widget_set_size_request(myself->application_window, WINDOW_WIDTH, WINDOW_HEIGHT);

  myself->grid = gtk_grid_new();
  gtk_widget_set_valign(myself->grid, GTK_ALIGN_START);
  gtk_window_set_child(GTK_WINDOW(myself->application_window), myself->grid);

  myself->logo_image = gtk_image_new_from_file(FOURCRYPT_IMG_FPATH);
  gtk_widget_set_size_request(myself->logo_image, FOURCRYPT_IMG_WIDTH, FOURCRYPT_IMG_HEIGHT);

  myself->title_image = gtk_image_new_from_file(FOURCRYPT_TITLE_FPATH);
  gtk_widget_set_size_request(myself->title_image, FOURCRYPT_TITLE_WIDTH, FOURCRYPT_TITLE_HEIGHT);

  myself->encrypt_button = gtk_button_new_with_label("Encrypt");
  g_signal_connect(myself->encrypt_button, "clicked", G_CALLBACK(on_encrypt_button_clicked), myself);

  myself->decrypt_button = gtk_button_new_with_label("Decrypt");
  g_signal_connect(myself->decrypt_button, "clicked", G_CALLBACK(on_decrypt_button_clicked), myself);

  // Place the logo_image in the grid cell (0, 0), and make it fill
  // just 2 cells horizontally and vertically.
  // Occupies (0,0), (0,1), (1,0), (1,1).
  gtk_grid_attach(GTK_GRID(myself->grid), myself->logo_image , 0, 0, 2, 2);

  // Place the title_image in the grid cell (2, 0), and make it fill
  // just 2 cells horizontally and vertically.
  // Occupies (2,0), (3,0), (2,1), (2,2).
  gtk_grid_attach(GTK_GRID(myself->grid), myself->title_image, 2, 0, 2, 2);

  // Place the encrypt_button in the grid cell (0, 2) and make it fill
  // four cells horizontally and one cell vertically.
  gtk_grid_attach(GTK_GRID(myself->grid), myself->encrypt_button, 0, 2, 4, 1);

  // Place the decrypt_button in the grid cell (0, 3) and make it fill
  // four cells horizontally and one cell vertically.
  gtk_grid_attach(GTK_GRID(myself->grid), myself->decrypt_button, 0, 3, 4, 1);

  gtk_window_set_child(GTK_WINDOW(myself->application_window), myself->grid);
  gtk_window_present(GTK_WINDOW(myself->application_window));
 }

int
Gui::run(void)
 {
  application = gtk_application_new("cc.calder.fourcrypt", G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect(application, "activate", G_CALLBACK(on_application_activate), this);
  int run_result = g_application_run(G_APPLICATION(application), argc, argv);
  if (run_result != 0)
    fprintf(stderr, "Error: g_application_run() returned %i!\n", run_result);
  return run_result;
 }

void
Gui::set_mode(Mode m)
 {
  //TODO
 }

int main(
 int   argc,
 char* argv[])
 {
 #if 1
  Gui gui{argc, argv};
  return gui.run();
 #else
  GtkApplication* app = gtk_application_new("cc.calder.fourcrypt", G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect(app, "activate", G_CALLBACK(on_application_activate), nullptr);
  return g_application_run(G_APPLICATION(app), argc, argv);
 #endif
 }
