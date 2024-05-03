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

static std::string getExecutablePath(void)
{
  size_t pathsize;
  char* c_execpath = SSC_getExecutablePath(nullptr);
  SSC_assertMsg(c_execpath, "Error: getExecutablePath(): c_execpath was NULL!\n");
  std::string s{c_execpath};
  free(c_execpath);
  return s;
}

static std::string getExecutableDirPath(void)
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

static void callback_todo(
 GtkWidget* widget,
 gpointer   data)
{
  std::printf("Executable path is %s\n", getExecutablePath().c_str());
  std::printf("Executable dir path is %s\n", getExecutableDirPath().c_str());
}

static void on_app_activate(
 GtkApplication* app)
{
  GtkWidget* window;
  GtkWidget* grid;
  GtkWidget* logo_image;
  GtkWidget* title_image;
  GtkWidget* encrypt_button;
  GtkWidget* decrypt_button;
  GtkWidget* pass_entry;

  window = gtk_application_window_new(app);
  gtk_window_set_title(GTK_WINDOW(window), "4crypt");
  gtk_widget_set_size_request(window, WINDOW_WIDTH, WINDOW_HEIGHT);

  grid = gtk_grid_new();
  gtk_widget_set_valign(grid, GTK_ALIGN_START);
  gtk_window_set_child(GTK_WINDOW(window), grid);

  logo_image = gtk_image_new_from_file(FOURCRYPT_IMG_FPATH);
  gtk_widget_set_size_request(logo_image, FOURCRYPT_IMG_WIDTH, FOURCRYPT_IMG_HEIGHT);

  title_image = gtk_image_new_from_file(FOURCRYPT_TITLE_FPATH);
  gtk_widget_set_size_request(title_image, FOURCRYPT_TITLE_WIDTH, FOURCRYPT_TITLE_HEIGHT);

  encrypt_button = gtk_button_new_with_label("Encrypt");
  g_signal_connect(encrypt_button, "clicked", G_CALLBACK(callback_todo), nullptr); //TODO

  decrypt_button = gtk_button_new_with_label("Decrypt");
  g_signal_connect(decrypt_button, "clicked", G_CALLBACK(callback_todo), nullptr); //TODO

  pass_entry = gtk_password_entry_new();

  // Check it out! You can use C++ lambdas for the GTK callbacks!
  g_signal_connect(
   pass_entry,
   "activate",
   G_CALLBACK(
    static_cast<void(*)(GtkPasswordEntry*, gpointer)>(
     [](GtkPasswordEntry* self, gpointer user_data) -> void {
      std::printf(
       "The input password was %s!\n",
       gtk_editable_get_text(GTK_EDITABLE(self)));
     })),
   nullptr);

  // Place the logo_image in the grid cell (0, 0), and make it fill
  // just 2 cells horizontally and vertically.
  // Occupies (0,0), (0,1), (1,0), (1,1).
  gtk_grid_attach(GTK_GRID(grid), logo_image , 0, 0, 2, 2);

  // Place the title_image in the grid cell (2, 0), and make it fill
  // just 2 cells horizontally and vertically.
  // Occupies (2,0), (3,0), (2,1), (2,2).
  gtk_grid_attach(GTK_GRID(grid), title_image, 2, 0, 2, 2);

  // Place the encrypt_button in the grid cell (0, 2) and make it fill
  // four cells horizontally and one cell vertically.
  gtk_grid_attach(GTK_GRID(grid), encrypt_button, 0, 2, 4, 1);

  // Place the decrypt_button in the grid cell (0, 3) and make it fill
  // four cells horizontally and one cell vertically.
  gtk_grid_attach(GTK_GRID(grid), decrypt_button, 0, 3, 4, 1);

  // Place the pass_entry in the grid cell (0, 4) and make it fill
  // four cells horizontally and one cell vertically.
  gtk_grid_attach(GTK_GRID(grid), pass_entry, 0, 4, 4, 1);

  gtk_window_set_child(GTK_WINDOW(window), grid);
  gtk_window_present(GTK_WINDOW(window));
}

int main(
 int   argc,
 char* argv[])
{
  GtkApplication* app = gtk_application_new("cc.calder.fourcrypt", G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect(app, "activate", G_CALLBACK(on_app_activate), nullptr);
  return g_application_run(G_APPLICATION(app), argc, argv);
}
