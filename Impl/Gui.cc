#include "Gui.hh"
#include <gtk/gtk.h>
#include <gio/gio.h>
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

constexpr int FOURCRYPT_IMG_WIDTH_ORIGINAL  = 309;
constexpr int FOURCRYPT_IMG_WIDTH = FOURCRYPT_IMG_WIDTH_ORIGINAL - 100;
constexpr int FOURCRYPT_IMG_HEIGHT = 195;

constexpr int FOURCRYPT_TITLE_WIDTH  = 309;
constexpr int FOURCRYPT_TITLE_HEIGHT = 195;

constexpr int WINDOW_WIDTH  = FOURCRYPT_IMG_WIDTH * 2;
constexpr int WINDOW_HEIGHT = FOURCRYPT_IMG_HEIGHT * 4; 

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

  str.erase(
   str.end() - (FOURCRYPT_GUI_BINARY_LENGTH + 1), // Also erase the trailing '/'.
   str.end());
  return str;
 }

std::string
Gui::getResourcePath(void)
 {
 #if defined(FOURCRYPT_IS_PORTABLE)
  return getExecutableDirPath();
 #elif defined(__gnu_linux__)
  return std::string{"/usr/share/4crypt"};
 #else
  #error "Unsupported!"
 #endif
 }

Gui::Gui(int param_argc, char** param_argv)
: application{nullptr},application_window{nullptr},password_window{nullptr},grid{nullptr},
  logo_image{nullptr},title_image{nullptr},encrypt_button{nullptr},decrypt_button{nullptr},
  input_label{nullptr},output_label{nullptr},go_button{nullptr},password_entry{nullptr},
  mode{Mode::NONE},argc{param_argc},argv{param_argv}
 {
  gtk_init();
  // Initialize some CSS stuff.
  SSC_assertMsg(gdk_display_get_default(), "DEFAULT DISPLAY IS NULL\n");
  GtkCssProvider* provider = gtk_css_provider_new();
  gtk_css_provider_load_from_path(provider, (getResourcePath() + "/style.css").c_str());
  gtk_style_context_add_provider_for_display(
   gdk_display_get_default(),
   GTK_STYLE_PROVIDER(provider),
   GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
 }

void
Gui::on_encrypt_button_clicked(GtkWidget* button, gpointer self)
 {
  Gui* myself = static_cast<Gui*>(self);
  std::puts("Encrypt button was pushed.");
  myself->set_mode(Mode::ENCRYPT);
 }

void
Gui::on_decrypt_button_clicked(GtkWidget* button, gpointer self)
 {
  Gui* myself = static_cast<Gui*>(self);
  std::puts("Decrypt button was pushed.");
  myself->set_mode(Mode::DECRYPT);
  //TODO
 }

void
Gui::on_go_button_clicked(GtkWidget* button, gpointer self)
 {
  Gui* myself = static_cast<Gui*>(self);
  std::puts("GO! button was pushed.");
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
  gtk_grid_set_column_homogeneous(GTK_GRID(myself->grid), TRUE);

  myself->logo_image = gtk_image_new_from_file((getResourcePath() + "/4crypt_cutout_export.png").c_str());
  gtk_widget_set_size_request(myself->logo_image, FOURCRYPT_IMG_WIDTH, FOURCRYPT_IMG_HEIGHT);

  myself->encrypt_button = gtk_button_new_with_label("Encrypt");
  g_signal_connect(myself->encrypt_button, "clicked", G_CALLBACK(on_encrypt_button_clicked), myself);

  myself->decrypt_button = gtk_button_new_with_label("Decrypt");
  g_signal_connect(myself->decrypt_button, "clicked", G_CALLBACK(on_decrypt_button_clicked), myself);

  myself->input_label  = gtk_label_new("Input:");
  myself->input_text   = gtk_text_new();
  myself->output_label = gtk_label_new("Output:");
  myself->output_text  = gtk_text_new();

  myself->go_button = gtk_button_new_with_label("GO!");
  g_signal_connect(myself->go_button, "clicked", G_CALLBACK(on_go_button_clicked), myself);

  int grid_y_idx = 0;

  // Place the @logo_image in the grid cell (0, @grid_y_idx), and make it fill
  // just 2 cells horizontally and vertically.
  gtk_grid_attach(GTK_GRID(myself->grid), myself->logo_image , 0, grid_y_idx, 2, 2);
  grid_y_idx += 2;

  gtk_grid_attach(GTK_GRID(myself->grid), myself->encrypt_button, 0, grid_y_idx, 1, 1);
  gtk_grid_attach(GTK_GRID(myself->grid), myself->decrypt_button, 1, grid_y_idx, 1, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(myself->grid), myself->input_label, 0, grid_y_idx, 1, 1);
  gtk_grid_attach(GTK_GRID(myself->grid), myself->input_text , 1, grid_y_idx, 2, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(myself->grid), myself->output_label, 0, grid_y_idx, 1, 1);
  gtk_grid_attach(GTK_GRID(myself->grid), myself->output_text , 1, grid_y_idx, 2, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(myself->grid), myself->go_button, 0, grid_y_idx, 2, 1);

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
  if (gtk_widget_has_css_class(encrypt_button, "highlight"))
    gtk_widget_remove_css_class(encrypt_button, "highlight");
  if (gtk_widget_has_css_class(decrypt_button, "highlight"))
    gtk_widget_remove_css_class(decrypt_button, "highlight");
  mode = m;
  switch (mode)
   {
    case Mode::ENCRYPT:
      gtk_widget_add_css_class(encrypt_button, "highlight");
      break;
    case Mode::DECRYPT:
      gtk_widget_add_css_class(decrypt_button, "highlight");
      break;
   }
 }

int main(
 int   argc,
 char* argv[])
 {
  Gui gui{argc, argv};
  return gui.run();
 }
