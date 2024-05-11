#include "Gui.hh"
#include <gtk/gtk.h>
#include <gio/gio.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include <SSC/Process.h>

#if defined(FOURCRYPT_IS_PORTABLE) && !defined(SSC_HAS_GETEXECUTABLEPATH)
 #warning "Trying to build a portable 4crypt while SSC does not support SSC_getExecutablePath()!"
 #error   "Unsatisfiable build requirements."
#endif

#if !defined(SSC_LANG_CPP)
 #error "We need C++!"
#elif SSC_LANG_CPP < SSC_CPP_17
 #error "We need at least C++17!"
#endif

using Pod_t = Gui::Pod_t;
constexpr int FOURCRYPT_IMG_WIDTH_ORIGINAL {300};
constexpr int FOURCRYPT_IMG_WIDTH    {FOURCRYPT_IMG_WIDTH_ORIGINAL - 100};
constexpr int FOURCRYPT_IMG_HEIGHT   {300};

constexpr int FOURCRYPT_TITLE_WIDTH  {309};
constexpr int FOURCRYPT_TITLE_HEIGHT {195};

constexpr int WINDOW_WIDTH  {FOURCRYPT_IMG_WIDTH  * 2};
constexpr int WINDOW_HEIGHT {FOURCRYPT_IMG_HEIGHT * 2}; 

void
make_os_path(std::string& str)
 {
  for (char& c : str)
   {
   #if   defined(SSC_OS_UNIXLIKE)
    if (c == '\\')
      c = '/';
   #elif defined(SSC_OS_WINDOWS)
    if (c == '/')
      c = '\\';
   #else
    #error "Unsupported!"
   #endif
   }
 }

#ifdef FOURCRYPT_IS_PORTABLE
std::string
Gui::getExecutablePath(void)
 {
  size_t pathsize;
  char* c_execpath {SSC_getExecutablePath(nullptr)};
  SSC_assertMsg(c_execpath != nullptr, "Error: getExecutablePath(): c_execpath was NULL!\n");
  std::string s {c_execpath};
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
#endif

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

Gui::Gui(Pod_t* param_pod, int param_argc, char** param_argv)
: mode{Mode::NONE}, pod{param_pod}, argc{param_argc}, argv{param_argv}
 {
  gtk_init();
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

void
Gui::on_encrypt_button_clicked(GtkWidget* button, void* self)
 {
  Gui* myself {static_cast<Gui*>(self)};
  std::puts("Encrypt button was pushed.");
  myself->set_mode(Mode::ENCRYPT);
 }

void
Gui::on_decrypt_button_clicked(GtkWidget* button, void* self)
 {
  Gui* myself {static_cast<Gui*>(self)};
  std::puts("Decrypt button was pushed.");
  myself->set_mode(Mode::DECRYPT);
 }

void
Gui::on_start_button_clicked(GtkWidget* button, void* self)
 {
  Gui* myself {static_cast<Gui*>(self)};
  std::puts("Start button was pushed.");
  myself->verify_inputs();
  switch (myself->mode)
   {
    case Mode::ENCRYPT:
     {
      //TODO
     } break;
    case Mode::DECRYPT:
     {
      //TODO
     } break;
   }
 }

bool
Gui::verify_inputs(void)
 {
  GtkEntryBuffer* text_buffer {
   gtk_text_get_buffer(GTK_TEXT(input_text))
  };
  const char* filepath_cstr {
   gtk_entry_buffer_get_text(text_buffer)
  };
  std::string filepath {filepath_cstr};
  make_os_path(filepath);

  //TODO: Explain to the user that it's invalid for the input file to not exist.
  if (!SSC_FilePath_exists(filepath.c_str()))
   {
    std::fprintf(stderr, "%s did not exist!\n", filepath.c_str());
    return false;
   }

  text_buffer   = gtk_text_get_buffer(GTK_TEXT(output_text));
  filepath_cstr = gtk_entry_buffer_get_text(text_buffer);
  filepath      = filepath_cstr;
  make_os_path(filepath);

  //TODO: Explain to the user that it's invalid for the output file to already exist.
  if (SSC_FilePath_exists(filepath.c_str()))
   {
    std::fprintf(stderr, "%s already exists!\n", filepath.c_str());
    return false;
   }
  return true;
 }

void
Gui::on_application_activate(GtkApplication* gtk_app, void* self)
 {
  constexpr int TEXT_HEIGHT {25};
  // Create the application window.
  Gui* myself {static_cast<Gui*>(self)};
  myself->application_window = gtk_application_window_new(myself->application);
  gtk_window_set_title(GTK_WINDOW(myself->application_window), "4crypt");
  gtk_widget_set_size_request(myself->application_window, WINDOW_WIDTH, WINDOW_HEIGHT);
  
  // Create the grid and configure it.
  myself->grid = gtk_grid_new();
  gtk_widget_set_valign(myself->grid, GTK_ALIGN_START);
  gtk_window_set_child(GTK_WINDOW(myself->application_window), myself->grid);
  gtk_grid_set_column_homogeneous(GTK_GRID(myself->grid), TRUE);

  // Add the FourCrypt dragon logo.
  std::string logo_path {getResourcePath() + "/4crypt_cutout_export.png"};
  make_os_path(logo_path);
  myself->logo_image = gtk_image_new_from_file(logo_path.c_str());
  gtk_image_set_icon_size(GTK_IMAGE(myself->logo_image), GTK_ICON_SIZE_LARGE);
  gtk_widget_set_size_request(myself->logo_image, FOURCRYPT_IMG_WIDTH, FOURCRYPT_IMG_HEIGHT);
  gtk_widget_set_hexpand(myself->logo_image, TRUE);
  gtk_widget_set_vexpand(myself->logo_image, TRUE);

  // Create the Encrypt button.
  myself->encrypt_button = gtk_button_new_with_label("Encrypt");
  g_signal_connect(myself->encrypt_button, "clicked", G_CALLBACK(on_encrypt_button_clicked), myself);

  // Create the Decrypt button.
  myself->decrypt_button = gtk_button_new_with_label("Decrypt");
  g_signal_connect(myself->decrypt_button, "clicked", G_CALLBACK(on_decrypt_button_clicked), myself);

  // Create a Box for input.
  myself->input_box    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  myself->input_label  = gtk_label_new(" Input:");
  myself->input_text   = gtk_text_new();
  // Fill the box with a label and text.
  gtk_box_append(GTK_BOX(myself->input_box), myself->input_label);
  gtk_box_append(GTK_BOX(myself->input_box), myself->input_text);
  gtk_widget_set_size_request(myself->input_box, -1, TEXT_HEIGHT);
  gtk_widget_set_hexpand(myself->input_text, TRUE);

  // Create a Box for output.
  myself->output_box   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  myself->output_label = gtk_label_new("Output:");
  myself->output_text  = gtk_text_new();
  // Fill the box with a label and text.
  gtk_box_append(GTK_BOX(myself->output_box), myself->output_label);
  gtk_box_append(GTK_BOX(myself->output_box), myself->output_text);
  gtk_widget_set_size_request(myself->output_box, -1, TEXT_HEIGHT);
  gtk_widget_set_hexpand(myself->output_text, TRUE);

  myself->start_button = gtk_button_new_with_label("Start");
  g_signal_connect(myself->start_button, "clicked", G_CALLBACK(on_start_button_clicked), myself);

  int grid_y_idx{0};

  // Attach the widgets to the grid according to the following syntax:
  // gtk_grid_attach(grid, widget, grid_x_idx, grid_y_idx, horizontal_fill, vertical_fill)
  gtk_grid_attach(GTK_GRID(myself->grid), myself->logo_image , 0, grid_y_idx, 4, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(myself->grid), myself->encrypt_button, 0, grid_y_idx, 2, 1);
  gtk_grid_attach(GTK_GRID(myself->grid), myself->decrypt_button, 2, grid_y_idx, 2, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(myself->grid), myself->input_box  , 0, grid_y_idx, 4, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(myself->grid), myself->output_box  , 0, grid_y_idx, 4, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(myself->grid), myself->start_button, 0, grid_y_idx, 4, 1);

  // Set the grid as a child of the application window, then present the application window.
  gtk_window_set_child(GTK_WINDOW(myself->application_window), myself->grid);
  gtk_window_present(GTK_WINDOW(myself->application_window));
 }

int
Gui::run(void)
 {
  application = gtk_application_new("cc.calder.fourcrypt", G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect(application, "activate", G_CALLBACK(on_application_activate), this);
  int run_result {g_application_run(G_APPLICATION(application), argc, argv)};
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
  FourCrypt fc{};
  Gui       gui{fc.getPod(), argc, argv};

  return gui.run();
 }
