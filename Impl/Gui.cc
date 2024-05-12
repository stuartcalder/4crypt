#include "Gui.hh"
#include <gtk/gtk.h>
#include <gio/gio.h>
#include <string>
#include <utility>
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

static bool
str_ends_with(const std::string& str, const std::string& with)
 {
  std::string::size_type position {
   str.rfind(
    with.c_str(),
    std::string::npos,
    with.size())};
  return position != std::string::npos;
 }

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
  std::string str {getExecutablePath()};
  auto size {str.size()};
  SSC_assertMsg(size > FOURCRYPT_GUI_BINARY_LENGTH, "Error: ExecutableDirPath invalid size!\n");

  SSC_assertMsg(
   str_ends_with(str, FOURCRYPT_GUI_BINARY),
   "Error: " FOURCRYPT_GUI_BINARY "was not found at the end of the path!\n");

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

Gui::Gui(FourCrypt* param_fc, int param_argc, char** param_argv)
: fourcrypt{param_fc}, argc{param_argc}, argv{param_argv}
 {
  pod = fourcrypt->getPod();
  gtk_init();

  file_dialog = gtk_file_dialog_new();

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
Gui::~Gui()
 {
  g_object_unref(file_dialog);
 }

void
Gui::on_encrypt_button_clicked(GtkWidget* button, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  std::puts("Encrypt button was pushed.");
  gui->set_mode(Mode::ENCRYPT);
 }

void
Gui::on_decrypt_button_clicked(GtkWidget* button, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  std::puts("Decrypt button was pushed.");
  gui->set_mode(Mode::DECRYPT);
 }

void
Gui::on_input_button_clicked(GtkWidget* button, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  std::puts("Input button was pushed.");
  //TODO: Open a file dialog to choose an input file.
  gtk_file_dialog_open(
   gui->file_dialog,
   GTK_WINDOW(gui->application_window),
   nullptr, // (GCancellable*)
   static_cast<GAsyncReadyCallback>([]
    (GObject*      fdialog,
     GAsyncResult* result,
     void*         void_self)
    {
     Gui*    lambda_self {static_cast<Gui*>(void_self)};
    /* This function initiates a file selection operation by presenting a file chooser
     * dialog to the user.The callback will be called when the dialog is dismissed.
     * It should call gtk_file_dialog_open_finish() to obtain
     * the result. */
     GFile* file {
      gtk_file_dialog_open_finish(
       GTK_FILE_DIALOG(fdialog),
       result,
       nullptr)};
     if (file != nullptr)
      {
       lambda_self->input_filepath = g_file_get_path(file);
       lambda_self->on_input_filepath_updated();
      }
    }),
   gui); // (gpointer)
 }

void
Gui::on_output_button_clicked(GtkWidget* button, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  std::puts("Output button was pushed.");
  gtk_file_dialog_save(
   gui->file_dialog,
   GTK_WINDOW(gui->application_window),
   nullptr, // (GCancellable*)
   static_cast<GAsyncReadyCallback>([]
    (GObject*      fdialog,
     GAsyncResult* result,
     void*         void_self)
    {
     Gui* lambda_self {static_cast<Gui*>(void_self)};
     
     GFile* file {
      gtk_file_dialog_save_finish(
       GTK_FILE_DIALOG(fdialog),
       result,
       nullptr)};
     if (file != nullptr)
      {
       lambda_self->output_filepath = g_file_get_path(file);
      }
    }),
   gui);
 }

using ExeMode  = FourCrypt::ExeMode;
using PadMode  = FourCrypt::PadMode;
using InOutDir = FourCrypt::InOutDir;
using ErrType  = FourCrypt::ErrType;

void
Gui::encrypt(void)
 {
  SSC_CodeError_t code_err    {0};
  ErrType         code_type   {ErrType::FOURCRYPT};
  InOutDir        code_io_dir {InOutDir::NONE};

  pod->execute_mode = ExeMode::ENCRYPT;
  Pod_t::touchup(*pod);
  code_err = fourcrypt->encrypt(&code_type, &code_io_dir);
  //TODO: Handle errors and error types.
  Pod_t::del(*pod);
  Pod_t::init(*pod);
 }

void
Gui::decrypt(void)
 {
  SSC_CodeError_t code_err    {0};
  ErrType         code_type   {ErrType::FOURCRYPT};
  InOutDir        code_io_dir {InOutDir::NONE};

  pod->execute_mode = ExeMode::DECRYPT;
  code_err = fourcrypt->decrypt(&code_type, &code_io_dir);
  //TODO: Handle errors and error types.
  Pod_t::del(*pod);
  Pod_t::init(*pod);
 }

void
Gui::on_start_button_clicked(GtkWidget* button, void* self)
 {
  Gui*   gui {static_cast<Gui*>(self)};
  Pod_t* pod {gui->pod};

  std::puts("Start button was pushed.");
  if (not gui->verify_inputs())
    return;

  // Reset the POD if it's been initialized.
  if (pod->input_filename)
   {
    Pod_t::del(*pod);
    Pod_t::init(*pod);
   }

  pod->input_filename = new char [gui->input_filepath.size() + 1];
  memcpy(pod->input_filename, gui->input_filepath.c_str(), gui->input_filepath.size() + 1);
  pod->output_filename = new char [gui->output_filepath.size() + 1];
  memcpy(pod->output_filename, gui->output_filepath.c_str(), gui->output_filepath.size() + 1);

  pod->input_filename_size  = gui->input_filepath.size();
  pod->output_filename_size = gui->output_filepath.size();

  switch (gui->mode)
   {
    case Mode::ENCRYPT:
      gui->encrypt();
      break;
    case Mode::DECRYPT:
      gui->decrypt();
      break;
   }
 }

void
Gui::on_password_entry_activate(GtkWidget* pwe, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  //TODO
 }

void
Gui::on_reentry_entry_activate(GtkWidget* ree, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};
  //TODO
 }

void
Gui::on_input_text_activate(GtkWidget* text, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};

  GtkEntryBuffer* buffer {gtk_text_get_buffer(GTK_TEXT(text))};
  gui->input_filepath = gtk_entry_buffer_get_text(buffer);
  gui->on_input_filepath_updated();
 }

void
Gui::on_output_text_activate(GtkWidget* text, void* self)
 {
  Gui* gui {static_cast<Gui*>(self)};

  GtkEntryBuffer* buffer {gtk_text_get_buffer(GTK_TEXT(text))};
  gui->output_filepath = gtk_entry_buffer_get_text(buffer);
  gui->output_text_activated = true;
 }

bool
Gui::verify_inputs(void)
 {
  // Get the input text data.
  GtkEntryBuffer* text_buffer {
   gtk_text_get_buffer(GTK_TEXT(input_text))
  };
  const char* filepath_cstr {
   gtk_entry_buffer_get_text(text_buffer)
  };
  std::string filepath {filepath_cstr};
  make_os_path(filepath);
  input_filepath = filepath;

  //TODO: Explain to the user that it's invalid for the input file to not exist.
  if (!SSC_FilePath_exists(filepath.c_str()))
   {
    std::fprintf(stderr, "%s did not exist!\n", filepath.c_str());
    return false;
   }

  // Get the output text data.
  text_buffer   = gtk_text_get_buffer(GTK_TEXT(output_text));
  filepath_cstr = gtk_entry_buffer_get_text(text_buffer);
  filepath      = filepath_cstr;
  make_os_path(filepath);
  output_filepath = filepath;

  //TODO: Explain to the user that it's invalid for the output file to already exist.
  if (SSC_FilePath_exists(filepath.c_str()))
   {
    std::fprintf(stderr, "%s already exists!\n", filepath.c_str());
    return false;
   }
  return true;
 }

void
Gui::on_input_filepath_updated(void)
 {
   bool output_filepath_updated {};
   std::printf("on_input_filepath_updated() called with mode %i\n", (int)mode);
   switch (mode)
    {
     case Mode::NONE:
      {
       // The user has chosen an input filepath before selecting a mode.
       // Assume the mode will be ENCRYPT when the filepath doesn't end in ".4c".
       // Assume the mode will be DECRYPT when the filepath does end in ".4c".
       // Do not make an assumption if the user has specified an output filepath.
       if (!output_text_activated)
        {
         if (str_ends_with(input_filepath, ".4c"))
           set_mode(Mode::DECRYPT);
         else
           set_mode(Mode::ENCRYPT);
         on_input_filepath_updated();
        }
      } break;
     case Mode::ENCRYPT:
      {
       // The input filepath was set during encrypt mode. Assume that the output filepath
       // will be the same as the input filepath, but with ".4c" appended.
       std::string ofp {input_filepath + ".4c"};
       if (not SSC_FilePath_exists(ofp.c_str()))
        {
         output_filepath = std::move(ofp);
         output_filepath_updated = true;
        }
      } break;
     case Mode::DECRYPT:
      {
       //TODO: The input filepath was set during decrypt mode. Assume that the output filepath
       // will be the same as the input filepath, but with ".4c" removed. (Assuming it ended in ".4c").
       if (str_ends_with(input_filepath, ".4c"))
        {
         std::string ofp {input_filepath};
         ofp.erase(ofp.end() - 3, ofp.end());
         if (not SSC_FilePath_exists(ofp.c_str()))
          {
           output_filepath = std::move(ofp);
           output_filepath_updated = true;
          }
        }
      } break;
    }
   // After mode-specific updates, update the text in the text boxes.
   std::printf("input_filepath was %s\n", input_filepath.c_str());
   std::printf("output_filepath was %s\n", output_filepath.c_str());
   GtkEntryBuffer* buffer {gtk_text_get_buffer(GTK_TEXT(input_text))};
   gtk_entry_buffer_set_text(
    buffer,
    input_filepath.c_str(),
    input_filepath.size());
   if (output_filepath_updated)
     on_output_filepath_updated();
 }

void
Gui::on_output_filepath_updated(void)
 {
  std::printf("on_output_filepath_updated() called with mode %i\n", (int)mode);
  GtkEntryBuffer* buffer {gtk_text_get_buffer(GTK_TEXT(output_text))};
  gtk_entry_buffer_set_text(buffer, output_filepath.c_str(), output_filepath.size());
 }

void
Gui::on_application_activate(GtkApplication* gtk_app, void* self)
 {
  constexpr int TEXT_HEIGHT {20};
  // Create the application window.
  Gui* gui {static_cast<Gui*>(self)};
  gui->application_window = gtk_application_window_new(gui->application);
  gtk_window_set_title(GTK_WINDOW(gui->application_window), "4crypt");
  gtk_widget_set_size_request(gui->application_window, WINDOW_WIDTH, WINDOW_HEIGHT);
  gtk_widget_set_hexpand(gui->application_window, FALSE);
  gtk_widget_set_vexpand(gui->application_window, FALSE);
  
  // Create the grid and configure it.
  gui->grid = gtk_grid_new();
  gtk_widget_set_valign(gui->grid, GTK_ALIGN_START);
  gtk_window_set_child(GTK_WINDOW(gui->application_window), gui->grid);
  gtk_grid_set_column_homogeneous(GTK_GRID(gui->grid), TRUE);

  // Add the FourCrypt dragon logo.
  std::string logo_path {getResourcePath() + "/dragon.png"};
  make_os_path(logo_path);
  gui->logo_image = gtk_image_new_from_file(logo_path.c_str());
  gtk_image_set_icon_size(GTK_IMAGE(gui->logo_image), GTK_ICON_SIZE_LARGE);
  gtk_widget_set_size_request(gui->logo_image, FOURCRYPT_IMG_WIDTH, FOURCRYPT_IMG_HEIGHT);
  gtk_widget_set_hexpand(gui->logo_image, TRUE);
  gtk_widget_set_vexpand(gui->logo_image, TRUE);

  // Create the Encrypt button.
  gui->encrypt_button = gtk_button_new_with_label("Encrypt");
  g_signal_connect(gui->encrypt_button, "clicked", G_CALLBACK(on_encrypt_button_clicked), gui);

  // Create the Decrypt button.
  gui->decrypt_button = gtk_button_new_with_label("Decrypt");
  g_signal_connect(gui->decrypt_button, "clicked", G_CALLBACK(on_decrypt_button_clicked), gui);

  // Create a Box for input.
  gui->input_box    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  gui->input_label  = gtk_label_new(" Input:");
  gui->input_text   = gtk_text_new();
  gui->input_button = gtk_button_new_with_label("Pick File");
  g_signal_connect(gui->input_text  , "activate", G_CALLBACK(on_input_text_activate) , gui);
  g_signal_connect(gui->input_button, "clicked" , G_CALLBACK(on_input_button_clicked), gui);
  // Fill the box with a label and text.
  gtk_box_append(GTK_BOX(gui->input_box), gui->input_label);
  gtk_box_append(GTK_BOX(gui->input_box), gui->input_text);
  gtk_box_append(GTK_BOX(gui->input_box), gui->input_button);
  gtk_widget_set_size_request(gui->input_box, -1, TEXT_HEIGHT);
  gtk_widget_set_hexpand(gui->input_text, TRUE);

  // Create a Box for output.
  gui->output_box    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  gui->output_label  = gtk_label_new("Output:");
  gui->output_text   = gtk_text_new();
  gui->output_button = gtk_button_new_with_label("Pick File");
  g_signal_connect(gui->output_text  , "activate", G_CALLBACK(on_output_text_activate) , gui);
  g_signal_connect(gui->output_button, "clicked" , G_CALLBACK(on_output_button_clicked), gui);
  // Fill the box with a label and text.
  gtk_box_append(GTK_BOX(gui->output_box), gui->output_label);
  gtk_box_append(GTK_BOX(gui->output_box), gui->output_text);
  gtk_box_append(GTK_BOX(gui->output_box), gui->output_button);
  gtk_widget_set_size_request(gui->output_box, -1, TEXT_HEIGHT);
  gtk_widget_set_hexpand(gui->output_text, TRUE);

  // Create a Box for passwords.
  gui->password_box   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  gui->password_label = gtk_label_new("Password:");
  gui->password_entry = gtk_password_entry_new();
  g_signal_connect(gui->password_entry, "activate", G_CALLBACK(on_password_entry_activate), gui); //TODO
  gtk_box_append(GTK_BOX(gui->password_box), gui->password_label);
  gtk_box_append(GTK_BOX(gui->password_box), gui->password_entry);
  gtk_widget_set_size_request(gui->password_box, -1, TEXT_HEIGHT);
  gtk_widget_set_hexpand(gui->password_box, TRUE);
  gtk_widget_set_visible(gui->password_box, FALSE);

  // Create a Box for re-entering passwords.
  gui->reentry_box   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  gui->reentry_label = gtk_label_new("Re-Entry:");
  gui->reentry_entry = gtk_password_entry_new();
  g_signal_connect(gui->reentry_box, "activate", G_CALLBACK(on_reentry_entry_activate), gui); //TODO
  gtk_box_append(GTK_BOX(gui->reentry_box), gui->reentry_label);
  gtk_box_append(GTK_BOX(gui->reentry_box), gui->reentry_entry);
  gtk_widget_set_size_request(gui->reentry_box, -1, TEXT_HEIGHT);
  gtk_widget_set_hexpand(gui->reentry_box, TRUE);
  gtk_widget_set_visible(gui->reentry_box, FALSE);

  gui->start_button = gtk_button_new_with_label("Start");
  g_signal_connect(gui->start_button, "clicked", G_CALLBACK(on_start_button_clicked), gui);

  int grid_y_idx {0};

  // Attach the widgets to the grid according to the following syntax:
  // gtk_grid_attach(grid, widget, grid_x_idx, grid_y_idx, horizontal_fill, vertical_fill)
  gtk_grid_attach(GTK_GRID(gui->grid), gui->logo_image , 0, grid_y_idx, 4, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(gui->grid), gui->encrypt_button, 0, grid_y_idx, 2, 1);
  gtk_grid_attach(GTK_GRID(gui->grid), gui->decrypt_button, 2, grid_y_idx, 2, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(gui->grid), gui->input_box  , 0, grid_y_idx, 4, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(gui->grid), gui->output_box  , 0, grid_y_idx, 4, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(gui->grid), gui->password_box, 0, grid_y_idx, 4, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(gui->grid), gui->reentry_box , 0, grid_y_idx, 4, 1);
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(gui->grid), gui->start_button, 0, grid_y_idx, 4, 1);

  // Set the grid as a child of the application window, then present the application window.
  gtk_window_set_child(GTK_WINDOW(gui->application_window), gui->grid);
  gtk_window_present(GTK_WINDOW(gui->application_window));
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
      gtk_widget_set_visible(password_box, TRUE);
      gtk_widget_set_visible(reentry_box,  TRUE);
      break;
    case Mode::DECRYPT:
      gtk_widget_add_css_class(decrypt_button, "highlight");
      gtk_widget_set_visible(password_box, TRUE);
      gtk_widget_set_visible(reentry_box,  FALSE);
      break;
   }
 }

int main(
 int   argc,
 char* argv[])
 {
  FourCrypt fc {};
  Gui       gui{&fc, argc, argv};

  return gui.run();
 }
