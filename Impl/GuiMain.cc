#include "Gui.hh"
// GTK4
#include <gtk/gtk.h>
#include <gio/gio.h>
// C++ STL
#include <algorithm>
#include <chrono>
#include <string>
#include <thread>
#include <utility>
// C++ C Lib
#include <cstring>
#include <cstdlib>
#include <cstdio>
// SSC
#ifdef FOURCRYPT_IS_PORTABLE
 #include <SSC/Process.h>
 #ifndef SSC_HAS_GETEXECUTABLEPATH
  #warning "Trying to build a portable 4crypt while SSC does not support SSC_getExecutablePath()!"
  #error   "Unsatisfiable build requirements."
 #endif
#endif

#if !defined(SSC_LANG_CPP)
 #error "We need C++!"
#elif SSC_LANG_CPP < SSC_CPP_17
 #error "We need at least C++17!"
#endif
using namespace fourcrypt;

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
fourcrypt::make_os_path(std::string& str)
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

Gui::Gui(Core* param_core, int param_argc, char** param_argv)
: core{param_core}, argc{param_argc}, argv{param_argv}
 {
  pod = core->getPod();
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
     void*         void_self) -> void
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

using ExeMode  = Core::ExeMode;
using PadMode  = Core::PadMode;
using InOutDir = Core::InOutDir;
using ErrType  = Core::ErrType;

void
Gui::progress_bar_callback(void* v_gui)
 {
  g_idle_add(
   static_cast<GSourceFunc>([](void* userdata) -> gboolean
    {
     Gui*            gui {static_cast<Gui*>(userdata)};
     GtkProgressBar* pb  {GTK_PROGRESS_BAR(gui->progress_bar)};
     double old_fraction {gtk_progress_bar_get_fraction(pb)};
     double new_fraction {old_fraction + PROGRESS_PULSE_STEP};
     if (new_fraction > 1.0)
       new_fraction = 1.0;
     gtk_progress_bar_set_fraction(pb, new_fraction);
     return G_SOURCE_REMOVE;
    }),
   v_gui);
 }

gboolean
Gui::end_operation(void* userdata)
 {
  Gui* g {static_cast<Gui*>(userdata)};
  gtk_widget_set_visible(g->progress_box, FALSE);
  gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(g->progress_bar), 0.0);
  g->operation_is_ongoing = false;
  return G_SOURCE_REMOVE;
 }

void
Gui::encrypt_thread(
 Core::StatusCallback_f* status_callback,
 void*                   status_callback_data)
 {
  Gui*   gui  {static_cast<Gui*>(status_callback_data)};
  Core*  core {gui->core};
  Pod_t* pod  {gui->pod};
  {
    std::lock_guard {gui->operation_mtx};
    gui->operation_data.code_error = core->encrypt(
     &gui->operation_data.error_type,
     &gui->operation_data.in_out_dir,
     status_callback,
     status_callback_data);
    Pod_t::del(*pod);
    Pod_t::init(*pod);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    g_idle_add(&end_operation, gui);
  }
 }

void
Gui::encrypt(void)
 {
  if (not operation_is_ongoing)
   {
    operation_is_ongoing = true;
    pod->execute_mode = ExeMode::ENCRYPT;
    Pod_t::touchup(*pod);
    gtk_widget_set_visible(progress_box, TRUE);

    std::thread th {&encrypt_thread, &progress_bar_callback, this};
    th.detach();
   }
  //TODO: Handle errors and error types.
 }

void
Gui::decrypt_thread(
 Core::StatusCallback_f* status_callback,
 void*                   status_callback_data)
 {
  Gui*   gui  {static_cast<Gui*>(status_callback_data)};
  Core*  core {gui->core};
  Pod_t* pod  {gui->pod};
  {
    std::lock_guard {gui->operation_mtx};
    gui->operation_data.code_error = core->decrypt(
     &gui->operation_data.error_type,
     &gui->operation_data.in_out_dir,
     status_callback,
     status_callback_data);
    Pod_t::del(*pod);
    Pod_t::init(*pod);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    g_idle_add(&end_operation, gui);
  }
 }

void
Gui::decrypt(void)
 {
  if (not operation_is_ongoing)
   {
    operation_is_ongoing = true;
    pod->execute_mode = ExeMode::DECRYPT;
    gtk_widget_set_visible(progress_box, TRUE);

    std::thread th {&decrypt_thread, &progress_bar_callback, this};
    th.detach();
   }
  //TODO: Handle errors and error types.
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

  if (not gui->get_password())
    return;

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

bool
Gui::get_password(void)
 {
  const char* pw_0 {gtk_editable_get_text(GTK_EDITABLE(password_entry))};
  const char* pw_1 {gtk_editable_get_text(GTK_EDITABLE(reentry_entry))};
  size_t pw_0_len = std::strlen(pw_0);
  size_t pw_1_len = std::strlen(pw_1);
  SSC_assertMsg(pw_0_len <= Core::MAX_PW_BYTES, "pw_0_len > MAX_PW_BYTES!\n");
  SSC_assertMsg(pw_1_len <= Core::MAX_PW_BYTES, "pw_1_len > MAX_PW_BYTES!\n");
  bool   equal = (pw_0_len == pw_1_len) and (not std::strcmp(pw_0, pw_1));
  memset(pod->password_buffer, 0, sizeof(pod->password_buffer));

  if (pw_0_len == 0)
    return false;
  switch (mode)
   {
    case Mode::ENCRYPT:
      // ENCRYPT mode requires that we get the same password input at least twice.
      if (not equal)
        return false;
      memcpy(pod->password_buffer, pw_0, pw_0_len);
      pod->password_size = pw_0_len;
      break;
    case Mode::DECRYPT:
      memcpy(pod->password_buffer, pw_0, pw_0_len);
      pod->password_size = pw_0_len;
      break;
   }
  return true;
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

  // Add the Core dragon logo.
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
  gtk_widget_add_css_class(gui->input_text, "basic");
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
  gtk_widget_add_css_class(gui->output_text, "basic");
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
  gtk_widget_set_hexpand(gui->password_box,   TRUE);
  gtk_widget_set_hexpand(gui->password_entry, TRUE);
  gtk_widget_set_visible(gui->password_box,   FALSE);
  gtk_editable_set_max_width_chars(GTK_EDITABLE(gui->password_entry), Core::MAX_PW_BYTES);

  // Create a Box for re-entering passwords.
  gui->reentry_box   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  gui->reentry_label = gtk_label_new("Re-Entry:");
  gui->reentry_entry = gtk_password_entry_new();
  g_signal_connect(gui->reentry_entry, "activate", G_CALLBACK(on_reentry_entry_activate), gui); //TODO
  gtk_box_append(GTK_BOX(gui->reentry_box), gui->reentry_label);
  gtk_box_append(GTK_BOX(gui->reentry_box), gui->reentry_entry);
  gtk_widget_set_size_request(gui->reentry_box, -1, TEXT_HEIGHT);
  gtk_widget_set_hexpand(gui->reentry_box,   TRUE);
  gtk_widget_set_hexpand(gui->reentry_entry, TRUE);
  gtk_widget_set_visible(gui->reentry_box,   FALSE);
  gtk_editable_set_max_width_chars(GTK_EDITABLE(gui->reentry_entry), Core::MAX_PW_BYTES);

  // Initialize the start button.
  gui->start_button = gtk_button_new_with_label("Start");
  g_signal_connect(gui->start_button, "clicked", G_CALLBACK(on_start_button_clicked), gui);

  // Initialize the progress box and its bar.
  gui->progress_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1);
  gui->progress_bar = gtk_progress_bar_new();
  gtk_widget_set_hexpand(gui->progress_bar, TRUE);
  gtk_box_append(GTK_BOX(gui->progress_box), gui->progress_bar);
  // Set the pulse of progress for each step of progress
  gtk_progress_bar_set_pulse_step(GTK_PROGRESS_BAR(gui->progress_bar), PROGRESS_PULSE_STEP);
  gtk_widget_set_hexpand(gui->progress_box, TRUE);
  gtk_widget_set_vexpand(gui->progress_box, TRUE);
  gtk_widget_set_visible(gui->progress_box, TRUE);

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
  ++grid_y_idx;

  gtk_grid_attach(GTK_GRID(gui->grid), gui->progress_box, 0, grid_y_idx, 4, 1);
  ++grid_y_idx;

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
  Core core {};
  Gui  gui  {&core, argc, argv};

  return gui.run();
 }
