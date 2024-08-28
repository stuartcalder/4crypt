#ifndef FOURCRYPT_GUI_HH
#define FOURCRYPT_GUI_HH

// Local
#include "Core.hh"
// GTK4
#include <gtk/gtk.h>
// C++ STL
#include <atomic>
#include <mutex>
#include <string>

#define FOURCRYPT_SLASH_CHAR_UNIXLIKE '/'
#define FOURCRYPT_SLASH_CHAR_WINDOWS  '\\'

// OS-specific binary names.
#if   defined(SSC_OS_UNIXLIKE)
 #define FOURCRYPT_GUI_BINARY        "g4crypt"
 #define FOURCRYPT_GUI_BINARY_LENGTH 7
 #define FOURCRYPT_SLASH_CHAR_OS     FOURCRYPT_SLASH_CHAR_UNIXLIKE
#elif defined(SSC_OS_WINDOWS)
 #define FOURCRYPT_GUI_BINARY        "g4crypt.exe"
 #define FOURCRYPT_GUI_BINARY_LENGTH 11
 #define FOURCRYPT_SLASH_CHAR_OS     FOURCRYPT_SLASH_CHAR_WINDOWS
#else
 #error "Unsupported OS".
#endif

#if !defined(FOURCRYPT_IS_PORTABLE) && !defined(__gnu_linux__)
 #error "Unsupported! Not Portable or GNU/Linux!"
#endif

namespace fourcrypt {

void make_os_path(std::string& str);

class Gui
 {
 public:
 // Public Types //
  using Pod_t = Core::PlainOldData;
 // Public Constants //
  enum class Mode
   {
    NONE, ENCRYPT, DECRYPT
   };
  static constexpr double PROGRESS_PULSE_STEP {0.14285714285714285}; //FIXME: Fraction of total number of steps.
  static constexpr int    TEXT_HEIGHT {20};
 // Public Static Procedures //
  #ifdef FOURCRYPT_IS_PORTABLE
  static std::string getExecutablePath(void);
  static std::string getExecutableDirPath(void);
  #endif
  static std::string getResourcePath(void);
 // Constructors //
  Gui(Core* param_core, int param_argc, char** param_argv);
 // Destructor //
  ~Gui();
 // Public Methods //
  int run(void);
 private:
 // Private Data //
  std::string     input_filepath  {};
  std::string     output_filepath {};

  std::atomic_bool operation_is_ongoing {};
  std::atomic_bool status_is_blinking   {};
  std::mutex       operation_mtx {};
  struct OpData {
    SSC_CodeError_t code_error {0};
    Core::ErrType   error_type {Core::ErrType::CORE};
    Core::InOutDir  in_out_dir {Core::InOutDir::NONE};
  } operation_data {};

  GtkApplication* application {};
  GtkFileDialog*  file_dialog {};        // Input & Output file dialogs.
  GtkWidget*      application_window {}; // Main window for displaying stuff.
  GtkWidget*      grid {};               // Organize UI elements using cells.

  GtkWidget*      logo_image {};         // Blue Dragon.

  GtkWidget*      encrypt_button {};     // Click me to switch to encrypt mode.
  GtkWidget*      decrypt_button {};     // Click me to switch to decrypt mode.
  GtkWidget*      start_button   {};     // Click me to begin encrypting/decrypting.

  GtkWidget*      progress_box   {};     // Contain the progress bar.
  GtkWidget*      progress_bar   {};     // I track the progress of encryption/decryption.

  GtkWidget*      input_box    {};       // Contain the Label, Text, & Button for input.
  GtkWidget*      input_label  {};
  GtkWidget*      input_text   {};
  GtkWidget*      input_button {};

  GtkWidget*      output_box    {};      // Contain the Label, Text, & Button for output.
  GtkWidget*      output_label  {};
  GtkWidget*      output_text   {};
  GtkWidget*      output_button {};

  GtkWidget*      encrypt_param_box {};
  GtkWidget*      encrypt_param_phi_checkbutton  {};
  GtkWidget*      encrypt_param_mem_dropdown     {};
  GtkWidget*      encrypt_param_iterations_box   {};
  GtkWidget*      encrypt_param_iterations_label {};
  GtkWidget*      encrypt_param_iterations_text  {};
  GtkWidget*      encrypt_param_threads_box      {};
  GtkWidget*      encrypt_param_threads_label    {};
  GtkWidget*      encrypt_param_threads_text     {};
  GtkWidget*      encrypt_param_batch_size_box   {};
  GtkWidget*      encrypt_param_batch_size_label {};
  GtkWidget*      encrypt_param_batch_size_text  {};

  GtkWidget*      decrypt_param_box {}; //TODO
  GtkWidget*      decrypt_param_batch_size_box   {}; //TODO
  GtkWidget*      decrypt_param_batch_size_label {};  //TODO
  GtkWidget*      decrypt_param_batch_size_text  {};  //TODO

  GtkWidget*      password_box   {};
  GtkWidget*      password_label {};
  GtkWidget*      password_entry {};

  GtkWidget*      reentry_box   {};
  GtkWidget*      reentry_label {};
  GtkWidget*      reentry_entry {};

  GtkWidget*      status_box   {};
  GtkWidget*      status_label {};

  Core*           core {};                  // Access the primary 4crypt methods through me.
  Pod_t*          pod  {};                  // Access the primary 4crypt data through me.
  Mode            mode {Mode::NONE};        // Encrypt mode? Decrypt mode?
  int             argc {};                  // "argc" passed in from main(int argc, char* argv[])
  char**          argv {};                  // "argv" passed in from main(int argc, char* argv[])
  bool            output_text_activated {}; // Has the user pressed "enter" on the output text at least once?
  int             number_processors {}; // How many processors does the executing user have on their machine?
 // Private Methods //
  void init_application_window(void);
  void init_grid(void);
  void init_logo_image(void);
  void init_crypt_buttons(void);
  void init_input_box(void);
  void init_output_box(void);
  void init_encrypt_param_box(void);
  void init_decrypt_param_box(void); //TODO
  void init_password_box(void);
  void init_reentry_box(void);
  void init_status_box(void);
  void init_progress_box(void);
  void attach_grid(void);

  void set_mode(Mode);
  bool verify_inputs(void);
  void encrypt(void);
  void decrypt(void);
  void on_input_filepath_updated(void);
  void on_output_filepath_updated(void);
  bool get_password(void);
  void clear_password_entries(void);

  // Update progress bar percentage until it's full.
  static void     update_progress_callback(void* cb_data);
  // Encryption happens in a separate thread, and we pass in a progress bar update function and a Gui* as its callback data.
  static void     encrypt_thread(Core::StatusCallback_f* status_callback, void* status_callback_data);
  // Decryption happens in a separate thread, and we pass in a progress bar update function and a Gui* as its callback data.
  static void     decrypt_thread(Core::StatusCallback_f* status_callback, void* status_callback_data);
  // Update the status text and blink it on-screen until dismissed by falsifying @status_is_blinking.
  static void     status_thread(void* vgui);
  static gboolean end_operation(void* vgui);
  static gboolean make_status_visible(void* vgui);
  static gboolean make_status_invisible(void* vgui);
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

} // ! namespace fourcrypt
#endif
