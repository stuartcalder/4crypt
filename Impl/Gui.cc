#include "Gui.hh"
#include <gtk/gtk.h>

static const char* FOURCRYPT_IMG_FPATH = "/ram/u/4crypt_cutout_export.png";
constexpr int FOURCRYPT_IMG_WIDTH  = 313;
constexpr int FOURCRYPT_IMG_HEIGHT = 200;

static void callback_todo(
 GtkWidget* widget,
 gpointer   data
 )
{
}

static void on_app_activate(
 GtkApplication* app)
{
  GtkWidget* window;
  GtkWidget* grid;
  GtkWidget* image  = gtk_image_new_from_file(FOURCRYPT_IMG_FPATH);
  GtkWidget* button;

  window = gtk_application_window_new(app);
  gtk_window_set_title(GTK_WINDOW(window), "4crypt");

  grid = gtk_grid_new();
  gtk_window_set_child(GTK_WINDOW(window), grid);

  image = gtk_image_new_from_file(FOURCRYPT_IMG_FPATH);
  gtk_widget_set_size_request(image, FOURCRYPT_IMG_WIDTH, FOURCRYPT_IMG_HEIGHT);

  button = gtk_button_new_with_label("Encrypt");
  g_signal_connect(button, "clicked", G_CALLBACK(callback_todo), nullptr); //TODO
  //g_signal_connect_swapped(button, "clicked", G_CALLBACK(gtk_window_close), window);

  /* Place the image in the grid cell (0, 0), and make it fill
   * just 2 cells horizontally and vertically.
   * Occupies (0,0), (0,1), (1,0), (1,1).
   */
  gtk_grid_attach(GTK_GRID(grid), image , 0, 0, 2, 2);
  /* Place the button in the grid cell (0, 2) and make it fill
   * two cells horizontally and one cell vertically.
   */
  gtk_grid_attach(GTK_GRID(grid), button, 0, 2, 2, 1);

  gtk_window_set_child(GTK_WINDOW(window), grid);
  gtk_window_present(GTK_WINDOW(window));
#if 0
  gtk_window_set_child(GTK_WINDOW(window), button);
  gtk_window_set_child(GTK_WINDOW(window), image);
  gtk_window_present(GTK_WINDOW(window));
#endif
}

int main(
 int   argc,
 char* argv[])
{
  GtkApplication* app = gtk_application_new("cc.calder.fourcrypt", G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect(app, "activate", G_CALLBACK(on_app_activate), nullptr);
  return g_application_run(G_APPLICATION(app), argc, argv);
}
