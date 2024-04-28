#include "Gui.hh"
#include <gtk/gtk.h>

static void on_app_activate(
 GtkApplication* app)
{
  GtkWidget* window = gtk_application_window_new(app);
  GtkWidget* button = gtk_button_new_with_label("Hello, World!");
  g_signal_connect_swapped(button, "clicked", G_CALLBACK(gtk_window_close), window);
  gtk_window_set_child(GTK_WINDOW(window), button);
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
