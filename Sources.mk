# Which source files include which headers?
include Headers.mk
Deps_CommandLineArg_cc := $(Deps_CommandLineArg_hh)
Deps_Main_cc           := $(Deps_Core_hh) $(Deps_CommandLineArg_hh)
Deps_Gui_cc            := $(Deps_Gui_hh)
