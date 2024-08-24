# Which source files include which headers?
include Headers.mk
Deps_Util_cc           := $(Deps_Util_hh)
Deps_CommandLineArg_cc := $(Deps_CommandLineArg_hh) $(Deps_Util_hh)
Deps_CliMain_cc        := $(Deps_Core_hh) $(Deps_CommandLineArg_hh)
Deps_GuiMain_cc        := $(Deps_Gui_hh) $(Deps_Util_hh)
