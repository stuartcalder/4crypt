# Which headers include which other headers?
Deps_Core_hh           := Core.hh
Deps_CommandLineArg_hh := CommandLineArg.hh $(Deps_Core_hh)
Deps_Gui_hh            := Gui.hh $(Deps_Core_hh)
