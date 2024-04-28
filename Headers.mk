# Which headers include which other headers?
Deps_FourCrypt_hh      := FourCrypt.hh
Deps_CommandLineArg_hh := CommandLineArg.hh $(Deps_FourCrypt_hh)
Deps_Gui_hh            := Gui.hh $(Deps_FourCrypt_hh)
