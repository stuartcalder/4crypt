# Which source files include which headers?
include Headers.mk
Deps_CommandLineArg_cc := $(Deps_CommandLineArg_hh)
Deps_Main_cc           := $(Deps_FourCrypt_hh) $(Deps_CommandLineArg_hh)
