Includes := -I.
Objects  := Obj/CommandLineArg.o Obj/FourCrypt.o
LinkLibs := -lSSC -lPPQ
CppStd   := c++20
Lto      := -flto
Optimize := -O3
Compile  := c++ $(Includes) $(LinkLibs) -std=$(CppStd) $(Lto) $(Optimize)

include Headers.mk

Obj/%.o: Impl/%.cc %.hh
	$(Compile) -c -o $@ $<
Obj/CommandLineArg.o: Obj/%.o: Impl/%.cc %.hh $(Deps_FourCrypt_hh)
	$(Compile) -c -o $@ $<

Bin/4crypt: Impl/Main.cc $(Objects) $(Deps_FourCrypt_hh) $(Deps_CommandLineArg_hh)
	$(Compile) -o $@ $< $(Objects)

all: Bin/4crypt
clean:
	rm -f Obj/*.o Bin/4crypt
