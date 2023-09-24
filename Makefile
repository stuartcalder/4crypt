Includes := -I.
Objects  := Obj/CommandLineArg.o Obj/FourCrypt.o
LinkLibs := -lSSC -lPPQ
CppStd   := c++20
Lto      := -flto
Optimize := -O3
Compile  := c++ $(Includes) $(LinkLibs) -std=$(CppStd) $(Lto) $(Optimize) -march=native

include Sources.mk

Obj/%.o: Impl/%.cc %.hh
	$(Compile) -c -o $@ $<

Obj/CommandLineArg.o: Obj/%.o: Impl/%.cc $(Deps_CommandLineArg_cc)
	$(Compile) -c -o $@ $<

Bin/4crypt: Impl/Main.cc $(Objects) $(Deps_Main_cc)
	$(Compile) -o $@ $< $(Objects)

all: Bin/4crypt
clean:
	rm -f Obj/*.o Bin/4crypt
