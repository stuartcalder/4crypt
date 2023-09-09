Includes := -I.
Headers  := CommandLineArg.hh DragonflyV2.hh FourCrypt.hh
Sources  := Impl/CommandLineArg.cc Impl/FourCrypt.cc Impl/Main.cc
Objects  := Obj/CommandLineArg.o Obj/FourCrypt.o
LinkLibs := -lSSC -lPPQ
CppStd   := c++20
Lto      := -flto
Optimize := -O3
Compile  := c++ $(Includes) $(LinkLibs) -std=$(CppStd) $(Lto) $(Optimize)

Obj/%.o: Impl/%.cc %.hh
	$(Compile) -c -o $@ $<
Obj/CommandLineArg.o: Obj/%.o: Impl/%.cc %.hh FourCrypt.hh
	$(Compile) -c -o $@ $<

Bin/4crypt: Impl/Main.cc $(Objects) FourCrypt.hh CommandLineArg.hh
	$(Compile) -o $@ $< $(Objects)

all: Bin/4crypt
clean:
	rm -f Obj/*.o Bin/4crypt
