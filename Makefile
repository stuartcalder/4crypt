Includes := -I.
Headers  := CommandLineArg.hh DragonflyV2.hh FourCrypt.hh
Sources  := Impl/CommandLineArg.cc Impl/FourCrypt.cc Impl/Main.cc
Objects  := CommandLineArg.o FourCrypt.o
LinkLibs := -lSSC -lPPQ
CppStd   := c++20
Lto      := -flto
Optimize := -O3
Compile  := c++ $(Includes) $(LinkLibs) -std=$(CppStd) $(Lto) $(Optimize)

%.o: Impl/%.cc %.hh
	$(Compile) -c -o $@ $<
CommandLineArg.o: %.o: Impl/%.cc %.hh FourCrypt.hh
	$(Compile) -c -o $@ $<

4crypt: Impl/Main.cc $(Objects)
	$(Compile) -o $@ $< $(Objects)

clean:
	rm -f *.o 4crypt
