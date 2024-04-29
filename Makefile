Includes := -I.
Objects  := Obj/CommandLineArg.o Obj/FourCrypt.o
LinkLibs := -lSSC -lPPQ
CppStd   := c++20
Lto      := -flto
Optimize := -O3
Compile  := c++ $(Includes) $(LinkLibs) -std=$(CppStd) $(Lto) $(Optimize) -march=native

Dir    := /ram/$(USER)/4crypt
BinDir := $(Dir)/Bin
ObjDir := $(Dir)/Obj

include Sources.mk

Obj/%.o: Impl/%.cc $(Deps_$%_cc)
	$(Compile) -c -o $@ $<

Bin/4crypt: Impl/Main.cc $(Objects) $(Deps_Main_cc)
	$(Compile) -o $@ $< $(Objects)
Bin/g4crypt: Impl/Gui.cc $(Objects) $(Deps_Gui_cc)
	$(Compile) `pkg-config --cflags --libs gtk4` -o $@ $< $(Objects)

dirs:
	[ -d $(Dir)    ] || mkdir $(Dir)
	[ -d $(BinDir) ] || mkdir $(BinDir)
	[ -d $(ObjDir) ] || mkdir $(ObjDir)
4crypt:  dirs Bin/4crypt
g4crypt: dirs Bin/g4crypt
all: 4crypt g4crypt
clean:
	rm -f Obj/*.o Bin/4crypt Bin/g4crypt
