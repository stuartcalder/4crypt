Includes := -I.
Objects  := Obj/CommandLineArg.o Obj/Core.o
LinkLibs := -lSSC -lPPQ
CppStd   := -std=c++20
Lto      := -flto
Optimize := -O3
Native   := -march=native
ObjCompile := c++ $(Includes) $(CppStd) $(Lto) $(Optimize) $(Native) -c
Compile  := c++ $(Includes) $(LinkLibs) $(CppStd) $(Lto) $(Optimize) $(Native)

Dir    := /ram/$(USER)/4crypt
BinDir := $(Dir)/Bin
ObjDir := $(Dir)/Obj

include Sources.mk

Obj/%.o: Impl/%.cc $(Deps_$%_cc)
	$(ObjCompile) -o $@ $<

Bin/4crypt: Impl/CliMain.cc $(Objects) $(Deps_CliMain_cc)
	$(Compile) -o $@ $< $(Objects)
Bin/g4crypt: Impl/GuiMain.cc $(Objects) $(Deps_GuiMain_cc)
	$(Compile) `pkg-config --cflags --libs gtk4` -o $@ $< $(Objects)

dirs:
	[ -d $(Dir)    ] || mkdir $(Dir)
	[ -d $(BinDir) ] || mkdir $(BinDir)
	[ -d $(ObjDir) ] || mkdir $(ObjDir)

# User targets.
4crypt:  dirs Bin/4crypt
g4crypt: dirs Bin/g4crypt
all: 4crypt g4crypt
clean:
	rm -f $(ObjDir)/*.o $(BinDir)/4crypt $(BinDir)/g4crypt
