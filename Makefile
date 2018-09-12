all: ModLoader.so

ModLoader.so: main.cpp dep.cpp dep.h PFishHook.h StaticHook.h libPFishHook.a
	g++ -g -std=c++2a -shared -fPIC main.cpp dep.cpp -o ModLoader.so -L . -lPFishHook -lZydis -ldl -lstdc++fs

clean:
	-rm ModLoader.so