CC=gcc 
CXX=g++
CFLAGS=-municode
LDFLAGS=-lWinmm
DLL=-shared

ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else
	RM=rm
endif


all: inject

inject:
	$(CXX) inject.cpp $(CFLAGS) -o inject.exe 


clean:
	rm *.exe