CXX=gcc
CXXFLAGS=-Wall -pedantic
LDFLAGS=-lgmp

all: main

main: *.c
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

clean:
	rm -f main

run: all
	./main
