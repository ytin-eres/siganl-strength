CC = g++
LDLIBS = -lpcap

all: signal_strength

signal_strength: main.o mac.o signal_strength.o
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	@rm -f ./signal_strength *.o