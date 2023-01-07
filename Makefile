CC = g++
LDLIBS = -lpcap

all: airodump

airodump: main.o mac.o airodump.o
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	@rm -f ./airodump *.o