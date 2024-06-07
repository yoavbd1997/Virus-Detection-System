all: virusDetector

virusDetector: AntiVirus.o
	gcc -g -Wall -m32 -o virusDetector AntiVirus.o

AntiVirus.o: AntiVirus.c
	gcc -g -Wall -m32 -c -o AntiVirus.o AntiVirus.c

.PHONY: clean
clean:
		rm -f *.o virusDetector
