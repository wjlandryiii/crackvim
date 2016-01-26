all: crackvim


pkzip_crypto.o: pkzip_crypto.c pkzip_crypto.h
	gcc -c -o $@ $<

crackvim.o: crackvim.c crc32.h pkzip_crypto.h
	gcc -g -c -o $@ $<

crc32.o: crc32.c
	gcc -c -o $@ $<

crackvim: crackvim.o crc32.o pkzip_crypto.o
	gcc -g -o $@ $^

.PHONY: clean

clean:
	rm -f *.o
	rm -f crackvim
