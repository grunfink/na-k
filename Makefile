PREFIX=/usr/local

na-k: na.h na.o na-kmf.o aes.o ecc.o sha256.o
	$(CC) -g -Wall na.o na-kmf.o aes.o ecc.o sha256.o -o $@

aes.o: aes.c
	$(CC) -g -Wall -O3 -c $<

ecc.o: ecc.c
	$(CC) -g -Wall -O3 -c $<

sha256.o: sha256.c
	$(CC) -g -Wall -O3 -c $<

na-kmf.o: na-kmf.c na.h
	$(CC) -g -Wall -O3 -c $<

na.o: na.c na.h
	$(CC) -g -Wall -O3 -c $<

install:
	install -m 755 na-k $(PREFIX)/bin/na-k

uninstall:
	rm -f $(PREFIX)/bin/na-k

dist: clean
	cd .. && tar czvf na-k/na-k.tar.gz na-k/*

clean:
	rm -f *.o na-k *.tar.gz *.asc
