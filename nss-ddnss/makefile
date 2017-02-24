CC:=gcc

.PHONY: all, install, clean

all: install

install: libnss_ddnss.so.2

libnss_ddnss.so.2: nss-ddnss.c
	$(CC) -shared -o $@ -Wl,-soname,$@ $< -fPIC

clean:
	rm -f libnss_ddnss.so.2
