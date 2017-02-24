CC:=gcc
SUDO:=sudo
INSTALL:=install
PATCH:=patch

.PHONY: all, install, clean

all: install

install: libnss_ddnss.so.2
	$(SUDO) $(INSTALL) -m 644 $< /lib/x86_64-linux-gnu/
	$(SUDO) $(PATCH) /etc/nsswitch.conf < nsswitch.diff

libnss_ddnss.so.2: nss-ddnss.c
	$(CC) -shared -o $@ -Wl,-soname,$@ $< -fPIC

clean:
	rm -f libnss_ddnss.so.2
