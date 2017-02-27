CC:=gcc
SUDO:=sudo
INSTALL:=install
PATCH:=patch
RM:=rm
MKDIR:=mkdir

TARGET_FOLDER:=/lib/x86_64-linux-gnu/

.PHONY: all, install, clean

all: install

install: libnss_ddnss.so.2
	$(MKDIR) -p /var/lib/ddnss/
	$(SUDO) $(INSTALL) -m 644 $< $(TARGET_FOLDER)
	$(SUDO) $(PATCH) -N -r - /etc/nsswitch.conf < nsswitch.diff

uninstall:
	$(SUDO) $(PATCH) -R -r - /etc/nsswitch.conf < nsswitch.diff
	$(SUDO) $(RM) $(TARGET_FOLDER)/libnss_ddnss.so.2

libnss_ddnss.so.2: nss-ddnss.c
	$(CC) -shared -o $@ -Wl,-soname,$@ $< -fPIC

clean:
	rm -f libnss_ddnss.so.2
