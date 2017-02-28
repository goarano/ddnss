CC:=gcc
INSTALL:=install
PATCH:=patch
RM:=rm
MKDIR:=mkdir

TARGET_FOLDER:=/lib/x86_64-linux-gnu/
NSSWITCH_DIFF:=nsswitch.diff
NSSWITCH_TARGET:=/etc/nsswitch.conf

.PHONY: all, install, clean

all: install

install: libnss_ddnss.so.2
	@$(MKDIR) -p /var/lib/ddnss/
	$(INSTALL) -m 644 $< $(TARGET_FOLDER)
	@if ! $(PATCH) -RNs --dry-run $(NSSWITCH_TARGET) < $(NSSWITCH_DIFF); then \
		$(PATCH) -Nsr - $(NSSWITCH_TARGET) < $(NSSWITCH_DIFF); \
	fi

uninstall:
	@if ! $(PATCH) -Ns --dry-run $(NSSWITCH_TARGET) < $(NSSWITCH_DIFF); then \
		$(PATCH) -RNsr - $(NSSWITCH_TARGET) < $(NSSWITCH_DIFF); \
	fi
	-$(RM) $(TARGET_FOLDER)/libnss_ddnss.so.2

libnss_ddnss.so.2: nss-ddnss.c
	$(CC) -shared -o $@ -Wl,-soname,$@ $< -fPIC

clean:
	rm -f libnss_ddnss.so.2
