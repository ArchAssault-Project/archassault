CC ?= gcc
CFLAGS ?= -g
CFLAGS += -Wall

TARGETS=pth-samba.so
SCRIPTS=pth-smbclient pth-rpcclient pth-net pth-smbget pth-openchangeclient pth-winexe pth-sqsh

all: $(TARGETS)

clean:
	rm -f *.o *.so

%.o: %.c
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<
%.so: %.o
	$(CC) -shared -Wl,-soname,$@ $(LDFLAGS) -o $@ $< -ldl


install: $(TARGETS)
	install -d $(DESTDIR)/usr/lib/passing-the-hash
	install -d $(DESTDIR)/usr/bin
	cp -a $(TARGETS) $(DESTDIR)/usr/lib/passing-the-hash/
	cp -a $(SCRIPTS) $(DESTDIR)/usr/bin/

