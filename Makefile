CC = gcc
CFLAGS = `pkg-config --cflags gio-2.0 polkit-gobject-1 libcryptsetup` -Iinclude
LDFLAGS = `pkg-config --libs gio-2.0 polkit-gobject-1 libcryptsetup` -ldevmapper
CFLAGS_HELPER = `pkg-config --cflags libcryptsetup`
LDFLAGS_HELPER = `pkg-config --libs libcryptsetup`

SOURCES = src/crypted.c \
          src/polkit.c \
          src/cryptsetup.c
SOURCES_HELPER = src/crypted-helper/crypted-helper.c

TARGET = crypted
TARGET_HELPER = crypted-helper

PREFIX ?= /usr

all: $(TARGET) $(TARGET_HELPER)

$(TARGET):
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

$(TARGET_HELPER):
	$(CC) $(CFLAGS_HELPER) $(SOURCES_HELPER) -o $(TARGET_HELPER) $(LDFLAGS_HELPER)

clean:
	rm -f $(TARGET) $(TARGET_HELPER)

install:
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/sbin
	install -m 755 $(TARGET_HELPER) $(DESTDIR)$(PREFIX)/sbin
	install -m 755 data/crypted-helper-shutdown.sh $(DESTDIR)$(PREFIX)/sbin/crypted-helper-shutdown
	install -d $(DESTDIR)$(PREFIX)/share/polkit-1/actions
	install -m 644 data/io.furios.Crypted.policy $(DESTDIR)$(PREFIX)/share/polkit-1/actions
	install -d $(DESTDIR)$(PREFIX)/lib/systemd/system
	install -m 644 data/crypted.service $(DESTDIR)$(PREFIX)/lib/systemd/system
	install -m 644 data/crypted-helper-shutdown.service $(DESTDIR)$(PREFIX)/lib/systemd/system
	install -d $(DESTDIR)$(PREFIX)/share/dbus-1/system.d
	install -m 644 data/io.furios.Crypted.conf $(DESTDIR)$(PREFIX)/share/dbus-1/system.d
	install -d $(DESTDIR)$(PREFIX)/share/dbus-1/system-services
	install -m 644 data/io.furios.Crypted.service $(DESTDIR)$(PREFIX)/share/dbus-1/system-services

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(TARGET_HELPER)
	rm -f $(DESTDIR)$(PREFIX)/sbin/crypted-helper-shutdown
	rm -f $(DESTDIR)$(PREFIX)/share/polkit-1/actions/io.furios.Crypted.policy
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/crypted.service
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/crypted-helper-shutdown.service
	rm -f $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/io.furios.Crypted.conf
	rm -f $(DESTDIR)$(PREFIX)/share/dbus-1/system-services/io.furios.Crypted.service

.PHONY: all clean install uninstall
