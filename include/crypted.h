/**
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef CRYPTED_H
#define CRYPTED_H

#include <polkit/polkit.h>
#include <libcryptsetup.h>

/* Paths */
#define FURIOS_HEADER_PATH "/dev/furios/furios-reserved"
#define FURIOS_ROOTFS_PATH "/dev/furios/furios-rootfs"
#define FURIOS_ENCRYPTED_NAME "furios_encrypted"
#define DROIDIAN_HEADER_PATH "/dev/droidian/droidian-reserved"
#define DROIDIAN_ROOTFS_PATH "/dev/droidian/droidian-rootfs"
#define DROIDIAN_ENCRYPTED_NAME "droidian_encrypted"

/* Encryption settings */
#define CIPHER "aes"
#define CIPHER_MODE "xts-plain64"
#define SECTOR_SIZE 4096
#define SECTOR_SIZE_FORCE FALSE

/* Helper and status files */
#define ENCRYPTION_HELPER_PIDFILE "/run/crypted-helper.pid"
#define ENCRYPTION_HELPER_FAILURE "/run/crypted-helper-failed"

/* Encryption status enum */
typedef enum {
    CRYPTED_STATUS_UNKNOWN = 0,
    CRYPTED_STATUS_UNSUPPORTED,
    CRYPTED_STATUS_UNCONFIGURED,
    CRYPTED_STATUS_CONFIGURING,
    CRYPTED_STATUS_CONFIGURED,
    CRYPTED_STATUS_ENCRYPTING,
    CRYPTED_STATUS_ENCRYPTED,
    CRYPTED_STATUS_FAILED,
} CryptedStatus;

typedef struct {
    GObject parent_instance;

    GDBusConnection *connection;
    GDBusNodeInfo *introspection_data;
    guint bus_id;
    guint timeout_id;
    gint64 last_call_timestamp;

    gboolean encryption_supported;
    CryptedStatus status;

    gchar *header_device;
    gchar *data_device;
    gchar *mapped_name;

    struct crypt_device *crypt_device;
    GMutex encryption_process_mutex;
    GThread *encryption_thread;
    char *passphrase;

    PolkitAuthority *authority;

    gboolean should_quit;
} Crypted;

/**
 * Register a timestamp for the last activity
 * Updates the last_call_timestamp with the current monotonic time
 * @param self The Crypted instance
 */
void
crypted_register_timestamp(Crypted *self);

/**
 * Set the encryption status and emit property change signals if needed
 * @param self The Crypted instance
 * @param status The new encryption status to set
 */
void
crypted_set_status(Crypted *self, CryptedStatus status);

#endif /* CRYPTED_H */
