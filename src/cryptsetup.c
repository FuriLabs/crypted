/**
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2022 Eugenio Paolantonio (g7)
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#define G_LOG_DOMAIN "crypted-cryptsetup"

#include <libcryptsetup.h>
#include <libdevmapper.h>

#include "crypted.h"
#include "cryptsetup.h"

int
cryptsetup_get_supported_features(void)
{
    int flags = 0;
    struct dm_task *dmt = NULL;
    struct dm_versions *target;
    struct dm_versions *last_target;

    if (!(dmt = dm_task_create(DM_DEVICE_LIST_VERSIONS)))
        goto out;

    if (!(dm_task_run(dmt)))
        goto out;

    target = dm_task_get_versions(dmt);

    do {
        last_target = target;

        if (strcmp("crypt", target->name) == 0) {
            if (target->version[0] >= 1 && target->version[1] >= 17)
                /* sector_size supported */
                flags |= DM_CRYPT_SECTOR_SIZE;
        }

        target = (void *)target + target->next;
    } while (last_target != target);

out:
    if (dmt)
        dm_task_destroy(dmt);

    return flags;
}

CryptedStatus
cryptsetup_check_status(Crypted *self)
{
    CryptedStatus status;
    crypt_status_info cryptsetup_status;
    crypt_reencrypt_info reencrypt_status;
    int result;
    gchar *content = NULL;
    GError *error = NULL;

    g_return_val_if_fail(self != NULL, CRYPTED_STATUS_UNKNOWN);

    /* Check if encryption is supported at all */
    if (!self->encryption_supported)
        return CRYPTED_STATUS_UNSUPPORTED;

    /* Check if we have a persistent state file */
    if (g_file_get_contents(ENCRYPTION_STATE_FILE, &content, NULL, NULL)) {
        int saved_status = atoi(content);
        g_free(content);

        /* If we previously saved CONFIGURING or CONFIGURED state, respect it */
        if (saved_status == CRYPTED_STATUS_CONFIGURING ||
            saved_status == CRYPTED_STATUS_CONFIGURED) {
            g_debug("Using saved state: %d", saved_status);
            return (CryptedStatus)saved_status;
        }
    }

    /* Check if encryption is in progress */
    if (access(ENCRYPTION_HELPER_PIDFILE, F_OK) == 0) {
        g_debug("Found helper PID file, assuming encryption is in progress");
        return CRYPTED_STATUS_ENCRYPTING;
    }

    /* Check if encryption failed */
    if (access(ENCRYPTION_HELPER_FAILURE, F_OK) == 0) {
        g_debug("Found helper failure file, assuming encryption failed");
        return CRYPTED_STATUS_FAILED;
    }

    /* Open the device and check status */
    if (self->crypt_device == NULL) {
        result = crypt_init(&self->crypt_device, self->header_device);
        /* Can't open device, assume unconfigured */
        if (result < 0)
            return CRYPTED_STATUS_UNCONFIGURED;

        /* Try to load the LUKS header */
        result = crypt_load(self->crypt_device, CRYPT_LUKS2, NULL);
        if (result < 0) {
            /* No valid LUKS header, device is unconfigured */
            crypt_free(self->crypt_device);
            self->crypt_device = NULL;
            return CRYPTED_STATUS_UNCONFIGURED;
        }
    }

    /* Check device activation status */
    cryptsetup_status = crypt_status(self->crypt_device, self->mapped_name);

    switch (cryptsetup_status) {
        case CRYPT_INVALID:
        case CRYPT_INACTIVE:
            /* Device not active */
            status = CRYPTED_STATUS_UNCONFIGURED;
            break;
        case CRYPT_ACTIVE:
        case CRYPT_BUSY:
            /* Device active, check reencryption status */
            reencrypt_status = crypt_reencrypt_status(self->crypt_device, NULL);
            switch (reencrypt_status) {
                case CRYPT_REENCRYPT_NONE:
                    /* No reencryption, device fully encrypted */
                    status = CRYPTED_STATUS_ENCRYPTED;
                    break;
                case CRYPT_REENCRYPT_CLEAN:
                    /* Reencryption in progress */
                    status = CRYPTED_STATUS_ENCRYPTING;
                    break;
                default:
                    /* Something went wrong */
                    status = CRYPTED_STATUS_FAILED;
                    break;
            }
            break;
        default:
            /* Unknown status */
            status = CRYPTED_STATUS_UNKNOWN;
            break;
    }

    if (self->crypt_device) {
        crypt_free(self->crypt_device);
        self->crypt_device = NULL;
    }

    return status;
}

gpointer
cryptsetup_encryption_thread(Crypted *self)
{
    struct crypt_params_luks2 luks2_params = {0};
    struct crypt_params_reencrypt params = {0};
    struct crypt_device *local_crypt_device = NULL;
    int result;

    g_return_val_if_fail(self != NULL, NULL);

    g_debug("Starting encryption thread");
    g_debug("Header device: %s", self->header_device);
    g_debug("Data device: %s", self->data_device);
    g_debug("Mapped name: %s", self->mapped_name);

    /* Validate device paths before proceeding */
    if (!self->header_device || !self->data_device) {
        g_warning("Header or data device path is NULL");
        crypted_set_status(self, CRYPTED_STATUS_FAILED);
        goto out;
    }

    /* Check if we can access the devices with proper permissions */
    if (access(self->header_device, F_OK | W_OK) != 0) {
        g_warning("Cannot access header device: %s", g_strerror(errno));
        crypted_set_status(self, CRYPTED_STATUS_FAILED);
        goto out;
    }

    if (access(self->data_device, F_OK | W_OK) != 0) {
        g_warning("Cannot access data device: %s", g_strerror(errno));
        crypted_set_status(self, CRYPTED_STATUS_FAILED);
        goto out;
    }

    /* Set up LUKS2 parameters */
    luks2_params.data_device = self->data_device;

    /* Set up reencryption parameters with safe defaults */
    params.resilience = "checksum";
    params.hash = "sha256";
    params.direction = CRYPT_REENCRYPT_FORWARD;
    params.mode = CRYPT_REENCRYPT_ENCRYPT;
    params.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY;
    params.luks2 = &luks2_params;

    /* Initialize a local cryptsetup device instead of using shared one */
    g_debug("Initializing crypt device");
    result = crypt_init(&local_crypt_device, self->header_device);
    if (result < 0 || local_crypt_device == NULL) {
        g_critical("Failed to initialize cryptsetup device: %s", g_strerror(-result));
        crypted_set_status(self, CRYPTED_STATUS_FAILED);
        goto out;
    }

    /* Set data offset to 0 for header device */
    result = crypt_set_data_offset(local_crypt_device, 0);
    if (result < 0) {
        g_debug("Failed to set data offset: %s", g_strerror(-result));
        crypted_set_status(self, CRYPTED_STATUS_FAILED);
        goto out_free_crypt;
    }

    /* Check kernel support for sector size */
    if (SECTOR_SIZE_FORCE || (cryptsetup_get_supported_features() & DM_CRYPT_SECTOR_SIZE)) {
        luks2_params.sector_size = SECTOR_SIZE;
        g_debug("Using sector size: %d", SECTOR_SIZE);
    } else {
        g_warning("Sector size not supported by kernel, falling back to 512");
        luks2_params.sector_size = 512;
    }

    /* Format LUKS2 header */
    g_debug("format LUKS device with cipher: %s, mode: %s, sector_size: %d",
            CIPHER, CIPHER_MODE, luks2_params.sector_size);

    result = crypt_format(local_crypt_device, CRYPT_LUKS2, CIPHER,
                          CIPHER_MODE, NULL, NULL, 512 / 8, &luks2_params);

    if (result < 0) {
        g_critical("Failed to format LUKS device: %s", g_strerror(-result));
        crypted_set_status(self, CRYPTED_STATUS_FAILED);
        goto out_free_crypt;
    }

    g_debug("Format successful, setting persistent flags");

    /* Set persistent LUKS2 flags - failure is non-fatal */
    result = crypt_persistent_flags_set(local_crypt_device, CRYPT_FLAGS_ACTIVATION,
                                        CRYPT_ACTIVATE_ALLOW_DISCARDS);
    if (result < 0)
        g_warning("Failed to set ALLOW_DISCARDS flag: %s", g_strerror(-result));

    g_mutex_lock(&self->encryption_process_mutex);

    /* Validate passphrase before adding keyslot */
    if (!self->passphrase) {
        g_warning("Passphrase is NULL");
        crypted_set_status(self, CRYPTED_STATUS_FAILED);
        g_mutex_unlock(&self->encryption_process_mutex);
        goto out_free_crypt;
    }

    /* Make a local copy of the passphrase */
    char *passphrase_copy = g_strdup(self->passphrase);
    size_t passphrase_len = strlen(passphrase_copy);

    /* Unlock mutex after copying passphrase */
    g_mutex_unlock(&self->encryption_process_mutex);

    /* Add key to LUKS2 volume */
    result = crypt_keyslot_add_by_volume_key(local_crypt_device, CRYPT_ANY_SLOT, NULL,
                                             0, passphrase_copy, passphrase_len);
    if (result < 0) {
        g_warning("Failed to add keyslot: %s", g_strerror(-result));
        crypted_set_status(self, CRYPTED_STATUS_FAILED);
        g_free(passphrase_copy);
        goto out_free_crypt;
    }

    /* Initialize reencryption process */
    g_debug("Initializing reencryption");
    result = crypt_reencrypt_init_by_passphrase(local_crypt_device, NULL,
                                                passphrase_copy, passphrase_len,
                                                CRYPT_ANY_SLOT, 0,
                                                CIPHER, CIPHER_MODE,
                                                &params);

    memset(passphrase_copy, 0, passphrase_len);
    g_free(passphrase_copy);

    if (result < 0) {
        g_warning("Failed to initialize reencryption: %s", g_strerror(-result));
        crypted_set_status(self, CRYPTED_STATUS_FAILED);
        goto out_free_crypt;
    }

    g_debug("Encryption initialized successfully");
    crypted_set_status(self, CRYPTED_STATUS_CONFIGURED);

out_free_crypt:
    if (local_crypt_device)
        crypt_free(local_crypt_device);
out:
    g_mutex_lock(&self->encryption_process_mutex);
    if (self->passphrase) {
        memset(self->passphrase, 0, strlen(self->passphrase));
        g_free(self->passphrase);
        self->passphrase = NULL;
    }
    g_mutex_unlock(&self->encryption_process_mutex);

    return NULL;
}

gboolean
cryptsetup_handle_encrypt(Crypted *self,
                          GDBusMethodInvocation *invocation,
                          const gchar *passphrase)
{
    g_return_val_if_fail(self != NULL, FALSE);

    g_mutex_lock(&self->encryption_process_mutex);

    /* Check if encryption is already in progress or device already encrypted */
    if (self->status != CRYPTED_STATUS_UNCONFIGURED) {
        g_debug("Device is already encrypted or encryption is in progress: status=%d", self->status);
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Device is already encrypted or encryption is in progress");
        g_mutex_unlock(&self->encryption_process_mutex);
        return TRUE;
    }

    /* Check if device supports encryption */
    if (!self->encryption_supported) {
        g_debug("Encryption is not supported on this device");
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Encryption is not supported on this device");
        g_mutex_unlock(&self->encryption_process_mutex);
        return TRUE;
    }

    /* Validate device paths are properly initialized */
    if (!self->header_device || !self->data_device || !self->mapped_name) {
        g_warning("Device paths are not properly initialized");
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Internal error: device paths not properly initialized");
        g_mutex_unlock(&self->encryption_process_mutex);
        return TRUE;
    }

    /* Validate passphrase is not empty */
    if (!passphrase || strlen(passphrase) == 0) {
        g_debug("Empty passphrase provided");
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Empty passphrase not allowed");
        g_mutex_unlock(&self->encryption_process_mutex);
        return TRUE;
    }

    /* Update encryption status to configuring */
    g_debug("Setting status to CONFIGURING");
    crypted_set_status(self, CRYPTED_STATUS_CONFIGURING);

    g_free(self->passphrase);
    self->passphrase = g_strdup(passphrase);

    /* First respond to D-Bus client */
    g_dbus_method_invocation_return_value(invocation, NULL);

    /* Then start encryption in a separate thread */
    g_debug("Creating encryption thread");
    self->encryption_thread = g_thread_new("crypted_thread",
                                           (GThreadFunc) cryptsetup_encryption_thread,
                                           self);

    g_mutex_unlock(&self->encryption_process_mutex);

    return TRUE;
}

gboolean
cryptsetup_handle_change_password(Crypted *self,
                                  GDBusMethodInvocation *invocation,
                                  const gchar *old_passphrase,
                                  const gchar *new_passphrase)
{
    int result;
    gboolean success = FALSE;

    g_return_val_if_fail(self != NULL, FALSE);

    g_mutex_lock(&self->encryption_process_mutex);

    /* Check if device is encrypted */
    if (self->status != CRYPTED_STATUS_ENCRYPTED) {
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Device is not encrypted");
        g_mutex_unlock(&self->encryption_process_mutex);
        return TRUE;
    }

    /* Open the LUKS device */
    if (self->crypt_device == NULL) {
        result = crypt_init(&self->crypt_device, self->header_device);
        if (result < 0) {
            g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                                  "Failed to initialize LUKS device: %s",
                                                  g_strerror(-result));
            g_mutex_unlock(&self->encryption_process_mutex);
            return TRUE;
        }

        result = crypt_load(self->crypt_device, CRYPT_LUKS2, NULL);
        if (result < 0) {
            crypt_free(self->crypt_device);
            self->crypt_device = NULL;
            g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                                  "Failed to load LUKS device: %s",
                                                  g_strerror(-result));
            g_mutex_unlock(&self->encryption_process_mutex);
            return TRUE;
        }
    }

    result = crypt_keyslot_change_by_passphrase(
        self->crypt_device,
        CRYPT_ANY_SLOT,   /* Any keyslot with old passphrase */
        CRYPT_ANY_SLOT,   /* Use the same keyslot */
        old_passphrase, strlen(old_passphrase),
        new_passphrase, strlen(new_passphrase)
    );

    if (result >= 0)
        success = TRUE;

    if (self->crypt_device) {
        crypt_free(self->crypt_device);
        self->crypt_device = NULL;
    }

    g_mutex_unlock(&self->encryption_process_mutex);

    g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", success));
    return TRUE;
}

gboolean
cryptsetup_handle_refresh_status(Crypted *self, GDBusMethodInvocation *invocation)
{
    g_return_val_if_fail(self != NULL, FALSE);

    CryptedStatus new_status = cryptsetup_check_status(self);

    crypted_set_status(self, new_status);

    g_dbus_method_invocation_return_value(invocation, NULL);
    return TRUE;
}
