/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef CRYPTSETUP_H
#define CRYPTSETUP_H

#include "crypted.h"

/* Feature flags for dm-crypt */
enum {
    DM_CRYPT_SECTOR_SIZE = 1 << 0,
};

/**
 * Get supported cryptographic features from the kernel
 * @return Bitmask of supported feature flags
 */
int
cryptsetup_get_supported_features(void);

/**
 * Check the current status of the encryption device
 * @param self The Crypted instance
 * @return The current encryption status
 */
CryptedStatus
cryptsetup_check_status(Crypted *self);

/**
 * Thread function to perform disk encryption
 * @param self The Crypted instance
 * @return NULL (required for thread functions)
 */
gpointer
cryptsetup_encryption_thread(Crypted *self);

/**
 * Handle the Encrypt D-Bus method
 * @param self The Crypted instance
 * @param invocation The D-Bus method invocation
 * @param passphrase The encryption passphrase
 * @return TRUE if method handling was successful
 */
gboolean
cryptsetup_handle_encrypt(Crypted *self,
                          GDBusMethodInvocation *invocation,
                          const gchar *passphrase);

/**
 * Handle the ChangePassword D-Bus method
 * @param self The Crypted instance
 * @param invocation The D-Bus method invocation
 * @param old_passphrase The current passphrase
 * @param new_passphrase The new passphrase to set
 * @return TRUE if method handling was successful
 */
gboolean
cryptsetup_handle_change_password(Crypted *self,
                                  GDBusMethodInvocation *invocation,
                                  const gchar *old_passphrase,
                                  const gchar *new_passphrase);

/**
 * Handle the RefreshStatus D-Bus method
 * @param self The Crypted instance
 * @param invocation The D-Bus method invocation
 * @return TRUE if method handling was successful
 */
gboolean
cryptsetup_handle_refresh_status(Crypted *self,
                                 GDBusMethodInvocation *invocation);

#endif /* CRYPTSETUP_H */
