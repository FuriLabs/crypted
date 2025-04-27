/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#ifndef POLKIT_H
#define POLKIT_H

#include "crypted.h"

/* PolicyKit action IDs */
#define POLKIT_ACTION_ENCRYPT "io.furios.Crypted.Encrypt"
#define POLKIT_ACTION_CHANGE_PASSWORD "io.furios.Crypted.ChangePassword"

/**
 * Initialize the PolicyKit authority
 * @param self The Crypted instance
 * @return TRUE if successful, FALSE otherwise
 */
gboolean
polkit_init(Crypted *self);

/**
 * Check if the caller is authorized for the specified action
 * @param self The Crypted instance
 * @param invocation The D-Bus method invocation
 * @param action The PolicyKit action ID to check
 * @return TRUE if authorized, FALSE otherwise
 */
gboolean
polkit_check_authorization(Crypted *self,
                           GDBusMethodInvocation *invocation,
                           const gchar *action);
#endif /* POLKIT_H */
