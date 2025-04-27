/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#define G_LOG_DOMAIN "crypted-polkit"

#include "polkit.h"

gboolean
polkit_init(Crypted *self)
{
    GError *error = NULL;

    g_return_val_if_fail(self != NULL, FALSE);

    /* Get polkit authority */
    self->authority = polkit_authority_get_sync(NULL, &error);
    if (error != NULL) {
        g_warning("Failed to get polkit authority: %s", error->message);
        g_error_free(error);
        return FALSE;
    }

    return TRUE;
}

gboolean
polkit_check_authorization(Crypted *self,
                           GDBusMethodInvocation *invocation,
                           const gchar *action)
{
    PolkitSubject *subject;
    PolkitAuthorizationResult *result;
    GError *error = NULL;
    gboolean authorized = FALSE;
    const gchar *sender;

    g_return_val_if_fail(self != NULL, FALSE);
    g_return_val_if_fail(POLKIT_IS_AUTHORITY(self->authority), FALSE);

    /* Register timestamp for timeout handling */
    crypted_register_timestamp(self);

    sender = g_dbus_method_invocation_get_sender(invocation);
    subject = polkit_system_bus_name_new(sender);

    result = polkit_authority_check_authorization_sync(
        self->authority,
        subject,
        action,
        NULL,
        POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
        NULL,
        &error);

    if (result == NULL) {
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Authorization error: %s", error->message);
        g_clear_error(&error);
        g_object_unref(subject);
        return FALSE;
    }

    authorized = polkit_authorization_result_get_is_authorized(result);

    if (!authorized)
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
                                              "Not authorized");

    g_object_unref(subject);
    g_object_unref(result);

    return authorized;
}
