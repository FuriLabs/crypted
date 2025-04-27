/**
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>
 */

#define G_LOG_DOMAIN "crypted"

#include <glib-unix.h>

#include "crypted.h"
#include "polkit.h"
#include "cryptsetup.h"

const gchar introspection_xml[] =
"<node>"
"  <interface name='io.furios.Crypted'>"
"    <method name='Encrypt'>"
"      <arg type='s' name='passphrase' direction='in'/>"
"    </method>"
"    <method name='ChangePassword'>"
"      <arg type='s' name='old_passphrase' direction='in'/>"
"      <arg type='s' name='new_passphrase' direction='in'/>"
"      <arg type='b' name='success' direction='out'/>"
"    </method>"
"    <method name='RefreshStatus'>"
"    </method>"
"    <property name='Status' type='u' access='read'/>"
"    <property name='EncryptionSupported' type='b' access='read'/>"
"  </interface>"
"</node>";

void
crypted_register_timestamp(Crypted *self)
{
    g_return_if_fail(self != NULL);
    self->last_call_timestamp = g_get_monotonic_time();
}

void
handle_method_call(GDBusConnection *connection,
                   const gchar *sender,
                   const gchar *object_path,
                   const gchar *interface_name,
                   const gchar *method_name,
                   GVariant *parameters,
                   GDBusMethodInvocation *invocation,
                   gpointer user_data)
{
    Crypted *self = (Crypted *)user_data;

    /* Register timestamp for timeout handling */
    crypted_register_timestamp(self);

    g_debug("Method %s called", method_name);
    if (g_strcmp0(method_name, "Encrypt") == 0) {
        const gchar *passphrase;

        if (!polkit_check_authorization(self, invocation, POLKIT_ACTION_ENCRYPT)) {
            g_debug("Polkit authorization check failed. skipping method call %s", method_name);
            return;
        }

        g_variant_get(parameters, "(&s)", &passphrase);
        cryptsetup_handle_encrypt(self, invocation, passphrase);
    } else if (g_strcmp0(method_name, "ChangePassword") == 0) {
        const gchar *old_passphrase, *new_passphrase;

        if (!polkit_check_authorization(self, invocation, POLKIT_ACTION_CHANGE_PASSWORD)) {
            g_debug("Polkit authorization check failed. skipping method call %s", method_name);
            return;
        }

        g_variant_get(parameters, "(&s&s)", &old_passphrase, &new_passphrase);
        cryptsetup_handle_change_password(self, invocation, old_passphrase, new_passphrase);
    } else if (g_strcmp0(method_name, "RefreshStatus") == 0) {
        cryptsetup_handle_refresh_status(self, invocation);
    } else {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR,
                                              G_DBUS_ERROR_UNKNOWN_METHOD,
                                              "Unknown method: %s", method_name);
    }
}

GVariant *
handle_get_property(GDBusConnection *connection,
                    const gchar *sender,
                    const gchar *object_path,
                    const gchar *interface_name,
                    const gchar *property_name,
                    GError **error,
                    gpointer user_data)
{
    Crypted *self = (Crypted *)user_data;

    /* Register timestamp for timeout handling */
    crypted_register_timestamp(self);

    if (g_strcmp0(property_name, "Status") == 0)
        return g_variant_new_uint32((guint32)self->status);
    else if (g_strcmp0(property_name, "EncryptionSupported") == 0)
        return g_variant_new_boolean(self->encryption_supported);

    g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_PROPERTY,
                "Property %s not found", property_name);
    return NULL;
}

gboolean
handle_set_property(GDBusConnection *connection,
                    const gchar *sender,
                    const gchar *object_path,
                    const gchar *interface_name,
                    const gchar *property_name,
                    GVariant *value,
                    GError **error,
                    gpointer user_data)
{
    g_set_error(error, G_DBUS_ERROR, G_DBUS_ERROR_PROPERTY_READ_ONLY,
                "No writable properties");
    return FALSE;
}

void
crypted_emit_properties_changed(Crypted *self, const gchar* property_name)
{
    GVariantBuilder *builder;
    GVariantBuilder *invalidated_builder;
    GError *error = NULL;

    g_return_if_fail(self != NULL);

    g_debug("Property %s changed", property_name);

    builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

    if (g_strcmp0(property_name, "Status") == 0)
        g_variant_builder_add(builder, "{sv}", "Status",
                              g_variant_new_uint32((guint32)self->status));
    else if (g_strcmp0(property_name, "EncryptionSupported") == 0)
        g_variant_builder_add(builder, "{sv}", "EncryptionSupported",
                              g_variant_new_boolean(self->encryption_supported));

    invalidated_builder = g_variant_builder_new(G_VARIANT_TYPE("as"));

    g_dbus_connection_emit_signal(self->connection,
                                  NULL,
                                  "/io/furios/Crypted",
                                  "org.freedesktop.DBus.Properties",
                                  "PropertiesChanged",
                                  g_variant_new("(sa{sv}as)",
                                                "io.furios.Crypted",
                                                builder,
                                                invalidated_builder),
                                  &error);

    if (error != NULL) {
        g_warning("Failed to emit PropertiesChanged: %s", error->message);
        g_error_free(error);
    }

    g_variant_builder_unref(builder);
    g_variant_builder_unref(invalidated_builder);
}

static const GDBusInterfaceVTable interface_vtable = {
    handle_method_call,
    handle_get_property,
    handle_set_property
};

void
crypted_set_status(Crypted *self, CryptedStatus status)
{
    g_return_if_fail(self != NULL);

    if (self->status != status) {
        self->status = status;
        crypted_emit_properties_changed(self, "Status");
    }
}

void
crypted_set_encryption_supported(Crypted *self, gboolean supported)
{
    g_return_if_fail(self != NULL);

    if (self->encryption_supported != supported) {
        self->encryption_supported = supported;
        crypted_emit_properties_changed(self, "EncryptionSupported");
    }
}

void
crypted_detect_devices(Crypted *self)
{
    g_return_if_fail(self != NULL);

    /* Check FuriOS paths first */
    if (access(FURIOS_HEADER_PATH, F_OK) == 0 &&
        access(FURIOS_ROOTFS_PATH, F_OK) == 0) {
        self->header_device = g_strdup(FURIOS_HEADER_PATH);
        self->data_device = g_strdup(FURIOS_ROOTFS_PATH);
        self->mapped_name = g_strdup(FURIOS_ENCRYPTED_NAME);
        crypted_set_encryption_supported(self, TRUE);
        g_debug("FuriOS path detected");
        return;
    }

    /* Then check legacy Droidian paths */
    if (access(DROIDIAN_HEADER_PATH, F_OK) == 0 &&
        access(DROIDIAN_ROOTFS_PATH, F_OK) == 0) {
        self->header_device = g_strdup(DROIDIAN_HEADER_PATH);
        self->data_device = g_strdup(DROIDIAN_ROOTFS_PATH);
        self->mapped_name = g_strdup(DROIDIAN_ENCRYPTED_NAME);
        crypted_set_encryption_supported(self, TRUE);
        g_debug("legacy Droidian path detected");
        return;
    }

    /* Neither exists, encryption not supported */
    self->header_device = NULL;
    self->data_device = NULL;
    self->mapped_name = NULL;
    crypted_set_encryption_supported(self, FALSE);
    crypted_set_status(self, CRYPTED_STATUS_UNSUPPORTED);
    g_debug("No compatible path detected, encryption not supported");
}

void
on_bus_acquired(GDBusConnection *connection, const gchar *name, Crypted *self)
{
    guint registration_id;
    GError *error = NULL;

    g_return_if_fail(self != NULL);

    g_debug("Bus acquired: %s", name);

    self->connection = connection;

    registration_id = g_dbus_connection_register_object(
        connection,
        "/io/furios/Crypted",
        self->introspection_data->interfaces[0],
        &interface_vtable,
        self,
        NULL,
        &error);

    if (registration_id == 0) {
        g_warning("Failed to register object: %s", error->message);
        g_error_free(error);
        return;
    }

    /* Check initial device status */
    crypted_detect_devices(self);
    crypted_set_status(self, cryptsetup_check_status(self));
}

void
on_name_acquired(GDBusConnection *connection, const gchar *name, Crypted *self)
{
    g_return_if_fail(self != NULL);
    g_debug("Name acquired: %s", name);
}

void
on_name_lost(GDBusConnection *connection, const gchar *name, Crypted *self)
{
    g_return_if_fail(self != NULL);
    g_debug("Name lost: %s", name);

    /* If we lost the name, quit */
    self->should_quit = TRUE;
    g_main_context_wakeup(NULL);
}

gboolean
crypted_timeout_callback(gpointer user_data)
{
    Crypted *self = (Crypted *)user_data;

    g_return_val_if_fail(self != NULL, G_SOURCE_REMOVE);

    /* Check if it's been more than 5 minutes since the last call */
    if ((g_get_monotonic_time() - self->last_call_timestamp) > 300 * 1000000) {
        /* Safety check for CONFIGURING / CONFIGURED status (service must not exit) */
        if (self->status == CRYPTED_STATUS_CONFIGURING ||
            self->status == CRYPTED_STATUS_CONFIGURED) {
            g_warning("Service will remain in background due to configuring/configured status");
            return G_SOURCE_CONTINUE;
        }

        /* Time to exit */
        g_debug("Idle timeout reached, exiting...");
        self->should_quit = TRUE;
        g_main_context_wakeup(NULL);
        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE;
}

void
crypted_init(Crypted *self)
{
    GError *error = NULL;

    g_return_if_fail(self != NULL);

    self->connection = NULL;
    self->bus_id = 0;
    self->timeout_id = 0;
    self->last_call_timestamp = 0;
    self->encryption_supported = FALSE;
    self->status = CRYPTED_STATUS_UNKNOWN;
    self->header_device = NULL;
    self->data_device = NULL;
    self->mapped_name = NULL;
    self->crypt_device = NULL;
    self->encryption_thread = NULL;
    self->passphrase = NULL;
    self->should_quit = FALSE;

    g_mutex_init(&self->encryption_process_mutex);

    self->introspection_data = g_dbus_node_info_new_for_xml(introspection_xml, &error);
    if (error != NULL) {
        g_error("Failed to parse introspection XML: %s", error->message);
        g_error_free(error);
        return;
    }

    if (!polkit_init(self))
        g_warning("Failed to initialize polkit");

    /* Set up initial timestamp and timeout */
    crypted_register_timestamp(self);
    self->timeout_id = g_timeout_add_seconds(60, crypted_timeout_callback, self);
}

void
crypted_free(Crypted *self)
{
    g_return_if_fail(self != NULL);

    g_debug("Cleaning up");

    /* Wait for encryption thread to finish if running */
    if (self->encryption_thread) {
        g_thread_join(self->encryption_thread);
        self->encryption_thread = NULL;
    }

    g_mutex_clear(&self->encryption_process_mutex);

    if (self->timeout_id > 0) {
        g_source_remove(self->timeout_id);
        self->timeout_id = 0;
    }

    if (self->bus_id > 0) {
        g_bus_unown_name(self->bus_id);
        self->bus_id = 0;
    }

    if (self->introspection_data) {
        g_dbus_node_info_unref(self->introspection_data);
        self->introspection_data = NULL;
    }

    if (self->authority) {
        g_object_unref(self->authority);
        self->authority = NULL;
    }

    if (self->crypt_device) {
        crypt_free(self->crypt_device);
        self->crypt_device = NULL;
    }

    g_free(self->header_device);
    g_free(self->data_device);
    g_free(self->mapped_name);
    g_free(self->passphrase);
}

void
crypted_own_name(Crypted *self)
{
    g_return_if_fail(self != NULL);

    if (self->bus_id == 0) {
        self->bus_id = g_bus_own_name(
            G_BUS_TYPE_SYSTEM,
            "io.furios.Crypted",
            G_BUS_NAME_OWNER_FLAGS_NONE,
            (GBusAcquiredCallback) on_bus_acquired,
            (GBusNameAcquiredCallback) on_name_acquired,
            (GBusNameLostCallback) on_name_lost,
            self,
            NULL);
    }
}

gboolean
handle_unix_signal(gpointer user_data)
{
    Crypted *self = (Crypted *)user_data;

    g_return_val_if_fail(self != NULL, G_SOURCE_REMOVE);

    g_warning("Received termination signal, exiting...");

    self->should_quit = TRUE;
    g_main_context_wakeup(NULL);

    return G_SOURCE_REMOVE;
}

int
main(int argc, char *argv[])
{
    Crypted crypted;

    crypted_init(&crypted);

    g_unix_signal_add(SIGTERM, handle_unix_signal, &crypted);
    g_unix_signal_add(SIGINT, handle_unix_signal, &crypted);

    crypted_own_name(&crypted);

    GMainContext *main_context = g_main_context_default();

    while (!crypted.should_quit) {
        g_main_context_iteration(main_context, TRUE);
    }

    crypted_free(&crypted);

    return EXIT_SUCCESS;
}
