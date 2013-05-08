/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Instituto Nokia de Tecnologia - INdT
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <errno.h>

#include "error.h"
#include "log.h"
#include "plugin.h"
#include "lib/uuid.h"
#include "gdbus/gdbus.h"
#include "dbus-common.h"

#define GATT_OBJECT_PATH		"/org/bluez"
#define GATT_SERVICE_INTERFACE		"org.bluez.gatt.Service1"
#define GATT_MANAGER_INTERFACE		"org.bluez.gatt.Manager1"

/* Attribute access permissions (modes) */
typedef enum {
	ATT_PERM_READ,		/* read-only */
	ATT_PERM_WRITE,		/* write-only */
	ATT_PERM_RDWR,		/* read-write */
} access_mode_t;

struct gatt_characteristic {
	bt_uuid_t uuid;
	uint8_t properties;
	uint16_t ext_properties;	/* extended properties */

	access_mode_t access_modes;	/* access modes for attribute */
	access_mode_t authentication;	/* modes requiring authentication */
	access_mode_t authorization;	/* modes requiring authorization */
	access_mode_t encryption;	/* modes requiring encryption */

	GSList *descriptors;	/* profile specific descriptors */
};

/* FIXME: split into sub-functions */
static DBusMessage *add_characteristic(DBusConnection *conn, DBusMessage *msg,
								void *user_data)
{
	const char *sender, *uuid, *dispatcher_path;
	const char *obj_path = "/org/bluez/test123";
	DBusMessageIter args, iter;

	sender = dbus_message_get_sender(msg);
	DBG("sender %s", sender);

	dbus_message_iter_init(msg, &args);

	/* Characteristic UUID */

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &uuid);
	dbus_message_iter_next(&args);

	/* FIXME: validate and store UUID */
	DBG("Characteristic UUID: %s", uuid);

	/* GATT procedure dispatcher object path */

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &dispatcher_path);
	dbus_message_iter_next(&args);

	/* FIXME: store object path */
	DBG("GATT procedure dispatcher: %s", dispatcher_path);

	/* Characteristic basic/extended properties */

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		return btd_error_invalid_args(msg);

	dbus_message_iter_recurse(&args, &iter);

	while (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING) {
		const char *value;

		dbus_message_iter_get_basic(&iter, &value);

		/* FIXME: validate and store properties */
		DBG("New property: %s", value);

		dbus_message_iter_next(&iter);
	}

	/* Characteristic value permissions */

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		return btd_error_invalid_args(msg);

	dbus_message_iter_recurse(&args, &iter);

	while (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter value, entry, iter2;
		const char *key;

		dbus_message_iter_recurse(&iter, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return btd_error_invalid_args(msg);

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		/* FIXME: validate key */
		DBG("Permission key: %s", key);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return btd_error_invalid_args(msg);

		dbus_message_iter_recurse(&entry, &value);

		if (dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_ARRAY)
			return btd_error_invalid_args(msg);

		dbus_message_iter_recurse(&value, &iter2);

		while (dbus_message_iter_get_arg_type(&iter2) ==
							DBUS_TYPE_STRING) {
			const char *value;

			dbus_message_iter_get_basic(&iter2, &value);

			/* FIXME: validate and store permissions */
			DBG("New permission: %s", value);

			dbus_message_iter_next(&iter);
		}
	}

	/* FIXME: Register disconnect watch */
	/* FIXME: investigate if returning object path is a good idea */

	return g_dbus_create_reply(msg, DBUS_TYPE_OBJECT_PATH, &obj_path,
							DBUS_TYPE_INVALID);
}

static DBusMessage *manager_create_application(DBusConnection *conn,
							DBusMessage *msg,
							void *user_data)
{
	const char *obj_path = "/org/bluez/gatt/application0";
	
	DBG("object path: %s", obj_path);

	return g_dbus_create_reply(msg, DBUS_TYPE_OBJECT_PATH, &obj_path,
							DBUS_TYPE_INVALID);
}


static const GDBusMethodTable service_methods[] = {
	{ GDBUS_METHOD("AddCharacteristic",
		GDBUS_ARGS({ "uuid", "s" }, { "procedure_dispatcher", "o" },
			{ "properties", "as" }, { "permissions", "a{sv}" }),
		GDBUS_ARGS({ "characteristic", "o" }), add_characteristic) },
	{ },
};

static const GDBusMethodTable manager_methods[] = {
	{ GDBUS_METHOD("CreateApplication", NULL,
		GDBUS_ARGS({ "application", "o" }),
		manager_create_application) },
	{ },
};

static int gatt_external_init(void)
{
	if (!g_dbus_register_interface(btd_get_dbus_connection(),
							GATT_OBJECT_PATH,
							GATT_SERVICE_INTERFACE,
							service_methods, NULL,
							NULL, NULL, NULL)) {
                error("D-Bus failed to register %s interface",
                                                        GATT_SERVICE_INTERFACE);
                goto register_service_failed;
	}

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
							GATT_OBJECT_PATH,
							GATT_MANAGER_INTERFACE,
							manager_methods, NULL,
							NULL, NULL, NULL)) {
                error("D-Bus failed to register %s interface",
                                                        GATT_MANAGER_INTERFACE);

                goto register_manager_failed;
	}

	return 0;

register_manager_failed:
	g_dbus_unregister_interface(btd_get_dbus_connection(), GATT_OBJECT_PATH,
							GATT_SERVICE_INTERFACE);
register_service_failed:
	return -EIO;
}

static void gatt_external_exit(void)
{
	g_dbus_unregister_interface(btd_get_dbus_connection(), GATT_OBJECT_PATH,
							GATT_MANAGER_INTERFACE);
	g_dbus_unregister_interface(btd_get_dbus_connection(), GATT_OBJECT_PATH,
							GATT_SERVICE_INTERFACE);
}

BLUETOOTH_PLUGIN_DEFINE(gatt_external, VERSION,
					BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
					gatt_external_init, gatt_external_exit)
