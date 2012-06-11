/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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
#include <gdbus.h>
#include <errno.h>
#include <bluetooth/uuid.h>

#include "att.h"
#include "error.h"
#include "gattrib.h"
#include "adapter.h"
#include "device.h"
#include "att-database.h"
#include "log.h"
#include "gatt-service.h"
#include "server.h"

#define PHONE_ALERT_STATUS_SVC_UUID		0x180E
#define RINGER_CP_CHR_UUID		0x2A40
#define RINGER_SETTING_CHR_UUID		0x2A41

#define ALERT_INTERFACE "org.bluez.PhoneAlert"

struct agent {
	char *name;
	char *path;
	guint listener_id;
};

static DBusConnection *connection = NULL;
static struct agent agent;

static uint8_t control_point_write(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	DBG("a = %p", a);

	return 0;
}

static uint8_t ringer_setting_read(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	DBG("a = %p", a);

	return 0;
}

static void register_phone_alert_service(struct btd_adapter *adapter)
{
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, PHONE_ALERT_STATUS_SVC_UUID);

	/* Phone Alert Status Service */
	gatt_service_add(adapter, GATT_PRIM_SVC_UUID, &uuid,
			/* Ringer Control Point characteristic */
			GATT_OPT_CHR_UUID, RINGER_CP_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_WRITE_WITHOUT_RESP,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_WRITE,
			control_point_write, NULL,
			/* Ringer Setting characteristic */
			GATT_OPT_CHR_UUID, RINGER_SETTING_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ |
							ATT_CHAR_PROPER_NOTIFY,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
			ringer_setting_read, NULL,
			GATT_OPT_INVALID);
}

static void agent_exited(DBusConnection *conn, void *user_data)
{
	DBG("Agent exiting ...");

	g_free(agent.path);
	g_free(agent.name);

	agent.path = NULL;
	agent.name = NULL;
}

static DBusMessage *register_agent(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *path, *name;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID))
		return NULL;

	if (agent.name != NULL)
		return btd_error_already_exists(msg);

	name = dbus_message_get_sender(msg);

	DBG("Registering agent: path = %s, name = %s", path, name);

	agent.path = strdup(path);
	agent.name = strdup(name);

	agent.listener_id = g_dbus_add_disconnect_watch(connection, name,
							agent_exited, NULL,
									NULL);

	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable alert_methods[] = {
	{ "RegisterAgent",	"o",	"",	register_agent },
	{ }
};

static int alert_server_probe(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	if (!g_dbus_register_interface(connection, path, ALERT_INTERFACE,
						alert_methods, NULL, NULL,
						adapter, NULL)) {
		error("D-Bus failed to register %s interface", ALERT_INTERFACE);
		dbus_connection_unref(connection);
		connection = NULL;

		return -1;
	}

	DBG("Registered interface %s on path %s", ALERT_INTERFACE, path);

	register_phone_alert_service(adapter);

	return 0;
}

static void alert_server_remove(struct btd_adapter *adapter)
{
}

struct btd_adapter_driver alert_server_driver = {
	.name = "gatt-alert-server",
	.probe = alert_server_probe,
	.remove = alert_server_remove,
};

int alert_server_init(void)
{
	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	btd_register_adapter_driver(&alert_server_driver);

	return 0;
}

void alert_server_exit(void)
{
	btd_unregister_adapter_driver(&alert_server_driver);

	dbus_connection_unref(connection);
	connection = NULL;
}
