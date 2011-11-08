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

#include <stdint.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "adapter.h"
#include "server.h"
#include "log.h"

#define TIME_DUMMY_IFACE "org.bluez.TimeProviderTest"
#define TIME_DUMMY_PATH "/org/bluez/test"

static DBusConnection *connection = NULL;

static DBusMessage *time_updated(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	DBG("");

	current_time_updated();

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable dummy_methods[] = {
	{ GDBUS_METHOD("TimeUpdated", NULL, NULL, time_updated) },
};

int time_provider_init(void)
{
	DBG("");

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (g_dbus_register_interface(connection, TIME_DUMMY_PATH,
					TIME_DUMMY_IFACE, dummy_methods, NULL,
					NULL, NULL, NULL) == FALSE) {
		error("time-dummy interface %s init failed on path %s",
					TIME_DUMMY_IFACE, TIME_DUMMY_PATH);
		dbus_connection_unref(connection);

		return -1;
	}

	return 0;
}

void time_provider_exit(void)
{
	DBG("");

	g_dbus_unregister_interface(connection, TIME_DUMMY_PATH,
							TIME_DUMMY_IFACE);
	dbus_connection_unref(connection);
	connection = NULL;
}

void time_provider_status(uint8_t *state, uint8_t *result)
{
	*state = UPDATE_STATE_IDLE;
	*result = UPDATE_RESULT_NOT_ATTEMPTED;
}

uint8_t time_provider_control(int op)
{
	DBG("");

	return 0;
}
