/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
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

#include <errno.h>

#include "gdbus.h"
#include "log.h"

#include "upower.h"

#define UPOWER_BUS_NAME		"org.freedesktop.UPower"
#define UPOWER_PATH		"/org/freedesktop/UPower"
#define UPOWER_INTERFACE	UPOWER_BUS_NAME

static DBusConnection *connection = NULL;
static guint suspending_watch = 0;
static guint resuming_watch = 0;
static suspend_event suspend_callback = NULL;
static resume_event resume_callback = NULL;

static gboolean suspending_cb(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	DBG("UPOWER: Suspending ...");

	suspend_callback();

	return TRUE;
}

static gboolean resuming_cb(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	DBG("UPOWER: Resuming ...");

	resume_callback();

	return TRUE;
}

int upower_init(DBusConnection *conn, suspend_event suspend_cb,
					resume_event resume_cb)
{
	connection = dbus_connection_ref(conn);

	if (suspend_cb) {
		suspending_watch = g_dbus_add_signal_watch(connection,
						UPOWER_BUS_NAME,
						UPOWER_PATH, UPOWER_INTERFACE,
						"Sleeping", suspending_cb,
						NULL, NULL);
		suspend_callback = suspend_cb;
	}

	if (resume_cb) {
		resuming_watch = g_dbus_add_signal_watch(connection,
						UPOWER_BUS_NAME,
						UPOWER_PATH, UPOWER_INTERFACE,
						"Resuming", resuming_cb,
						NULL, NULL);
		resume_callback = resume_cb;
	}

	return 0;
}

void upower_exit(void)
{
	if (suspending_watch)
		g_dbus_remove_watch(connection, suspending_watch);

	if (resuming_watch)
		g_dbus_remove_watch(connection, resuming_watch);

	dbus_connection_unref(connection);
	connection = NULL;
}
