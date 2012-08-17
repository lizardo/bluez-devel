/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia
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

#include "log.h"
#include "../src/adapter.h"
#include "../src/device.h"
#include "gdbus.h"

#include "plugin.h"
#include "hcid.h"
#include "device.h"
#include "upower.h"
#include "hog_device.h"

static DBusConnection *connection = NULL;
static GSList *devices = NULL;

static void set_suspend(gpointer data, gpointer user_data)
{
	struct hog_device *hogdev = data;
	gboolean suspend = GPOINTER_TO_INT(user_data);

	hog_device_set_control_point(hogdev, suspend);
}

static void suspend_event_cb(void)
{
	gboolean suspend = TRUE;

	g_slist_foreach(devices, set_suspend, GINT_TO_POINTER(suspend));
}

static void resume_event_cb(void)
{
	gboolean suspend = FALSE;

	g_slist_foreach(devices, set_suspend, GINT_TO_POINTER(suspend));
}

static int hog_device_probe(struct btd_device *device, GSList *uuids)
{
	const char *path = device_get_path(device);
	struct hog_device *hogdev;
	int err;

	DBG("path %s", path);

	hogdev = hog_device_find(devices, path);
	if (hogdev)
		return -EALREADY;

	hogdev = hog_device_register(device, path, &err);
	if (hogdev == NULL)
		return err;

	devices = g_slist_append(devices, hogdev);

	return 0;
}

static void hog_device_remove(struct btd_device *device)
{
	const gchar *path = device_get_path(device);
	struct hog_device *hogdev;

	DBG("path %s", path);

	hogdev = hog_device_find(devices, path);
	if (hogdev) {
		devices = g_slist_remove(devices, hogdev);
		hog_device_unregister(hogdev);
	}
}

static struct btd_device_driver hog_driver = {
	.name	= "input-hog",
	.uuids	= BTD_UUIDS(HOG_UUID),
	.probe	= hog_device_probe,
	.remove	= hog_device_remove,
};

static int hog_manager_init(void)
{
	int err;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	err = upower_init(connection, suspend_event_cb, resume_event_cb);
	if (err < 0)
		DBG("UPower: %s(%d)", strerror(-err), -err);

	return btd_register_device_driver(&hog_driver);
}

static void hog_manager_exit(void)
{
	upower_exit();

	dbus_connection_unref(connection);
	connection = NULL;

	btd_unregister_device_driver(&hog_driver);
}

static int hog_init(void)
{
	if (!main_opts.gatt_enabled) {
		DBG("GATT is disabled");
		return -ENOTSUP;
	}

	return hog_manager_init();
}

static void hog_exit(void)
{
	if (!main_opts.gatt_enabled)
		return;

	hog_manager_exit();
}

BLUETOOTH_PLUGIN_DEFINE(hog, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							hog_init, hog_exit)
