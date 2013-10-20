/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Nordic Semiconductor Inc.
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

#include <stdbool.h>
#include <errno.h>

#include "lib/uuid.h"
#include "log.h"
#include "plugin.h"
#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "service.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "attio.h"

#define SCAN_PARAMETERS_UUID		"00001813-0000-1000-8000-00805f9b34fb"

#define SCAN_INTERVAL_WIN_UUID		0x2A4F
#define SCAN_REFRESH_UUID		0x2A31

#define SCAN_INTERVAL		0x0060
#define SCAN_WINDOW		0x0030
#define SERVER_REQUIRES_REFRESH	0x00

struct scan {
	struct btd_device *device;
	GAttrib *attrib;
	struct att_range range;
	guint attioid;
	uint16_t interval;
	uint16_t window;
	uint16_t iwhandle;
	uint16_t refresh_handle;
	guint refresh_cb_id;
};

static void write_scan_params(GAttrib *attrib, uint16_t handle)
{
	uint8_t value[4];

	att_put_u16(SCAN_INTERVAL, &value[0]);
	att_put_u16(SCAN_WINDOW, &value[2]);

	gatt_write_cmd(attrib, handle, value, sizeof(value), NULL, NULL);
}

static void refresh_value_cb(const uint8_t *pdu, uint16_t len,
						gpointer user_data)
{
	struct scan *scan = user_data;

	DBG("Server requires refresh: %d", pdu[3]);

	if (pdu[3] == SERVER_REQUIRES_REFRESH)
		write_scan_params(scan->attrib, scan->iwhandle);
}

static void ccc_written_cb(uint8_t status, void *user_data)
{
	struct scan *scan = user_data;

	if (status != 0) {
		error("Write Scan Refresh CCC failed: %s",
						att_ecode2str(status));
		return;
	}

	DBG("Scan Refresh: notification enabled");

	scan->refresh_cb_id = g_attrib_register(scan->attrib,
				ATT_OP_HANDLE_NOTIFY, scan->refresh_handle,
				refresh_value_cb, scan, NULL);
}

static bool discover_descriptor_cb(uint8_t status, GSList *descs,
								void *user_data)
{
	struct scan *scan = user_data;
	GSList *l;

	if (status == ATT_ECODE_ATTR_NOT_FOUND)
		return true;

	if (status != 0) {
		error("Discover all GATT characteristic descriptors failed: %s",
							att_ecode2str(status));
		return true;
	}

	for (l = descs; l != NULL; l = g_slist_next(l)) {
		struct gatt_char_desc *desc = l->data;
		uint8_t value[2];
		bt_uuid_t uuid;

		bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
		if (bt_uuid_cmp(&desc->uuid, &uuid) != 0)
			continue;

		att_put_u16(GATT_CLIENT_CHARAC_CFG_NOTIF_BIT, value);
		gatt_write_char(scan->attrib, desc->handle, value,
				sizeof(value), ccc_written_cb, user_data);
	}

	return true;
}

static void refresh_discovered_cb(uint8_t status, GSList *chars,
								void *user_data)
{
	struct scan *scan = user_data;
	struct gatt_char *chr;
	uint16_t start, end;

	if (status) {
		error("Scan Refresh %s", att_ecode2str(status));
		return;
	}

	if (!chars) {
		DBG("Scan Refresh not supported");
		return;
	}

	chr = chars->data;

	DBG("Scan Refresh handle: 0x%04x", chr->value_handle);

	start = chr->value_handle + 1;
	end = scan->range.end;

	if (start > end)
		return;

	scan->refresh_handle = chr->value_handle;

	gatt_discover_char_desc(scan->attrib, start, end,
					discover_descriptor_cb, user_data);
}

static void iwin_discovered_cb(uint8_t status, GSList *chars, void *user_data)
{
	struct scan *scan = user_data;
	struct gatt_char *chr;

	if (status) {
		error("Discover Scan Interval Window: %s",
						att_ecode2str(status));
		return;
	}

	chr = chars->data;
	scan->iwhandle = chr->value_handle;

	DBG("Scan Interval Window handle: 0x%04x", scan->iwhandle);

	write_scan_params(scan->attrib, scan->iwhandle);
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct scan *scan = user_data;
	bt_uuid_t iwin_uuid, refresh_uuid;

	scan->attrib = g_attrib_ref(attrib);

	if (scan->iwhandle) {
		write_scan_params(scan->attrib, scan->iwhandle);
		return;
	}

	bt_uuid16_create(&iwin_uuid, SCAN_INTERVAL_WIN_UUID);
	bt_uuid16_create(&refresh_uuid, SCAN_REFRESH_UUID);

	gatt_discover_char(scan->attrib, scan->range.start, scan->range.end,
					&iwin_uuid, iwin_discovered_cb, scan);

	gatt_discover_char(scan->attrib, scan->range.start, scan->range.end,
				&refresh_uuid, refresh_discovered_cb, scan);
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct scan *scan = user_data;

	g_attrib_unref(scan->attrib);
	scan->attrib = NULL;
}

static int scan_register(struct btd_service *service, struct gatt_primary *prim)
{
	struct btd_device *device = btd_service_get_device(service);
	struct scan *scan;

	scan = g_new0(struct scan, 1);
	scan->device = btd_device_ref(device);
	scan->range = prim->range;
	scan->attioid = btd_device_add_attio_callback(device,
							attio_connected_cb,
							attio_disconnected_cb,
							scan);

	btd_service_set_user_data(service, scan);

	return 0;
}

static void scan_param_remove(struct btd_service *service)
{
	struct scan *scan = btd_service_get_user_data(service);

	if (scan->attrib != NULL && scan->refresh_cb_id > 0)
		g_attrib_unregister(scan->attrib, scan->refresh_cb_id);

	btd_device_remove_attio_callback(scan->device, scan->attioid);
	btd_device_unref(scan->device);
	g_attrib_unref(scan->attrib);
	g_free(scan);
}

static int scan_param_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct gatt_primary *prim;

	DBG("Probing Scan Parameters");

	prim = btd_device_get_primary(device, SCAN_PARAMETERS_UUID);
	if (!prim)
		return -EINVAL;

	return scan_register(service, prim);
}

static struct btd_profile scan_profile = {
	.name = "Scan Parameters Client Driver",
	.remote_uuid = SCAN_PARAMETERS_UUID,
	.device_probe = scan_param_probe,
	.device_remove = scan_param_remove,
};

static int scan_param_init(void)
{
	return btd_profile_register(&scan_profile);
}

static void scan_param_exit(void)
{
	btd_profile_unregister(&scan_profile);
}

BLUETOOTH_PLUGIN_DEFINE(scanparam, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			scan_param_init, scan_param_exit)
