/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012 Texas Instruments, Inc.
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

#include <glib.h>

#include "lib/uuid.h"
#include "plugin.h"
#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "service.h"
#include "attrib/gattrib.h"
#include "attio.h"
#include "attrib/att.h"
#include "attrib/gatt.h"
#include "log.h"

#define PNP_ID_SIZE	7

struct deviceinfo {
	struct btd_device	*dev;		/* Device reference */
	GAttrib			*attrib;	/* GATT connection */
	guint			attioid;	/* Att watcher id */
	struct att_range	*svc_range;	/* DeviceInfo range */
	GSList			*chars;		/* Characteristics */
};

static GSList *servers = NULL;

struct characteristic {
	struct gatt_char	attr;	/* Characteristic */
	struct deviceinfo	*d;	/* deviceinfo where the char belongs */
};

static void deviceinfo_free(gpointer user_data)
{
	struct deviceinfo *d = user_data;

	if (d->attioid > 0)
		btd_device_remove_attio_callback(d->dev, d->attioid);

	if (d->attrib != NULL)
		g_attrib_unref(d->attrib);

	g_slist_free_full(d->chars, g_free);

	btd_device_unref(d->dev);
	g_free(d->svc_range);
	g_free(d);
}

static int cmp_device(gconstpointer a, gconstpointer b)
{
	const struct deviceinfo *d = a;
	const struct btd_device *dev = b;

	if (dev == d->dev)
		return 0;

	return -1;
}

static void read_pnpid_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct characteristic *ch = user_data;
	uint8_t value[PNP_ID_SIZE];
	ssize_t vlen;

	if (status != 0) {
		error("Error reading PNP_ID value: %s", att_ecode2str(status));
		return;
	}

	vlen = dec_read_resp(pdu, len, value, sizeof(value));
	if (vlen < 0) {
		error("Error reading PNP_ID: Protocol error");
		return;
	}

	if (vlen < 7) {
		error("Error reading PNP_ID: Invalid pdu length received");
		return;
	}

	btd_device_set_pnpid(ch->d->dev, value[0], att_get_u16(&value[1]),
				att_get_u16(&value[3]), att_get_u16(&value[5]));
}

static void process_deviceinfo_char(struct characteristic *ch)
{
	if (g_strcmp0(ch->attr.uuid, PNPID_UUID) == 0)
		gatt_read_char(ch->d->attrib, ch->attr.value_handle,
							read_pnpid_cb, ch);
}

static bool configure_deviceinfo_cb(uint8_t status, GSList *characteristics,
								void *user_data)
{
	struct deviceinfo *d = user_data;
	GSList *l;

	if (status != 0) {
		error("Discover deviceinfo characteristics: %s",
							att_ecode2str(status));
		return false;
	}

	for (l = characteristics; l; l = l->next) {
		struct gatt_char *c = l->data;
		struct characteristic *ch;

		ch = g_new0(struct characteristic, 1);
		ch->attr.handle = c->handle;
		ch->attr.properties = c->properties;
		ch->attr.value_handle = c->value_handle;
		memcpy(ch->attr.uuid, c->uuid, MAX_LEN_UUID_STR + 1);
		ch->d = d;

		d->chars = g_slist_append(d->chars, ch);

		process_deviceinfo_char(ch);
	}

	return true;
}
static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct deviceinfo *d = user_data;

	d->attrib = g_attrib_ref(attrib);

	gatt_discover_char(d->attrib, d->svc_range->start, d->svc_range->end,
					NULL, configure_deviceinfo_cb, d);
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct deviceinfo *d = user_data;

	g_attrib_unref(d->attrib);
	d->attrib = NULL;
}

static int deviceinfo_register(struct btd_device *device,
						struct gatt_primary *prim)
{
	struct deviceinfo *d;

	d = g_new0(struct deviceinfo, 1);
	d->dev = btd_device_ref(device);
	d->svc_range = g_new0(struct att_range, 1);
	d->svc_range->start = prim->range.start;
	d->svc_range->end = prim->range.end;

	servers = g_slist_prepend(servers, d);

	d->attioid = btd_device_add_attio_callback(device, attio_connected_cb,
						attio_disconnected_cb, d);
	return 0;
}

static void deviceinfo_unregister(struct btd_device *device)
{
	struct deviceinfo *d;
	GSList *l;

	l = g_slist_find_custom(servers, device, cmp_device);
	if (l == NULL)
		return;

	d = l->data;
	servers = g_slist_remove(servers, d);

	deviceinfo_free(d);
}

static int deviceinfo_driver_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct gatt_primary *prim;

	prim = btd_device_get_primary(device, DEVICE_INFORMATION_UUID);
	if (prim == NULL)
		return -EINVAL;

	return deviceinfo_register(device, prim);
}

static void deviceinfo_driver_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);

	deviceinfo_unregister(device);
}

static struct btd_profile deviceinfo_profile = {
	.name		= "deviceinfo",
	.remote_uuid	= DEVICE_INFORMATION_UUID,
	.device_probe	= deviceinfo_driver_probe,
	.device_remove	= deviceinfo_driver_remove
};

static int deviceinfo_init(void)
{
	return btd_profile_register(&deviceinfo_profile);
}

static void deviceinfo_exit(void)
{
	btd_profile_unregister(&deviceinfo_profile);
}

BLUETOOTH_PLUGIN_DEFINE(deviceinfo, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
					deviceinfo_init, deviceinfo_exit)
