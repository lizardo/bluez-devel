/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/uhid.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>

#include <glib.h>

#include "log.h"

#include "../src/adapter.h"
#include "../src/device.h"

#include "hog_device.h"

#include "att.h"
#include "gattrib.h"
#include "attio.h"
#include "gatt.h"

#define HOG_REPORT_MAP_UUID	0x2A4B
#define HOG_REPORT_UUID		0x2A4D
#define UHID_DEVICE_FILE	"/dev/uhid"

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

struct report {
	struct gatt_char *decl;
};

struct hog_device {
	char			*path;
	struct btd_device	*device;
	GAttrib			*attrib;
	guint			attioid;
	struct gatt_primary	*hog_primary;
	GSList			*reports;
	int			uhid_fd;
};

static GSList *devices = NULL;

static void report_free(struct report *report)
{
	g_free(report->decl);
	g_free(report);
}

static void report_value_cb(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct uhid_event ev;
	uint16_t handle;
	uint16_t report_size = len - 3;

	if (len < 3) {
		error("Malformed ATT notification");
		return;
	}

	handle = att_get_u16(&pdu[1]);

	DBG("Report(0x%04x): 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x "
				"0x%02x", handle, pdu[2], pdu[3], pdu[4],
				pdu[5], pdu[6], pdu[7], pdu[8], pdu[9]);

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_INPUT;
	ev.u.input.size = MIN(report_size, UHID_DATA_MAX);
	memcpy(ev.u.input.data, &pdu[3], MIN(report_size, UHID_DATA_MAX));

	if (write(hogdev->uhid_fd, &ev, sizeof(ev)) < 0)
		error("UHID write failed: %s", strerror(errno));
}

static void report_ccc_written_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct hog_device *hogdev = user_data;

	if (status != 0) {
		error("Write report characteristic descriptor failed: %s",
							att_ecode2str(status));
		return;
	}

	DBG("Report characteristic descriptor written: notification enabled");

	g_attrib_register(hogdev->attrib, ATT_OP_HANDLE_NOTIFY, report_value_cb,
								hogdev, NULL);
}

static void write_ccc(uint16_t handle, gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	uint8_t value[] = { 0x01, 0x00 };

	gatt_write_char(hogdev->attrib, handle, value, sizeof(value),
					report_ccc_written_cb, hogdev);
}

static void report_reference_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	if (status != 0) {
		error("Read Report Reference descriptor failed: %s",
							att_ecode2str(status));
		return;
	}

	if (plen != 3) {
		error("Malformed ATT read response");
		return;
	}

	DBG("Report ID: 0x%02x Report type: 0x%02x", pdu[1], pdu[2]);
}

static void discover_descriptor_cb(guint8 status, const guint8 *pdu,
					guint16 len, gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct att_data_list *list;
	uint8_t format;
	int i;

	if (status != 0) {
		error("Discover all characteristic descriptors failed: %s",
							att_ecode2str(status));
		return;
	}

	list = dec_find_info_resp(pdu, len, &format);
	if (list == NULL)
		return;

	if (format != 0x01)
		goto done;

	for (i = 0; i < list->num; i++) {
		uint16_t uuid16, handle;
		uint8_t *value;

		value = list->data[i];
		handle = att_get_u16(value);
		uuid16 = att_get_u16(&value[2]);

		if (uuid16 == GATT_CLIENT_CHARAC_CFG_UUID)
			write_ccc(handle, user_data);
		else if (uuid16 == GATT_REPORT_REFERENCE)
			gatt_read_char(hogdev->attrib, handle, 0,
					report_reference_cb, hogdev);
	}

done:
	att_data_list_free(list);
}

static void discover_descriptor(GAttrib *attrib, struct gatt_char *chr,
				struct gatt_char *next, gpointer user_data)
{
	uint16_t start, end;

	start = chr->value_handle + 1;
	end = (next ? next->handle - 1 : 0xffff);

	if (start >= end)
		return;

	gatt_find_info(attrib, start, end, discover_descriptor_cb, user_data);
}

static void report_map_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct uhid_event ev;
	uint8_t value[ATT_MAX_MTU];
	uint16_t vendor_src, vendor, product, version;
	int vlen, i;

	if (status != 0) {
		error("Report Map read failed: %s", att_ecode2str(status));
		return;
	}

	if (!dec_read_resp(pdu, plen, value, &vlen)) {
		error("ATT protocol error");
		return;
	}

	DBG("Report MAP:");
	for (i = 0; i < vlen; i += 2) {
		if (i + 1 == vlen)
			DBG("\t %02x", value[i]);
		else
			DBG("\t %02x %02x", value[i], value[i + 1]);
	}

	vendor_src = btd_device_get_vendor_src(hogdev->device);
	vendor = btd_device_get_vendor(hogdev->device);
	product = btd_device_get_product(hogdev->device);
	version = btd_device_get_version(hogdev->device);
	DBG("DIS information: vendor_src=0x%X, vendor=0x%X, product=0x%X, "
			"version=0x%X",	vendor_src, vendor, product, version);

	/* create UHID device */
	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_CREATE;
	strcpy((char*)ev.u.create.name, "bluez-hog-device");
	ev.u.create.vendor = vendor;
	ev.u.create.product = product;
	ev.u.create.version = version;
	ev.u.create.country = 0; /* get this info from the right place */
	ev.u.create.bus = BUS_USB; /* BUS_BLUETOOTH doesn't work here */
	ev.u.create.rd_data = value;
	ev.u.create.rd_size = vlen;

	if (write(hogdev->uhid_fd, &ev, sizeof(ev)) < 0)
		error("Failed to create UHID device: %s", strerror(errno));
}

static void char_discovered_cb(GSList *chars, guint8 status, gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	bt_uuid_t report_uuid, report_map_uuid;
	struct report *report;
	GSList *l;

	if (status != 0) {
		const char *str = att_ecode2str(status);
		DBG("Discover all characteristics failed: %s", str);
		return;
	}

	bt_uuid16_create(&report_uuid, HOG_REPORT_UUID);
	bt_uuid16_create(&report_map_uuid, HOG_REPORT_MAP_UUID);

	for (l = chars; l; l = g_slist_next(l)) {
		struct gatt_char *chr, *next;
		bt_uuid_t uuid;

		chr = l->data;
		next = l->next ? l->next->data : NULL;

		DBG("0x%04x UUID: %s properties: %02x",
				chr->handle, chr->uuid, chr->properties);

		bt_string_to_uuid(&uuid, chr->uuid);

		if (bt_uuid_cmp(&uuid, &report_uuid) == 0) {
			report = g_new0(struct report, 1);
			report->decl = g_memdup(chr, sizeof(*chr));
			hogdev->reports = g_slist_append(hogdev->reports,
								report);
			discover_descriptor(hogdev->attrib, chr, next, hogdev);
		} else if (bt_uuid_cmp(&uuid, &report_map_uuid) == 0)
			gatt_read_char(hogdev->attrib, chr->value_handle, 0,
						report_map_read_cb, hogdev);
	}
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct gatt_primary *prim = hogdev->hog_primary;

	hogdev->attrib = g_attrib_ref(attrib);

	gatt_discover_char(hogdev->attrib, prim->range.start, prim->range.end,
					NULL, char_discovered_cb, hogdev);

	if (hogdev->uhid_fd > 0)
		return;

	hogdev->uhid_fd = open(UHID_DEVICE_FILE, O_RDWR | O_CLOEXEC);
	if (hogdev->uhid_fd < 0)
		error("Failed to open UHID device: %s", strerror(errno));
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct uhid_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_DESTROY;
	if (write(hogdev->uhid_fd, &ev, sizeof(ev)) < 0)
		error("Failed to destroy UHID device: %s", strerror(errno));

	close(hogdev->uhid_fd);
	hogdev->uhid_fd = -1;

	g_attrib_unref(hogdev->attrib);
	hogdev->attrib = NULL;
}

static struct hog_device *find_device_by_path(GSList *list, const char *path)
{
	for (; list; list = list->next) {
		struct hog_device *hogdev = list->data;

		if (!strcmp(hogdev->path, path))
			return hogdev;
	}

	return NULL;
}

static struct hog_device *hog_device_new(struct btd_device *device,
							const char *path)
{
	struct hog_device *hogdev;

	hogdev = g_new0(struct hog_device, 1);
	if (!hogdev)
		return NULL;

	hogdev->path = g_strdup(path);
	hogdev->device = btd_device_ref(device);

	return hogdev;
}

static gint primary_uuid_cmp(gconstpointer a, gconstpointer b)
{
	const struct gatt_primary *prim = a;
	const char *uuid = b;

	return g_strcmp0(prim->uuid, uuid);
}

static struct gatt_primary *load_hog_primary(struct btd_device *device)
{
	GSList *primaries, *l;

	primaries = btd_device_get_primaries(device);

	l = g_slist_find_custom(primaries, HOG_UUID, primary_uuid_cmp);

	return (l ? l->data : NULL);
}

int hog_device_register(struct btd_device *device, const char *path)
{
	struct hog_device *hogdev;
	struct gatt_primary *prim;

	hogdev = find_device_by_path(devices, path);
	if (hogdev)
		return -EALREADY;

	prim = load_hog_primary(device);
	if (!prim)
		return -EINVAL;

	hogdev = hog_device_new(device, path);
	if (!hogdev) {
		g_free(prim);
		return -ENOMEM;
	}

	hogdev->hog_primary = g_memdup(prim, sizeof(*prim));

	hogdev->attioid = btd_device_add_attio_callback(device,
							attio_connected_cb,
							attio_disconnected_cb,
							hogdev);
	device_set_auto_connect(device, TRUE);

	devices = g_slist_append(devices, hogdev);

	return 0;
}

static void hog_device_free(struct hog_device *hogdev)
{
	btd_device_unref(hogdev->device);
	g_slist_free_full(hogdev->reports, (GDestroyNotify) report_free);
	g_free(hogdev->path);
	g_free(hogdev->hog_primary);
	g_free(hogdev);
}

int hog_device_unregister(const char *path)
{
	struct hog_device *hogdev;

	hogdev = find_device_by_path(devices, path);
	if (hogdev == NULL)
		return -EINVAL;

	btd_device_remove_attio_callback(hogdev->device, hogdev->attioid);
	devices = g_slist_remove(devices, hogdev);
	hog_device_free(hogdev);

	return 0;
}
