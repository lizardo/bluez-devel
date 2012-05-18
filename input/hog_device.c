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

#define HOG_INFO_UUID		0x2A4A
#define HOG_REPORT_MAP_UUID	0x2A4B
#define HOG_REPORT_UUID		0x2A4D

#define UHID_DEVICE_FILE	"/dev/uhid"

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

struct hog_device {
	char			*path;
	struct btd_device	*device;
	GAttrib			*attrib;
	guint			attioid;
	guint			report_cb_id;
	struct gatt_primary	*hog_primary;
	GSList			*reports;
	int			uhid_fd;
	gboolean		prepend_id;
	guint			uhid_watch_id;
	uint16_t		bcdhid;
	uint8_t			bcountrycode;
	uint8_t			flags;
};

struct report {
	uint8_t			id;
	uint8_t			type;
	struct gatt_char	*decl;
	struct hog_device	*hogdev;
};

static GSList *devices = NULL;

static gint report_handle_cmp(gconstpointer a, gconstpointer b)
{
	const struct report *report = a;
	uint16_t handle = GPOINTER_TO_UINT(b);

	return report->decl->value_handle - handle;
}

static void report_value_cb(const uint8_t *pdu, uint16_t len, gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct uhid_event ev;
	uint16_t report_size = len - 3;
	guint handle;
	GSList *l;
	struct report *report;
	uint8_t *buf;

	if (len < 3) { /* 1-byte opcode + 2-byte handle */
		error("Malformed ATT notification");
		return;
	}

	handle = att_get_u16(&pdu[1]);

	l = g_slist_find_custom(hogdev->reports, GUINT_TO_POINTER(handle),
							report_handle_cmp);
	if (!l) {
		error("Invalid report");
		return;
	}

	report = l->data;

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_INPUT;
	ev.u.input.size = MIN(report_size, UHID_DATA_MAX);

	buf = ev.u.input.data;
	if (hogdev->prepend_id) {
		*buf = report->id;
		buf++;
		ev.u.input.size++;
	}

	memcpy(buf, &pdu[3], MIN(report_size, UHID_DATA_MAX));

	if (write(hogdev->uhid_fd, &ev, sizeof(ev)) < 0)
		error("UHID write failed: %s", strerror(errno));
}

static void report_ccc_written_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	if (status != 0) {
		error("Write report characteristic descriptor failed: %s",
							att_ecode2str(status));
		return;
	}

	DBG("Report characteristic descriptor written: notification enabled");
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
	struct report *report = user_data;

	if (status != 0) {
		error("Read Report Reference descriptor failed: %s",
							att_ecode2str(status));
		return;
	}

	if (plen != 3) {
		error("Malformed ATT read response");
		return;
	}

	report->id = pdu[1];
	report->type = pdu[2];
	DBG("Report ID: 0x%02x Report type: 0x%02x", pdu[1], pdu[2]);
}

static void discover_descriptor_cb(guint8 status, const guint8 *pdu,
					guint16 len, gpointer user_data)
{
	struct report *report = user_data;
	struct hog_device *hogdev = report->hogdev;
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
			write_ccc(handle, hogdev);
		else if (uuid16 == GATT_REPORT_REFERENCE)
			gatt_read_char(hogdev->attrib, handle, 0,
					report_reference_cb, report);
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
	for (i = 0; i < vlen; i++) {
		switch (value[i]) {
			case 0x85:
			case 0x86:
			case 0x87:
				hogdev->prepend_id = TRUE;
		}

		if (i % 2 == 0) {
			if (i + 1 == vlen)
				DBG("\t %02x", value[i]);
			else
				DBG("\t %02x %02x", value[i], value[i + 1]);
		}
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
	strcpy((char *)ev.u.create.name, "bluez-hog-device");
	ev.u.create.vendor = vendor;
	ev.u.create.product = product;
	ev.u.create.version = version;
	ev.u.create.country = hogdev->bcountrycode;
	ev.u.create.bus = BUS_USB; /* BUS_BLUETOOTH doesn't work here */
	ev.u.create.rd_data = value;
	ev.u.create.rd_size = vlen;

	if (write(hogdev->uhid_fd, &ev, sizeof(ev)) < 0)
		error("Failed to create UHID device: %s", strerror(errno));
}

static void info_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	uint8_t value[ATT_MAX_MTU];
	int vlen;

	if (status != 0) {
		error("HID Information read failed: %s",
						att_ecode2str(status));
		return;
	}

	if (plen != 5 || !dec_read_resp(pdu, plen, value, &vlen)) {
		error("ATT protocol error");
		return;
	}

	hogdev->bcdhid = att_get_u16(&pdu[1]);
	hogdev->bcountrycode = pdu[3];
	hogdev->flags = pdu[4];

	DBG("bcdHID: 0x%04X bCountryCode: 0x%02X Flags: 0x%02X",
			hogdev->bcdhid, hogdev->bcountrycode, hogdev->flags);
}

static void char_discovered_cb(GSList *chars, guint8 status, gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	bt_uuid_t report_uuid, report_map_uuid, info_uuid;
	struct report *report;
	GSList *l;
	uint16_t map_handle = 0, info_handle = 0;

	if (status != 0) {
		const char *str = att_ecode2str(status);
		DBG("Discover all characteristics failed: %s", str);
		return;
	}

	bt_uuid16_create(&report_uuid, HOG_REPORT_UUID);
	bt_uuid16_create(&report_map_uuid, HOG_REPORT_MAP_UUID);
	bt_uuid16_create(&info_uuid, HOG_INFO_UUID);

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
			report->hogdev = hogdev;
			report->decl = g_memdup(chr, sizeof(*chr));
			hogdev->reports = g_slist_append(hogdev->reports,
								report);
			discover_descriptor(hogdev->attrib, chr, next, report);
		} else if (bt_uuid_cmp(&uuid, &report_map_uuid) == 0)
			map_handle = chr->value_handle;
		else if (bt_uuid_cmp(&uuid, &info_uuid) == 0)
			info_handle = chr->value_handle;
	}

	if (info_handle)
		gatt_read_char(hogdev->attrib, info_handle, 0,
							info_read_cb, hogdev);

	if (map_handle)
		gatt_read_char(hogdev->attrib, map_handle, 0,
						report_map_read_cb, hogdev);
}

static void output_written_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	if (status != 0) {
		error("Write output report failed: %s", att_ecode2str(status));
		return;
	}
}

static gint report_type_cmp(gconstpointer a, gconstpointer b)
{
	const struct report *report = a;
	uint8_t type = GPOINTER_TO_UINT(b);

	return report->type - type;
}

static void forward_output(struct hog_device *hogdev,
						struct uhid_event *ev)
{
	struct report *report;
	GSList *l;
	void *data;
	int size;

	l = g_slist_find_custom(hogdev->reports, GUINT_TO_POINTER(ev->type),
							report_type_cmp);
	if (!l)
		return;

	report = l->data;

	if (ev->type == UHID_OUTPUT) {
		data = ev->u.output.data;
		size = ev->u.output.size;
	} else {
		data = &ev->u.output_ev.value;
		size = sizeof(ev->u.output_ev.value);
	}

	if (report->decl->properties & ATT_CHAR_PROPER_WRITE)
		gatt_write_char(hogdev->attrib, report->decl->value_handle,
				data, size, output_written_cb, hogdev);
	else if (ATT_CHAR_PROPER_WRITE_WITHOUT_RESP)
		gatt_write_char(hogdev->attrib, report->decl->value_handle,
						data, size, NULL, NULL);
}

static gboolean uhid_event_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct uhid_event ev;
	ssize_t bread;
	int fd;

	DBG("UHID event");

	if (cond & (G_IO_ERR | G_IO_NVAL))
		goto failed;

	fd = g_io_channel_unix_get_fd(io);
	memset(&ev, 0, sizeof(ev));

	bread = read(fd, &ev, sizeof(ev));
	if (bread < 0) {
		int err = errno;
		DBG("uhid-dev read: %s(%d)", strerror(err), err);
		goto failed;
	}

	switch (ev.type) {
	case UHID_START:
		DBG("UHID_START from uhid-dev");
		break;
	case UHID_STOP:
		DBG("UHID_STOP from uhid-dev");
		break;
	case UHID_OPEN:
		DBG("UHID_OPEN from uhid-dev");
		break;
	case UHID_CLOSE:
		DBG("UHID_CLOSE from uhid-dev");
		break;
	case UHID_OUTPUT:
		DBG("UHID_OUTPUT from uhid-dev");
		forward_output(hogdev, &ev);
		break;
	case UHID_OUTPUT_EV:
		DBG("UHID_OUTPUT_EV from uhid-dev");
		forward_output(hogdev, &ev);
		break;
	default:
		DBG("Invalid event from uhid-dev: %u", ev.type);
	}

	return TRUE;

failed:
	hogdev->uhid_watch_id = 0;
	return FALSE;
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct gatt_primary *prim = hogdev->hog_primary;
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_NVAL;
	GIOChannel *io;

	hogdev->attrib = g_attrib_ref(attrib);

	gatt_discover_char(hogdev->attrib, prim->range.start, prim->range.end,
					NULL, char_discovered_cb, hogdev);

	if (hogdev->uhid_fd > 0)
		return;

	hogdev->uhid_fd = open(UHID_DEVICE_FILE, O_RDWR | O_CLOEXEC);
	if (hogdev->uhid_fd < 0)
		error("Failed to open UHID device: %s", strerror(errno));

	hogdev->report_cb_id = g_attrib_register(hogdev->attrib,
					ATT_OP_HANDLE_NOTIFY, report_value_cb,
					hogdev, NULL);

	io = g_io_channel_unix_new(hogdev->uhid_fd);
	g_io_channel_set_encoding(io, NULL, NULL);
	hogdev->uhid_watch_id = g_io_add_watch(io, cond, uhid_event_cb,
								hogdev);
	g_io_channel_unref(io);
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct uhid_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_DESTROY;
	if (write(hogdev->uhid_fd, &ev, sizeof(ev)) < 0)
		error("Failed to destroy UHID device: %s", strerror(errno));

	g_source_remove(hogdev->uhid_watch_id);
	hogdev->uhid_watch_id = 0;

	close(hogdev->uhid_fd);
	hogdev->uhid_fd = -1;

	g_attrib_unregister(hogdev->attrib, hogdev->report_cb_id);
	hogdev->report_cb_id = 0;

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
	if (!hogdev)
		return -ENOMEM;

	hogdev->hog_primary = g_memdup(prim, sizeof(*prim));

	hogdev->attioid = btd_device_add_attio_callback(device,
							attio_connected_cb,
							attio_disconnected_cb,
							hogdev);
	device_set_auto_connect(device, TRUE);

	devices = g_slist_append(devices, hogdev);

	return 0;
}

static void report_free(void *data)
{
	struct report *report = data;
	g_free(report->decl);
	g_free(report);
}

static void hog_device_free(struct hog_device *hogdev)
{
	btd_device_unref(hogdev->device);
	g_slist_free_full(hogdev->reports, report_free);
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
