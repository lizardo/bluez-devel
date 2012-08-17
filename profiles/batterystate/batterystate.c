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

#include <gdbus.h>
#include <errno.h>
#include <dbus/dbus.h>
#include <bluetooth/uuid.h>

#include "adapter.h"
#include "device.h"
#include "gattrib.h"
#include "attio.h"
#include "att.h"
#include "gattrib.h"
#include "gatt.h"
#include "dbus-common.h"
#include "batterystate.h"
#include "log.h"

#define BATTERY_INTERFACE	"org.bluez.Battery"

#define BATTERY_LEVEL_UUID	"00002a19-0000-1000-8000-00805f9b34fb"

struct battery {
	DBusConnection		*conn;		/* The connection to the bus */
	struct btd_device	*dev;		/* Device reference */
	GAttrib			*attrib;	/* GATT connection */
	guint			attioid;	/* Att watcher id */
	struct att_range	*svc_range;	/* Battery range */
	GSList			*chars;		/* Characteristics */
};

static GSList *servers;

struct characteristic {
	char			*path;          /* object path */
	struct gatt_char	attr;		/* Characteristic */
	struct battery		*batt;		/* Parent Battery Service */
	GSList				*desc;	/* Descriptors */
	uint8_t			ns;		/* Battery Namespace */
	uint16_t		description;	/* Battery description */
	uint8_t			level;		/* Battery last known level */
};

struct descriptor {
	struct characteristic	*ch;		/* Parent Characteristic */
	uint16_t		handle;		/* Descriptor Handle */
	bt_uuid_t		uuid;		/* UUID */
};

static void char_free(gpointer user_data)
{
	struct characteristic *c = user_data;

	g_slist_free_full(c->desc, g_free);

	g_free(c);
}

static void char_interface_free(gpointer user_data)
{
	struct characteristic *c = user_data;
	device_remove_battery(c->batt->dev, c->path);

	g_dbus_unregister_interface(c->batt->conn,
			c->path, BATTERY_INTERFACE);

	g_free(c->path);

	char_free(c);
}

static gint cmp_device(gconstpointer a, gconstpointer b)
{
	const struct battery *batt = a;
	const struct btd_device *dev = b;

	if (dev == batt->dev)
		return 0;

	return -1;
}

static void batterystate_free(gpointer user_data)
{
	struct battery *batt = user_data;

	if (batt->chars != NULL)
		g_slist_free_full(batt->chars, char_interface_free);

	if (batt->attioid > 0)
		btd_device_remove_attio_callback(batt->dev, batt->attioid);

	if (batt->attrib != NULL)
		g_attrib_unref(batt->attrib);


	dbus_connection_unref(batt->conn);
	btd_device_unref(batt->dev);
	g_free(batt->svc_range);
	g_free(batt);
}

static void read_batterylevel_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct characteristic *ch = user_data;
	uint8_t value[ATT_MAX_MTU];
	int vlen;

	if (status != 0) {
		error("Failed to read Battery Level:%s", att_ecode2str(status));
		return;
	}

	vlen = dec_read_resp(pdu, len, value, sizeof(value));
	if (!vlen) {
		error("Failed to read Battery Level: Protocol error\n");
		return;
	}

	if (vlen < 1) {
		error("Failed to read Battery Level: Wrong pdu len");
		return;
	}

	ch->level = value[0];
}

static void process_batteryservice_char(struct characteristic *ch)
{
	if (g_strcmp0(ch->attr.uuid, BATTERY_LEVEL_UUID) == 0) {
		gatt_read_char(ch->batt->attrib, ch->attr.value_handle, 0,
						read_batterylevel_cb, ch);
	}
}

static void batterylevel_presentation_format_desc_cb(guint8 status,
						const guint8 *pdu, guint16 len,
						gpointer user_data)
{
	struct descriptor *desc = user_data;
	uint8_t value[ATT_MAX_MTU];
	int vlen;

	if (status != 0) {
		error("Presentation Format desc read failed: %s",
							att_ecode2str(status));
		return;
	}

	vlen = dec_read_resp(pdu, len, value, sizeof(value));
	if (!vlen) {
		error("Presentation Format desc read failed: Protocol error\n");
		return;
	}

	if (vlen < 7) {
		error("Presentation Format desc read failed: Invalid range");
		return;
	}

	desc->ch->ns = value[4];
	desc->ch->description = att_get_u16(&value[5]);
}


static void process_batterylevel_desc(struct descriptor *desc)
{
	struct characteristic *ch = desc->ch;
	char uuidstr[MAX_LEN_UUID_STR];
	bt_uuid_t btuuid;

	bt_uuid16_create(&btuuid, GATT_CHARAC_FMT_UUID);

	if (bt_uuid_cmp(&desc->uuid, &btuuid) == 0) {
		gatt_read_char(ch->batt->attrib, desc->handle, 0,
				batterylevel_presentation_format_desc_cb, desc);
		return;
	}

	bt_uuid_to_string(&desc->uuid, uuidstr, MAX_LEN_UUID_STR);
	DBG("Ignored descriptor %s characteristic %s", uuidstr,	ch->attr.uuid);
}


static void discover_desc_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct characteristic *ch = user_data;
	struct att_data_list *list;
	uint8_t format;
	int i;

	if (status != 0) {
		error("Discover all characteristic descriptors failed [%s]: %s",
					ch->attr.uuid, att_ecode2str(status));
		return;
	}

	list = dec_find_info_resp(pdu, len, &format);
	if (list == NULL)
		return;

	for (i = 0; i < list->num; i++) {
		struct descriptor *desc;
		uint8_t *value;

		value = list->data[i];
		desc = g_new0(struct descriptor, 1);
		desc->handle = att_get_u16(value);
		desc->ch = ch;

		if (format == 0x01)
			desc->uuid = att_get_uuid16(&value[2]);
		else
			desc->uuid = att_get_uuid128(&value[2]);

		ch->desc = g_slist_append(ch->desc, desc);
		process_batterylevel_desc(desc);
	}

	att_data_list_free(list);
}

static DBusMessage *get_properties(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct characteristic *c = data;
	DBusMessageIter iter;
	DBusMessageIter dict;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_entry(&dict, "Namespace", DBUS_TYPE_BYTE, &c->ns);

	dict_append_entry(&dict, "Description", DBUS_TYPE_UINT16,
							&c->description);

	dict_append_entry(&dict, "Level", DBUS_TYPE_BYTE, &c->level);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable battery_methods[] = {
	{ GDBUS_METHOD("GetProperties",
				NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
				get_properties) },
	{ }
};


static void configure_batterystate_cb(GSList *characteristics, guint8 status,
							gpointer user_data)
{
	struct battery *batt = user_data;
	GSList *l;

	if (status != 0) {
		error("Discover batterystate characteristics: %s",
							att_ecode2str(status));
		return;
	}

	for (l = characteristics; l; l = l->next) {
		struct gatt_char *c = l->data;

		if (g_strcmp0(c->uuid, BATTERY_LEVEL_UUID) == 0) {
			struct characteristic *ch;
			uint16_t start, end;

			ch = g_new0(struct characteristic, 1);
			ch->attr.handle = c->handle;
			ch->attr.properties = c->properties;
			ch->attr.value_handle = c->value_handle;
			memcpy(ch->attr.uuid, c->uuid, MAX_LEN_UUID_STR + 1);
			ch->batt = batt;
			ch->path = g_strdup_printf("%s/BATT%04X",
						device_get_path(batt->dev),
						c->handle);

			device_add_battery(batt->dev, ch->path);

			if (!g_dbus_register_interface(batt->conn, ch->path,
						BATTERY_INTERFACE,
						battery_methods, NULL, NULL,
						ch, NULL)) {
				error("D-Bus register interface %s failed",
							BATTERY_INTERFACE);
				continue;
			}

			process_batteryservice_char(ch);
			batt->chars = g_slist_append(batt->chars, ch);

			start = c->value_handle + 1;

			if (l->next != NULL) {
				struct gatt_char *c = l->next->data;
				if (start == c->handle)
					continue;
				end = c->handle - 1;
			} else if (c->value_handle != batt->svc_range->end)
				end = batt->svc_range->end;
			else
				continue;

			gatt_find_info(batt->attrib, start, end,
							discover_desc_cb, ch);
		}
	}
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct battery *batt = user_data;

	batt->attrib = g_attrib_ref(attrib);

	if (batt->chars == NULL) {
		gatt_discover_char(batt->attrib, batt->svc_range->start,
					batt->svc_range->end, NULL,
					configure_batterystate_cb, batt);
	} else {
		GSList *l;
		for (l = batt->chars; l; l = l->next) {
			struct characteristic *c = l->data;
			process_batteryservice_char(c);
		}
	}
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct battery *batt = user_data;

	g_attrib_unref(batt->attrib);
	batt->attrib = NULL;
}

int batterystate_register(DBusConnection *connection, struct btd_device *device,
						struct gatt_primary *prim)
{
	struct battery *batt;

	batt = g_new0(struct battery, 1);
	batt->dev = btd_device_ref(device);
	batt->conn = dbus_connection_ref(connection);
	batt->svc_range = g_new0(struct att_range, 1);
	batt->svc_range->start = prim->range.start;
	batt->svc_range->end = prim->range.end;

	servers = g_slist_prepend(servers, batt);

	batt->attioid = btd_device_add_attio_callback(device,
				attio_connected_cb, attio_disconnected_cb,
				batt);

	return 0;
}

void batterystate_unregister(struct btd_device *device)
{
	struct battery *batt;
	GSList *l;

	l = g_slist_find_custom(servers, device, cmp_device);
	if (l == NULL)
		return;

	batt = l->data;
	servers = g_slist_remove(servers, batt);

	batterystate_free(batt);
}
