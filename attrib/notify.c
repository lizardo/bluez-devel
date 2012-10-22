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

#include "notify.h"

struct att_notif_ind {
	struct btd_adapter *adapter;
	uint16_t value_handle;
	uint16_t ccc_handle;
};

struct notify_data {
	struct att_notif_ind *notif_ind;
	uint8_t *value;
	size_t len;
};

struct notify_callback {
	struct notify_data *notify_data;
	struct btd_device *device;
	guint id;
};

static GSList *notif_inds = NULL;

struct att_notif_ind *att_create_notif_ind(struct btd_adapter *adapter,
							uint16_t value_handle,
							uint16_t ccc_handle)
{
	struct att_notif_ind *notif_ind = g_new0(struct att_notif_ind, 1);

	notif_ind->adapter = adapter;
	notif_ind->value_handle = value_handle;
	notif_ind->ccc_handle = ccc_handle;

	notif_inds = g_slist_append(notif_inds, notif_ind);
}

void att_destroy_notif_inds(struct btd_adapter *adapter)
{
	GSList *l, *next;

	for (l = notif_inds; l != NULL; l = next) {
		struct att_notif_ind *notif_ind = l->data;

		next = g_slist_next(l);

		if (notif_ind->adapter == adapter) {
			notif_inds = g_slist_remove(notif_inds, notif_ind);
			g_free(notif_ind);
		}
	}
}

static struct btd_device *get_notifiable_device(struct btd_adapter *adapter,
							char *key, char *value,
							uint16_t ccc_handle)
{
	uint16_t hnd, val;
	char addr[18];

	sscanf(key, "%17s#%*hhu#%04hX", addr, &hnd);

	if (hnd != ccc_handle)
		return NULL;

	val = strtol(value, NULL, 16);
	if (!(val & 0x0001))
		return NULL;

	return adapter_find_device(adapter, addr);
}

static void notif_destroy(gpointer user_data)
{
	struct notify_callback *cb = user_data;

	DBG("");

	btd_device_remove_attio_callback(cb->device, cb->id);
	btd_device_unref(cb->device);
	g_free(cb);
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct notify_callback *cb = user_data;
	struct notify_data *nd = cb->notify_data;
	struct att_notif_ind *notif_ind = nd->notif_ind;
	uint8_t *pdu;
	size_t len;

	pdu = g_attrib_get_buffer(attrib, &len);

	len = enc_notification(notif_ind->value_handle, nd->value, nd->len, pdu,
									len);
	g_free(nd->value);
	g_free(nd);
	cb->notify_data = NULL;

	if (len == 0) {
		error("Could not create notification PDU");
		notif_destroy(cb);
		return;
	}

	DBG("Sending ATT notification to %s (value_handle=0x%04x)",
			device_get_path(device), notif_ind->value_handle);

	g_attrib_send(attrib, 0, pdu, len, NULL, cb, notif_destroy);
}

static void filter_devices_notify(char *key, char *value, void *user_data)
{
	struct notify_data *notify_data = user_data;
	struct att_notif_ind *notif_ind = notify_data->notif_ind;
	struct btd_device *device;

	/* Only notify connected devices */
	device = get_notifiable_device(notif_ind->adapter, key, value,
							notif_ind->ccc_handle);
	if (device == NULL || !device_is_connected(device))
		return;

	cb = g_new0(struct notify_callback, 1);
	cb->notify_data = notify_data;
	cb->device = btd_device_ref(device);
	cb->id = btd_device_add_attio_callback(device, attio_connected_cb, NULL,
									cb);
}

int att_send_notification(struct att_notif_ind *notif_ind, const uint8_t *value,
								size_t len)
{
	struct notify_data *notify_data;
	char filename[PATH_MAX + 1];
	char srcaddr[18];

	notify_data = g_new0(struct notify_data, 1);
	notify_data->notif_ind = notif_ind;
	notify_data->value = g_memdup(value, len);
	notify_data->len = len;

	ba2str(adapter_get_address(adapter), srcaddr);
	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "ccc");
	textfile_foreach(filename, filter_devices_notify, notify_data);

	return 0;
}

int att_send_indication(struct att_notif_ind *notif_ind, const uint8_t *value,
				size_t len, att_confirm_cb cb, void *user_data)
{
	/* TODO: implement ATT indication */

	return -ENOSYS;
}
