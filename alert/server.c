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
#include <stdlib.h>

#include "att.h"
#include "error.h"
#include "gattrib.h"
#include "adapter.h"
#include "device.h"
#include "att-database.h"
#include "log.h"
#include "attrib-server.h"
#include "gatt-service.h"
#include "server.h"
#include "storage.h"
#include "attio.h"
#include "../src/manager.h"

#define PHONE_ALERT_STATUS_SVC_UUID		0x180E
#define ALERT_NOTIF_SVC_UUID			0x1811

#define ALERT_STATUS_CHR_UUID		0x2A3F
#define RINGER_CP_CHR_UUID		0x2A40
#define RINGER_SETTING_CHR_UUID		0x2A41

#define AGENT_INTERFACE "org.bluez.PhoneAgent"
#define ALERT_INTERFACE "org.bluez.PhoneAlert"

/* OHM plugin D-Bus definitions */
#define OHM_BUS_NAME		"com.nokia.NonGraphicFeedback1"
#define OHM_INTERFACE		"com.nokia.NonGraphicFeedback1"
#define OHM_PATH		"/com/nokia/NonGraphicFeedback1"

enum {
	ALERT_RINGER_STATE = 1 << 0,
	ALERT_VIBRATOR_STATE = 1 << 1,
	ALERT_DISPLAY_STATE = 1 << 2,
};

enum {
	SET_SILENT_MODE = 1,
	MUTE_ONCE,
	CANCEL_SILENT_MODE,
};

enum {
	RINGER_SILENT = 0,
	RINGER_NORMAL = 1,
};

struct agent {
	char *name;
	char *path;
	guint listener_id;
};

static DBusConnection *connection = NULL;
static uint8_t ringer_setting = 0xff;
static uint8_t alert_status = 0xff;
static uint16_t handle_ringer_setting = 0x0000;
static uint16_t handle_alert_status = 0x0000;
static struct agent agent;

struct adapter_ccc {
	struct btd_adapter *adapter;
	uint16_t handle;
};

struct notify_callback {
	struct btd_device *device;
	guint id;
};

static GSList *devices_notify;

static uint16_t handle_new_alert;
static uint16_t handle_new_alert_ccc;

static void agent_operation(const char *operation)
{
	DBusMessage *message;

	if (!agent.name) {
		error("Agent not registered");
		return;
	}

	DBG("%s: agent %s, %s", operation, agent.name, agent.path);

	message = dbus_message_new_method_call(agent.name, agent.path,
						AGENT_INTERFACE, operation);

	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	if (!g_dbus_send_message(connection, message))
		error("D-Bus error: agent_operation %s", operation);
}

static void stop_ringtone(void)
{
	DBusMessage *message;

	message = dbus_message_new_method_call(OHM_BUS_NAME, OHM_PATH,
					OHM_INTERFACE, "StopRingtone");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	if (!g_dbus_send_message(connection, message))
		error("Failed to send D-Bus message");
}

static uint8_t control_point_write(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	DBG("a = %p", a);

	switch (a->data[0]) {
	case SET_SILENT_MODE:
		if (agent.name == NULL)
			return ATT_ECODE_IO;

		agent_operation("SetSilentMode");
		break;
	case MUTE_ONCE:
		stop_ringtone();
		break;
	case CANCEL_SILENT_MODE:
		if (agent.name == NULL)
			return ATT_ECODE_IO;

		agent_operation("CancelSilentMode");
		break;
	default:
		DBG("Unknown mode: 0x%02x", a->data[0]);
	}

	return 0;
}

static uint8_t alert_status_read(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	struct btd_adapter *adapter = user_data;

	if (alert_status == 0xff)
		return ATT_ECODE_IO;

	DBG("a = %p, state = %s", a,
		alert_status & ALERT_RINGER_STATE ? "Active": "Not Active");

	if (a->data == NULL || a->data[0] != alert_status)
		attrib_db_update(adapter, a->handle, NULL, &alert_status,
						sizeof(alert_status), NULL);

	return 0;
}

static uint8_t ringer_setting_read(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	struct btd_adapter *adapter = user_data;

	if (ringer_setting == 0xff)
		return ATT_ECODE_IO;

	DBG("a = %p, setting = %s", a,
			ringer_setting == RINGER_SILENT ? "Silent": "Normal");

	if (a->data == NULL || a->data[0] != ringer_setting)
		attrib_db_update(adapter, a->handle, NULL, &ringer_setting,
						sizeof(ringer_setting), NULL);

	return 0;
}

static void register_phone_alert_service(struct btd_adapter *adapter)
{
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, PHONE_ALERT_STATUS_SVC_UUID);

	/* Phone Alert Status Service */
	gatt_service_add(adapter, GATT_PRIM_SVC_UUID, &uuid,
			/* Alert Status characteristic */
			GATT_OPT_CHR_UUID, ALERT_STATUS_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ |
							ATT_CHAR_PROPER_NOTIFY,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
			alert_status_read, NULL,
			GATT_OPT_CHR_VALUE_GET_HANDLE, &handle_alert_status,
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
			GATT_OPT_CHR_VALUE_GET_HANDLE, &handle_ringer_setting,
			GATT_OPT_INVALID);
}

static uint8_t supp_new_alert_cat_read(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	struct btd_adapter *adapter = user_data;
	uint8_t value = 1 << 3; /* Call */

	DBG("");

	if (a->data == NULL || a->data[0] != value)
		attrib_db_update(adapter, a->handle, NULL, &value,
							sizeof(value), NULL);

	return 0;
}

static uint8_t supp_unread_alert_cat_read(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	struct btd_adapter *adapter = user_data;
	uint8_t value = 0;

	DBG("");

	if (a->data == NULL || a->data[0] != value)
		attrib_db_update(adapter, a->handle, NULL, &value,
							sizeof(value), NULL);

	return 0;
}

enum {
	ENABLE_NEW_INCOMING,
	ENABLE_UNREAD_CAT,
	DISABLE_NEW_INCOMING,
	DISABLE_UNREAD_CAT,
	NOTIFY_NEW_INCOMING,
	NOTIFY_UNREAD_CAT,
};

static uint8_t alert_notif_cp_write(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	DBG("a = %p", a);

	switch (a->data[0]) {
	case ENABLE_NEW_INCOMING:
		DBG("ENABLE_NEW_INCOMING: 0x%02x", a->data[1]);
		break;
	case ENABLE_UNREAD_CAT:
		DBG("ENABLE_UNREAD_CAT: 0x%02x", a->data[1]);
		break;
	case DISABLE_NEW_INCOMING:
		DBG("DISABLE_NEW_INCOMING: 0x%02x", a->data[1]);
		break;
	case DISABLE_UNREAD_CAT:
		DBG("DISABLE_UNREAD_CAT: 0x%02x", a->data[1]);
		if (a->data[1] & (1 << 3)) {
			DBG("Enabling incoming call notification");
		}
		break;
	case NOTIFY_NEW_INCOMING:
		DBG("NOTIFY_NEW_INCOMING: 0x%02x", a->data[1]);
		break;
	case NOTIFY_UNREAD_CAT:
		DBG("NOTIFY_UNREAD_CAT: 0x%02x", a->data[1]);
		break;
	default:
		DBG("0x%02x 0x%02x", a->data[0], a->data[1]);
	}

	return 0;
}

#define SUPP_NEW_ALERT_CAT_CHR_UUID 0x2A47
#define NEW_ALERT_CHR_UUID 0x2A46
#define SUPP_UNREAD_ALERT_CAT_CHR_UUID 0x2A48
#define UNREAD_ALERT_CHR_UUID 0x2A45
#define ALERT_NOTIF_CP_CHR_UUID 0x2A44

static void register_alert_notif_service(struct btd_adapter *adapter)
{
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, ALERT_NOTIF_SVC_UUID);

	/* Alert Notification Service */
	gatt_service_add(adapter, GATT_PRIM_SVC_UUID, &uuid,
			/* Supported New Alert Category */
			GATT_OPT_CHR_UUID, SUPP_NEW_ALERT_CAT_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
			supp_new_alert_cat_read, NULL,
			/* New Alert */
			GATT_OPT_CHR_UUID, NEW_ALERT_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_NOTIFY,
			GATT_OPT_CCC_GET_HANDLE, &handle_new_alert_ccc,
			GATT_OPT_CHR_VALUE_GET_HANDLE, &handle_new_alert,
			/* Supported Unread Alert Category */
			GATT_OPT_CHR_UUID, SUPP_UNREAD_ALERT_CAT_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
			supp_unread_alert_cat_read, NULL,
			/* Unread Alert Status */
			GATT_OPT_CHR_UUID, UNREAD_ALERT_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_NOTIFY,
			/* Alert Notification Control Point */
			GATT_OPT_CHR_UUID, ALERT_NOTIF_CP_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_WRITE,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_WRITE,
			alert_notif_cp_write, NULL,
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
	const char *path, *name, *setting;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_BYTE, &alert_status,
						DBUS_TYPE_STRING, &setting,
							DBUS_TYPE_INVALID))
		return NULL;

	if (agent.name != NULL)
		return btd_error_already_exists(msg);

	DBG("Ringer State (Alert Status): %s",
		alert_status & ALERT_RINGER_STATE ? "Active": "Not Active");

	DBG("Ringer Setting: %s", setting);
	if (g_str_equal(setting, "Silent"))
		ringer_setting = RINGER_SILENT;
	else
		ringer_setting = RINGER_NORMAL;

	name = dbus_message_get_sender(msg);

	DBG("Registering agent: path = %s, name = %s", path, name);

	agent.path = strdup(path);
	agent.name = strdup(name);

	agent.listener_id = g_dbus_add_disconnect_watch(connection, name,
							agent_exited, NULL,
									NULL);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *notify_ringer_setting(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	const char *setting;

	if (agent.name == NULL)
		return NULL;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &setting,
							DBUS_TYPE_INVALID))
		return NULL;

	if (g_str_equal(setting, "Silent"))
		ringer_setting = RINGER_SILENT;
	else
		ringer_setting = RINGER_NORMAL;

	attrib_db_update(adapter, handle_ringer_setting, NULL, &ringer_setting,
						sizeof(ringer_setting), NULL);

	return dbus_message_new_method_return(msg);
}

static void filter_devices_notify(char *key, char *value, void *user_data)
{
	struct adapter_ccc *ccc = user_data;
	struct btd_adapter *adapter = ccc->adapter;
	struct btd_device *device;
	char addr[18];
	uint16_t handle, ccc_val;

	sscanf(key, "%17s#%04hX", addr, &handle);

	DBG("addr %s handle %#x", addr, handle);

	//if (ccc->handle != handle)
	//	return;

	ccc_val = strtol(value, NULL, 16);
	if (!(ccc_val & 0x0001))
		return;

	device = adapter_find_device(adapter, addr);
	if (device == NULL)
		return;

	if (g_slist_find(devices_notify, device))
		return;

	devices_notify = g_slist_append(devices_notify, device);
}

static GSList *devices_to_notify(struct btd_adapter *adapter, uint16_t ccc_hnd)
{
	struct adapter_ccc ccc_list = { adapter, ccc_hnd };
	char filename[PATH_MAX + 1];
	char srcaddr[18];
	bdaddr_t src;

	adapter_get_address(adapter, &src);
	ba2str(&src, srcaddr);

	DBG("srcaddr=%s, ccc_hnd=0x%04x", srcaddr, ccc_hnd);

	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "ccc");

	textfile_foreach(filename, filter_devices_notify, &ccc_list);

	return devices_notify;
}

static void send_notification(GAttrib *attrib, gpointer user_data)
{
	struct notify_callback *callback = user_data;
	uint8_t pdu[ATT_MAX_MTU];
	static uint8_t new_alert[2];
	int len;

	DBG("");
#if 0
	len = enc_notification(handle_alert_status, &alert_status,
					sizeof(alert_status), pdu, sizeof(pdu));
	g_attrib_send(attrib, 0, ATT_OP_HANDLE_NOTIFY, pdu, len,
							NULL, NULL, NULL);
#endif
	new_alert[0] = 0x03;
	new_alert[1] = alert_status & 1;
	len = enc_notification(handle_new_alert, new_alert,
					sizeof(new_alert), pdu, sizeof(pdu));
	g_attrib_send(attrib, 0, ATT_OP_HANDLE_NOTIFY, pdu, len,
							NULL, NULL, NULL);

	btd_device_remove_attio_callback(callback->device, callback->id);
	devices_notify = g_slist_remove(devices_notify, callback->device);
	g_free(callback);
}

static void alert_status_updated(void)
{
	struct btd_adapter *adapter;
	GSList *devices, *l;

	DBG("");

	adapter = manager_get_default_adapter();
	if (adapter == NULL)
		return;

	devices = devices_to_notify(adapter, handle_new_alert_ccc);

	for (l = devices; l; l = l->next) {
		struct btd_device *device = l->data;
		struct notify_callback *callback;

		callback = g_new0(struct notify_callback, 1);
		callback->device = device;

		callback->id = btd_device_add_attio_callback(device,
					send_notification, NULL, callback);
	}
}

static DBusMessage *notify_alert_status(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct btd_adapter *adapter = data;
	uint8_t status;

	if (agent.name == NULL)
		return NULL;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_BYTE, &status,
							DBUS_TYPE_INVALID))
		return NULL;

	if (alert_status != status) {
		if ((alert_status & 1) != (status & 1)) {
			alert_status = status;
			alert_status_updated();
		}
		alert_status = status;
		attrib_db_update(adapter, handle_alert_status, NULL, &alert_status,
						sizeof(alert_status), NULL);
	}

	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable alert_methods[] = {
	{ "RegisterAgent",	"oys",	"",	register_agent		},
	{ "NotifyRingerSetting","s",	"",	notify_ringer_setting	},
	{ "NotifyAlertStatus","y",	"",	notify_alert_status	},
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
	register_alert_notif_service(adapter);

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
