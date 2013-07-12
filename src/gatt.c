/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Instituto Nokia de Tecnologia - INdT
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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "adapter.h"
#include "device.h"

#include "dbus-common.h"
#include "log.h"
#include "error.h"
#include "uuid.h"
#include "btio.h"
#include "textfile.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt_lib.h"

#include "gatt.h"

#define SERVICE_INTERFACE "org.bluez.gatt.Service1"
#define CHARACTERISTIC_INTERFACE "org.bluez.gatt.Characteristic1"

/*
 * Internal timeout for asynchronous operations. Prevents
 * client that never calls the result callback.
 */
#define TRANSACTION_TIMEOUT	20

struct characteristic {
	char *path;
	char *uuid;
};

struct service {
	char *path;
	char *uuid;
	GDBusClient *client;
	GSList *chrs;
};

struct application {
	char *owner;
	GSList *services;
	unsigned int watch;
};

static GSList *applications = NULL;

struct btd_attribute {
	uint16_t handle;
	bt_uuid_t type;
	btd_attr_read_t read_cb;
	btd_attr_write_t write_cb;
	int read_sec;
	int write_sec;
	int key_size;
	GHashTable *notifiers;
	uint16_t value_len;
	uint8_t value[0];
};

struct attribute_iface {
	struct btd_device *device;
	struct btd_attribute *attr;
};

struct notifier {
	btd_attr_value_t value_cb;
	void *user_data;
};

struct channel {
	struct btd_device *device;
	GAttrib *attrib;
	uint16_t mtu;
	unsigned int id;
};

struct attr_read_data {
	btd_attr_read_result_t func;
	void* user_data;
};

struct attr_write_data {
	btd_attr_write_result_t func;
	void* user_data;
};

struct att_transaction {
	struct btd_attribute *attr;
	struct channel *channel;
};

struct read_by_type_transaction {
	struct channel *channel;
	GList *match;			/* List of matching attributes */
	unsigned int timeout;		/* Asynchronous operation timeout */
	size_t vlen;			/* Pattern: length of each value */
	size_t olen;			/* Output PDU length */
	uint8_t opdu[0];		/* Output PDU */
};

static GList *local_attribute_db = NULL;
static unsigned int next_nofifier_id = 1;
static uint16_t next_handle = 1;
static GIOChannel *bredr_io = NULL;
static GIOChannel *le_io = NULL;
static GHashTable *channels = NULL;

static GSList *attr_proxy_list = NULL;

struct attr_proxy {
	struct btd_attribute *attr;
	GDBusProxy *proxy;
};

static void attr_set_proxy(struct btd_attribute *attr, GDBusProxy *proxy)
{
	struct attr_proxy *attr_proxy;

	attr_proxy = g_new0(struct attr_proxy, 1);

	attr_proxy->proxy = g_dbus_proxy_ref(proxy);
	attr_proxy->attr = attr;

	attr_proxy_list = g_slist_append(attr_proxy_list, attr_proxy);
}

static GDBusProxy *attr_get_proxy(struct btd_attribute *attr)
{
	GSList *list;

	for (list = attr_proxy_list; list; list = g_slist_next(list)) {
		struct attr_proxy *attr_proxy = list->data;

		if (attr_proxy->attr == attr)
			return attr_proxy->proxy;
	}

	return NULL;
}

static void print_attribute(gpointer a, gpointer b)
{
	struct btd_attribute *attr = a;
	char type[MAX_LEN_UUID_STR];
	char value_str[attr->value_len * 2 + 1];
	int i;

	memset(type, 0, sizeof(type));
	bt_uuid_to_string(&attr->type, type, sizeof(type));

	memset(value_str, 0, sizeof(value_str));
	for (i = 0; i < attr->value_len; i++)
		sprintf(&value_str[i * 2], "%02X", attr->value[i]);

	DBG("handle: 0x%04x Type: %s read_cb: %p write_cb: %p value: %s",
			attr->handle, type, attr->read_cb, attr->write_cb, value_str);
}

void btd_gatt_dump_local_attribute_database(void)
{
	DBG("======== begin =========");
	g_list_foreach(local_attribute_db, print_attribute, NULL);
	DBG("========= end ==========");
}

static int seclevel_string2int(const char *level)
{
	if (strcmp("high", level) == 0)
		return BT_SECURITY_HIGH;
	else if (strcmp("medium", level) == 0)
		return BT_SECURITY_MEDIUM;
	else
		return BT_SECURITY_LOW;
}

static void send_error(GAttrib *attrib, uint8_t opcode, uint16_t handle,
								uint8_t ecode)
{
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	size_t plen;

	plen = enc_error_resp(opcode, handle, ecode, pdu, sizeof(pdu));

	g_attrib_send(attrib, 0, pdu, plen, NULL, NULL, NULL);
}

static void destroy_attribute(struct btd_attribute *attr)
{
	if (attr->notifiers != NULL)
		g_hash_table_destroy(attr->notifiers);
	g_free(attr);
}

/* new_const_attribute - Create a new fixed value attribute.
 * @type:	Attribute type in ATT byte order.
 * @value:	Value of the attribute in ATT byte order.
 * @len:	Length of value in bytes.
 *
 * Returns a new attribute.
 */
static struct btd_attribute *new_const_attribute(bt_uuid_t *type,
							uint8_t *value,
							uint16_t len)
{
	struct btd_attribute *attr = g_malloc0(sizeof(struct btd_attribute) +
						len);

	memcpy(&attr->type, type, sizeof(*type));
	memcpy(&attr->value, value, len);
	attr->value_len = len;

	return attr;
}

static struct btd_attribute *new_attribute(bt_uuid_t *type,
						btd_attr_read_t read_cb,
						btd_attr_write_t write_cb)
{
	struct btd_attribute *attr = g_new0(struct btd_attribute, 1);

	memcpy(&attr->type, type, sizeof(*type));
	attr->read_cb = read_cb;
	attr->write_cb = write_cb;
	attr->notifiers = g_hash_table_new_full(g_int_hash, g_int_equal, NULL,
								g_free);

	return attr;
}

static void add_attribute(struct btd_attribute *attr)
{
	/* TODO: Throw error if next_handle overflows */
	attr->handle = next_handle++;

	local_attribute_db = g_list_append(local_attribute_db, attr);
}

static int attribute_cmp(gconstpointer a, gconstpointer b)
{
	const struct btd_attribute *attr1 = a, *attr2 = b;

	return attr1->handle - attr2->handle;
}

static GList *insert_attribute(GList *attr_database, struct btd_attribute *attr)
{
	return g_list_insert_sorted(attr_database, attr, attribute_cmp);
}

struct btd_attribute *btd_gatt_add_service(bt_uuid_t *uuid, bool primary)
{
	struct btd_attribute *attr;
	bt_uuid_t type;
	uint16_t len = bt_uuid_len(uuid);
	uint8_t value[len];

	/* Set attribute type */
	if (primary)
		bt_uuid16_create(&type, GATT_PRIM_SVC_UUID);
	else
		bt_uuid16_create(&type, GATT_SND_SVC_UUID);

	/* Set attribute value */
	att_put_uuid(*uuid, value);

	attr = new_const_attribute(&type, value, len);

	add_attribute(attr);

	return attr;
}

static bool is_service(struct btd_attribute *attr)
{
	if (attr->type.type != BT_UUID16)
		return false;

	if (attr->type.value.u16 == GATT_PRIM_SVC_UUID ||
				attr->type.value.u16 == GATT_SND_SVC_UUID)
		return true;
	else
		return false;

}
void btd_gatt_remove_service(struct btd_attribute *service)
{
	GList *list = g_list_find(local_attribute_db, service);

	if (list == NULL)
		return;

	/* Remove service declaration attribute */
	destroy_attribute(list->data);
	list = g_list_delete_link(list, list);

	/* Remove all characteristics until next service declaration */
	while (list && !is_service(list->data)) {
		destroy_attribute(list->data);
		list = g_list_delete_link(list, list);
	}
}

struct btd_attribute *btd_gatt_add_char(bt_uuid_t *uuid, uint8_t properties,
					btd_attr_read_t read_cb,
					btd_attr_write_t write_cb,
					int read_sec, int write_sec,
					int key_size)
{
	struct btd_attribute *char_decl, *char_value;
	bt_uuid_t type;
	/* Characteristic properties (1 octet), characteristic value attribute
	 * handle (2 octets) and characteristic UUID (2 or 16 octets).
	 */
	uint16_t len = 1 + 2 + bt_uuid_len(uuid);
	uint8_t value[len];

	/*
	 * Create and add the characteristic declaration attribute
	 */
	bt_uuid16_create(&type, GATT_CHARAC_UUID);

	value[0] = properties;

	/* Since we don't know yet the characteristic value attribute handle,
	 * we skip and set it later.
	 */

	att_put_uuid(*uuid, &value[3]);

	char_decl = new_const_attribute(&type, value, len);
	add_attribute(char_decl);

	/*
	 * Create and add the characteristic value attribute
	 */
	char_value = new_attribute(uuid, read_cb, write_cb);
	char_value->read_sec = read_sec;
	char_value->write_sec = write_sec;
	char_value->key_size = key_size;

	add_attribute(char_value);

	/* Update characteristic value handle in characteristic declaration
	 * attribute.
	 */
	att_put_u16(char_value->handle, &char_decl->value[1]);

	return char_value;
}

void btd_gatt_add_char_desc(bt_uuid_t *uuid, btd_attr_read_t read_cb,
				btd_attr_write_t write_cb,
				int read_sec, int write_sec, int key_size)
{
	struct btd_attribute *attr;

	attr = new_attribute(uuid, read_cb, write_cb);
	attr->read_sec = read_sec;
	attr->write_sec = write_sec;
	attr->key_size = key_size;

	add_attribute(attr);
}

GSList *btd_gatt_get_services(GList *database, bt_uuid_t *service)
{
	GList *list;
	GSList *services = NULL;

	for (list = g_list_first(database); list; list = g_list_next(list)) {
		struct btd_attribute *attr = list->data;

		if (is_service(attr)) {
			bt_uuid_t curr_svc;
			if (attr->value_len == 2)
				curr_svc = att_get_uuid16(attr->value);
			else
				curr_svc = att_get_uuid128(attr->value);

			if (!bt_uuid_cmp(&curr_svc, service))
				services = g_slist_prepend(services, attr);
		}
	}

	return services;
}

static bool is_characteristic(struct btd_attribute *attr)
{
	if (attr->type.value.u16 == GATT_CHARAC_UUID)
		return true;
	else
		return false;
}

GSList *btd_gatt_get_chars_decl(GList *database, struct btd_attribute *service,
							bt_uuid_t *type)
{
	GList *list = g_list_find(database, service);
	GSList *chars = NULL;

	if (!list)
		goto error;

	for (list = g_list_next(list); list && !is_service(list->data);
						list = g_list_next(list)) {
		struct btd_attribute *attr = list->data;

		if (is_characteristic(attr)) {
			GList *next_attr = g_list_next(list);
			struct btd_attribute *value_decl = next_attr->data;

			if (!bt_uuid_cmp(&value_decl->type, type))
				chars = g_slist_prepend(chars, attr);

			/*
			 * Avoid searching for a characteristic declaration in
			 * a characteristic value declaration.
			*/
			list = next_attr;
		}
	}

error:
	return chars;
}

struct btd_attribute *btd_gatt_get_char_desc(GList *database,
						struct btd_attribute *chr,
						bt_uuid_t *type)
{
	GList *list = g_list_find(database, chr);

	if (!list)
		goto error;

	for (list = g_list_nth(list, 2); list && !is_service(list->data)
					&& !is_characteristic(list->data);
						list = g_list_next(list)) {
		struct btd_attribute *attr = list->data;

		if (!bt_uuid_cmp(&attr->type, type))
			return attr;
	}

error:
	return NULL;
}

struct btd_attribute *btd_gatt_get_char_value(GList *database,
						struct btd_attribute *chr)
{
	GList *list = g_list_find(database, chr);

	if (!list)
		return NULL;

	list = g_list_next(list);
	return list->data;
}

void btd_gatt_read_attribute(struct btd_device *device,
					struct btd_attribute *attr,
					btd_attr_read_result_t result,
					void *user_data)
{
	if (attr->read_cb)
		attr->read_cb(device, attr, result, user_data);
	else if (attr->value_len > 0)
		result(0, attr->value, attr->value_len, user_data);
	else
		result(ATT_ECODE_READ_NOT_PERM, NULL, 0, user_data);
}

static void client_read_attribute_response(uint8_t status,
						const uint8_t *value,
						size_t vlen, void *user_data)
{
	struct attr_read_data *data = user_data;
	btd_attr_read_result_t func = data->func;

	if (status)
		func(status, NULL, 0, data->user_data);
	else
		func(status, (uint8_t *) value, vlen, data->user_data);

	g_free(data);
}

static void client_read_attribute_cb(struct btd_device *device,
						struct btd_attribute *attr,
						btd_attr_read_result_t result,
						void *user_data)
{
	struct channel *channel;
	struct attr_read_data *data;

	channel = g_hash_table_lookup(channels, device);
	if (channel == NULL || channel->attrib == NULL) {
		result(ATT_ECODE_IO, NULL, 0, user_data);
		return;
	}

	data = g_new0(struct attr_read_data, 1);
	data->func = result;
	data->user_data = user_data;

	if (gatt_read_char(channel->attrib, attr->handle,
				client_read_attribute_response, data) == 0) {
		result(ATT_ECODE_UNLIKELY, NULL, 0, user_data);
		g_free(data);
	}
}

void btd_gatt_write_attribute(struct btd_device *device,
				struct btd_attribute *attr,
				uint8_t *value, size_t len, uint16_t offset,
				btd_attr_write_result_t result,
				void *user_data)
{
	if (attr->write_cb)
		attr->write_cb(device, attr, value, len, offset,
						result, user_data);
	else
		result(ATT_ECODE_WRITE_NOT_PERM, user_data);
}

static void client_write_attribute_response(uint8_t status, void *user_data)
{
	struct attr_write_data *data = user_data;
	btd_attr_write_result_t func = data->func;

	func(status, data->user_data);
	g_free(data);
}

static void client_write_attribute_cb(struct btd_device *device,
					struct btd_attribute *attr,
					uint8_t *value, size_t len,
					uint16_t offset,
					btd_attr_write_result_t result,
					void *user_data)
{
	struct channel *channel;
	struct attr_write_data *data;

	channel = g_hash_table_lookup(channels, device);
	if (channel == NULL || channel->attrib == NULL) {
		result(ATT_ECODE_IO, user_data);
		return;
	}

	data = g_new0(struct attr_write_data, 1);
	data->func = result;
	data->user_data = user_data;

	if (gatt_write_char(channel->attrib, attr->handle, offset, value, len,
				client_write_attribute_response, data) == 0) {
		result(ATT_ECODE_UNLIKELY, user_data);
		g_free(data);
	}
}

unsigned int btd_gatt_add_notifier(struct btd_attribute *attr,
						btd_attr_value_t value_cb,
						void *user_data)
{
	struct notifier *notif;
	unsigned int id;

	if (!attr->notifiers)
		return -1;

	notif = g_new0(struct notifier, 1);
	notif->value_cb = value_cb;
	notif->user_data = user_data;

	id = next_nofifier_id++;
	g_hash_table_insert(attr->notifiers, &id, notif);

	return id;
}

void btd_gatt_remove_notifier(struct btd_attribute *attr, unsigned int id)
{
	if (!attr->notifiers)
		return;

	g_hash_table_remove(attr->notifiers, &id);
}

static struct characteristic *new_characteristic(const char *path,
							const char *uuid)
{
	struct characteristic *chr;

	chr = g_new0(struct characteristic, 1);

	chr->path = g_strdup(path);
	chr->uuid = g_strdup(uuid);

	return chr;
}

static void destroy_char(void *user_data)
{
	struct characteristic *chr = user_data;

	g_free(chr->path);
	g_free(chr->uuid);
	g_free(chr);
}

static void destroy_service(void *data)
{
	struct service *srv = data;

	g_free(srv->path);
	g_free(srv->uuid);

	g_dbus_client_unref(srv->client);

	g_free(srv);
}

static void read_char_setup(DBusMessageIter *iter, void *user_data)
{
	uint16_t value[] = { 0x0000 };

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, value);
}

static void read_char_reply(DBusMessage *msg, void *user_data)
{
	struct attr_read_data *rd = user_data;
	DBusMessageIter args, iter;
	const uint8_t *value;
	int len;

	if (dbus_message_iter_init(msg, &args) == false)
		goto invalid;

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		goto invalid;

	dbus_message_iter_recurse(&args, &iter);
	dbus_message_iter_get_fixed_array(&iter, &value, &len);

	rd->func(0, (uint8_t *) value, len, rd->user_data);

	return;

invalid:
	rd->func(ATT_ECODE_IO, NULL, 0, rd->user_data);
	DBG("Invalid parameters");
}

static void read_char_destroy(void *user_data)
{
	g_free(user_data);
}

static void read_char_cb(struct btd_device *device, struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{
	GDBusProxy *proxy;
	const char *path;
	struct attr_read_data *rd;

	rd = g_new0(struct attr_read_data, 1);
	rd->func = result;
	rd->user_data = user_data;

	proxy = attr_get_proxy(attr);
	path = g_dbus_proxy_get_path(proxy);

	if (!g_dbus_proxy_method_call(proxy, "ReadValue",
						read_char_setup,
						read_char_reply,
						rd,
						read_char_destroy)) {
		error("Could not call ReadValue dbus method");
		result(ATT_ECODE_IO, NULL, 0, user_data);
		read_char_destroy(rd);
		return;
	}

	DBG("Server: Read characteristic callback %s", path);
}

static void write_char_cb(struct btd_device *device, struct btd_attribute *attr,
			uint8_t *value, size_t len, uint16_t offset,
			btd_attr_write_result_t result, void *user_data)
{
	DBG("Server: Write characteristic callback");
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	struct service *srv = user_data;
	DBusMessageIter iter;
	const char *interface;
	const char *path;
	const char *uuid;

	interface = g_dbus_proxy_get_interface(proxy);

	DBG("iface %s", interface);

	if (g_strcmp0(interface, CHARACTERISTIC_INTERFACE) == 0) {
		struct characteristic *chr;
		const char *security;
		int read_sec = BT_SECURITY_LOW, write_sec = BT_SECURITY_LOW;
		bt_uuid_t uuid_value;
		uint8_t properties, key_size = 0;
		struct btd_attribute *attr;

		path = g_dbus_proxy_get_path(proxy);

		if (!g_dbus_proxy_get_property(proxy, "UUID", &iter))
			return;

		dbus_message_iter_get_basic(&iter, &uuid);

		if (g_dbus_proxy_get_property(proxy, "ReadSecurity", &iter)) {
			dbus_message_iter_get_basic(&iter, &security);
			DBG("ReadSecurity: %s", security);
			read_sec = seclevel_string2int(security);
		}

		if (g_dbus_proxy_get_property(proxy, "WriteSecurity", &iter)) {
			dbus_message_iter_get_basic(&iter, &security);
			DBG("WriteSecurity: %s", security);
			write_sec = seclevel_string2int(security);
		}

		if ((read_sec != BT_SECURITY_LOW ||
			write_sec != BT_SECURITY_LOW) &&
			g_dbus_proxy_get_property(proxy, "KeySize", &iter)) {
			dbus_message_iter_get_basic(&iter, &key_size);
			DBG("KeySize: %d", key_size);
		}

		if (!g_dbus_proxy_get_property(proxy, "Properties", &iter)) {
			error("Could not get Properties");
			return;
		}

		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BYTE) {
			error("Invalid type for Properties");
			return;
		}

		dbus_message_iter_get_basic(&iter, &properties);

		bt_string_to_uuid(&uuid_value, uuid);

		chr = new_characteristic(path, uuid);

		srv->chrs = g_slist_append(srv->chrs, chr);

		attr = btd_gatt_add_char(&uuid_value, properties, read_char_cb,
				write_char_cb, read_sec, write_sec, key_size);

		attr_set_proxy(attr, proxy);

		DBG("new char %s uuid %s", path, uuid);
	} else if (g_strcmp0(interface, SERVICE_INTERFACE) == 0) {
		bt_uuid_t uuid_value;

		if (srv->uuid != NULL)
			return;

		if (!g_dbus_proxy_get_property(proxy, "UUID", &iter)) {
			error("Could not get UUID");
			return;
		}

		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
			error("Invalid type for UUID");
			return;
		}

		dbus_message_iter_get_basic(&iter, &uuid);

		srv->uuid = g_strdup(uuid);

		bt_string_to_uuid(&uuid_value, uuid);
		btd_gatt_add_service(&uuid_value, true);

		DBG("uuid %s", uuid);
	}
}

static int char_by_path(const void *a, const void *b)
{
	const struct characteristic *chr = a;
	const char *path = b;

	return g_strcmp0(chr->path, path);
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	GSList *l;
	struct service *srv = user_data;
	struct characteristic *chr;
	const char *interface;
	const char *path;

	interface = g_dbus_proxy_get_interface(proxy);

	DBG("iface %s", interface);

	if (g_strcmp0(interface, CHARACTERISTIC_INTERFACE) != 0)
		return;

	path = g_dbus_proxy_get_path(proxy);

	l = g_slist_find_custom(srv->chrs, path, char_by_path);
	if (l == NULL)
		return;

	chr = l->data;

	srv->chrs = g_slist_remove(srv->chrs, chr);

	destroy_char(chr);
}

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	DBG("iface %s", interface);
}

static struct service *new_service(const char *sender, const char *path)
{
	struct service *srv;

	srv = g_new0(struct service, 1);

	srv->path = g_strdup(path);
	srv->client = g_dbus_client_new(btd_get_dbus_connection(),
							sender, path);
	if (srv->client == NULL) {
		destroy_service(srv);
		return NULL;
	}

	g_dbus_client_set_proxy_handlers(srv->client, proxy_added,
					proxy_removed, property_changed, srv);

	return srv;
}

static void destroy_application(void *data)
{
	struct application *app = data;

	DBG("app %p", app);

	g_free(app->owner);
	g_slist_free_full(app->services, destroy_service);

	if (app->watch > 0)
		g_dbus_remove_watch(btd_get_dbus_connection(), app->watch);

	applications = g_slist_remove(applications, app);

	g_free(app);
}

static void application_disconnected(DBusConnection *conn, void *user_data)
{
	destroy_application(user_data);
}

static struct application *new_application(const char *sender)
{
	struct application *app;

	app = g_new0(struct application, 1);

	app->watch = g_dbus_add_disconnect_watch(btd_get_dbus_connection(),
				sender, application_disconnected, app, NULL);
	if (app->watch == 0) {
		g_free(app);
		return NULL;
	}

	app->owner = g_strdup(sender);

	applications = g_slist_prepend(applications, app);

	return app;
}

static DBusMessage *register_services(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct application *app;
	DBusMessageIter args, iter;

	DBG("Registering GATT Service");

	if (dbus_message_iter_init(msg, &args) == false)
		goto invalid;

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		goto invalid;

	app = new_application(dbus_message_get_sender(msg));
	if (app == NULL)
		return btd_error_failed(msg, "Not enough resources");

	DBG("new app %p", app);

	dbus_message_iter_recurse(&args, &iter);

	while (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_OBJECT_PATH) {
		const char *path;

		dbus_message_iter_get_basic(&iter, &path);

		app->services = g_slist_append(app->services,
						new_service(app->owner, path));

		DBG("path %s", path);

		dbus_message_iter_next(&iter);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

invalid:
	return btd_error_invalid_args(msg);
}

static DBusMessage *unregister_services(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable methods[] = {
	{ GDBUS_EXPERIMENTAL_METHOD("RegisterServices",
				GDBUS_ARGS({ "services", "ao"}), NULL,
				register_services) },
	{ GDBUS_EXPERIMENTAL_METHOD("UnregisterServices", NULL, NULL,
				unregister_services) },
	{ }
};

static gboolean service_property_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct attribute_iface *iface = data;
	struct btd_attribute *attr = iface->attr;
	bt_uuid_t uuid, uuid128;
	char uuidstr[MAX_LEN_UUID_STR];
	const char *str = uuidstr;

	if (attr->value_len == 2) {
		uuid = att_get_uuid16(attr->value);
		bt_uuid_to_uuid128(&uuid, &uuid128);
	} else
		uuid128 = att_get_uuid128(attr->value);

	bt_uuid_to_string(&uuid128, uuidstr, sizeof(uuidstr));

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);

	return TRUE;
}

static gboolean service_property_get_includes(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static gboolean service_property_exists_includes(
					const GDBusPropertyTable *property,
					void *data)
{
	return FALSE;
}

static const GDBusPropertyTable service_properties[] = {
	{ "UUID", "s", service_property_get_uuid },
	{ "Includes", "as", service_property_get_includes, NULL,
					service_property_exists_includes },
	{ }
};

static void read_value_response(int err, uint8_t *value, size_t len,
					void *user_data)
{
	DBusMessage *reply, *msg = user_data;
	DBusMessageIter iter, array;

	if (err) {
		reply = btd_error_failed(msg, att_ecode2str(err));
		goto done;
	}

	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);
	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&value, len);

	dbus_message_iter_close_container(&iter, &array);

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);
}

static DBusMessage *chr_read_value(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct attribute_iface *iface = user_data;
	GList *database = btd_device_get_attribute_database(iface->device);
	struct btd_attribute *value;

	value = btd_gatt_get_char_value(database, iface->attr);

	btd_gatt_read_attribute(iface->device, value,
				read_value_response, dbus_message_ref(msg));

	return NULL;
}

static void write_value_response(int err, void *user_data)
{
	DBusMessage *reply, *msg = user_data;

	if (err) {
		reply = btd_error_failed(msg, att_ecode2str(err));
		goto done;
	}

	reply = dbus_message_new_method_return(msg);

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);
}

static DBusMessage *chr_write_value(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct attribute_iface *iface = user_data;
	struct btd_attribute *attr;
	GList *database;
	DBusMessageIter args, iter;
	const uint8_t *value;
	uint16_t offset;
	int len;

	if (dbus_message_iter_init(msg, &args) == false)
		goto invalid;

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_UINT16)
		goto invalid;

	dbus_message_iter_get_basic(&args, &offset);

	dbus_message_iter_next(&args);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		goto invalid;

	dbus_message_iter_recurse(&args, &iter);

	dbus_message_iter_get_fixed_array(&iter, &value, &len);

	database = btd_device_get_attribute_database(iface->device);
	attr = btd_gatt_get_char_value(database, iface->attr);

	btd_gatt_write_attribute(iface->device, attr, (uint8_t *) value, len,
					offset, write_value_response,
					dbus_message_ref(msg));

	return NULL;

invalid:
	return btd_error_invalid_args(msg);
}

static const GDBusMethodTable chr_methods[] = {
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("ReadValue",
				GDBUS_ARGS({"offset", "q"}),
				GDBUS_ARGS({"value", "ay"}),
				chr_read_value) },
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("WriteValue",
				GDBUS_ARGS({"offset", "q"}, {"value", "ay"}),
				NULL, chr_write_value) },
	{ }
};

static gboolean chr_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct attribute_iface *iface = data;
	struct btd_attribute *attr = iface->attr;
	bt_uuid_t uuid, uuid128;
	char uuidstr[MAX_LEN_UUID_STR];
	const char *str = uuidstr;

	if (attr->value_len - 3 == 2) {
		uuid = att_get_uuid16(&attr->value[3]);
		bt_uuid_to_uuid128(&uuid, &uuid128);
	} else if (attr->value_len - 3 == 16)
		uuid128 = att_get_uuid128(&attr->value[3]);

	bt_uuid_to_string(&uuid128, uuidstr, sizeof(uuidstr));

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);

	return TRUE;
}

static gboolean chr_get_value(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static void chr_set_value(const GDBusPropertyTable *property,
				DBusMessageIter *iter,
				GDBusPendingPropertySet id, void *user_data)
{
	g_dbus_pending_property_error(id, ERROR_INTERFACE ".Failed",
							"Not Supported");
}

static gboolean chr_exist_value(const GDBusPropertyTable *property,
								void *data)
{
	return FALSE;
}

static gboolean chr_get_perms(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static gboolean chr_exist_perms(const GDBusPropertyTable *property,
								void *data)
{
	return FALSE;
}

static gboolean chr_get_auth(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static gboolean chr_exist_auth(const GDBusPropertyTable *property, void *data)
{
	return FALSE;
}

static gboolean chr_get_props(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct attribute_iface *iface = data;
	struct btd_attribute *attr = iface->attr;
	uint8_t prop;

	prop = attr->value[0];

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &prop);

	return TRUE;
}

static gboolean chr_exist_props(const GDBusPropertyTable *property,
								void *data)
{
	return TRUE;
}

static gboolean chr_get_descriptors(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static void chr_set_descriptors(const GDBusPropertyTable *property,
				DBusMessageIter *iter,
				GDBusPendingPropertySet id, void *user_data)
{
	g_dbus_pending_property_success(id);
}

static gboolean chr_exist_descriptors(const GDBusPropertyTable *property,
								void *data)
{
	return FALSE;
}

static const GDBusPropertyTable chr_properties[] = {
	{ "UUID", "s", chr_get_uuid, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Value", "ay", chr_get_value, chr_set_value, chr_exist_value,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Permissions", "y", chr_get_perms, NULL, chr_exist_perms,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Authenticate", "b", chr_get_auth, NULL, chr_exist_auth,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Properties", "y", chr_get_props, NULL, chr_exist_props,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Descriptors", "a{a{sv}}", chr_get_descriptors, chr_set_descriptors,
		chr_exist_descriptors, G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static char *buf2str(const uint8_t *buf, size_t buflen)
{
	size_t i;
	char *str;

	if (buflen == 0)
		return NULL;

	str = g_try_new0(char, (buflen * 2) + 1);
	if (str == NULL)
		return NULL;

	for (i = 0; i < buflen; i++)
		sprintf(str + (i * 2), "%2.2x", buf[i]);

	return str;
}

static int str2buf(const char *str, uint8_t *buf, size_t blen)
{
	int i, dlen;

	if (str == NULL)
		return -EINVAL;

	memset(buf, 0, blen);

	dlen = MIN((strlen(str) / 2), blen);

	for (i = 0; i < dlen; i++)
		sscanf(str + (i * 2), "%02hhX", &buf[i]);

	return dlen;
}

static void store_attribute(struct btd_device *device,
					struct btd_attribute *attr)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	char srcaddr[18], dstaddr[18], handle[6], uuidstr[MAX_LEN_UUID_STR];
	char filename[PATH_MAX + 1], *data;
	const bdaddr_t *src, *dst;
	GKeyFile *key_file;
	size_t len;

	if (device_is_bonded(device) == FALSE)
		return;

	src = adapter_get_address(adapter);
	ba2str(src, srcaddr);

	dst = device_get_address(device);
	ba2str(dst, dstaddr);

	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/%s/attrib-database",
							srcaddr, dstaddr);
	key_file = g_key_file_new();

	g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, NULL);

	snprintf(handle, sizeof(handle), "%hu", attr->handle);

	bt_uuid_to_string(&attr->type, uuidstr, sizeof(uuidstr));
	g_key_file_set_string(key_file, handle, "Type", uuidstr);

	if (attr->value_len > 0) {
		char *str;

		str = buf2str(attr->value, attr->value_len);
		g_key_file_set_string(key_file, handle, "Value", str);

		g_free(str);
	}

	data = g_key_file_to_data(key_file, &len, NULL);
	if (len > 0) {
		create_file(filename, S_IRUSR | S_IWUSR);
		g_file_set_contents(filename, data, len, NULL);
	}

}

static void insert_primary_service(uint8_t status, uint16_t handle,
					uint8_t *value, size_t vlen,
					void *user_data)
{
	struct btd_device *device = user_data;
	struct attribute_iface *iface;
	struct btd_attribute *attr;
	GList *database;
	char *path;
	bt_uuid_t uuid;

	DBG("status %d handle %#4x", status, handle);

	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);

	attr = new_const_attribute(&uuid, value, vlen);
	attr->handle = handle;

	database = btd_device_get_attribute_database(device);

	device_set_attribute_database(device,
					insert_attribute(database, attr));

	store_attribute(device, attr);

	iface = g_new0(struct attribute_iface, 1);
	iface->attr = attr;
	iface->device = device;

	path = g_strdup_printf("%s/service%d", device_get_path(device),
						handle);

	/* FIXME: free how? */
	if (g_dbus_register_interface(btd_get_dbus_connection(),
					path, SERVICE_INTERFACE,
					NULL, NULL, service_properties, iface,
					NULL) == FALSE)
		error("Unable to register service interface for %s", path);

	g_free(path);
}

static void insert_secondary_service(uint8_t status, uint16_t handle,
					uint8_t *value, size_t vlen,
					void *user_data)
{
	struct btd_device *device = user_data;
	GList *database = btd_device_get_attribute_database(device);
	struct btd_attribute *attr;
	bt_uuid_t uuid;

	DBG("status %d handle %#4x", status, handle);

	bt_uuid16_create(&uuid, GATT_SND_SVC_UUID);

	attr = new_const_attribute(&uuid, value, vlen);
	attr->handle = handle;

	device_set_attribute_database(device,
					insert_attribute(database, attr));

	store_attribute(device, attr);
}

static struct btd_attribute *find_parent_service(GList *database,
						struct btd_attribute *attr)
{
	GList *l;

	l = g_list_find(database, attr);
	if (l == NULL)
		return NULL;

	for (; l; l = g_list_previous(l)) {
		struct btd_attribute *a = l->data;

		if (is_service(a))
			return a;
	}

	return NULL;
}

static void insert_char_declaration(uint8_t status, uint16_t handle,
					uint8_t *value, size_t vlen,
					void *user_data)
{
	struct btd_device *device = user_data;
	GList *database = btd_device_get_attribute_database(device);
	struct attribute_iface *iface;
	struct btd_attribute *attr, *parent;
	bt_uuid_t uuid, value_uuid;
	uint16_t value_handle;
	uint8_t value_properties;
	btd_attr_read_t read_cb = NULL;
	btd_attr_write_t write_cb = NULL;

	char *path;

	DBG("status %d handle %#4x", status, handle);

	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);

	attr = new_const_attribute(&uuid, value, vlen);
	attr->handle = handle;

	iface = g_new0(struct attribute_iface, 1);
	iface->attr = attr;
	iface->device = device;

	device_set_attribute_database(device,
					insert_attribute(database, attr));

	store_attribute(device, attr);

	parent = find_parent_service(database, attr);

	path = g_strdup_printf("%s/service%d/characteristics%d",
			device_get_path(device), parent->handle, handle);

	value_properties = value[0];

	value_handle = att_get_u16(&value[1]);

	vlen -= 3; /* Discarding 2 (handle) + 1 (properties) bytes */

	if (vlen == 2)
		value_uuid = att_get_uuid16(&value[3]);
	else if (vlen == 16)
		value_uuid = att_get_uuid128(&value[3]);

	if (value_properties & ATT_CHAR_PROPER_READ)
		read_cb = client_read_attribute_cb;

	if (value_properties & (ATT_CHAR_PROPER_WRITE |
					ATT_CHAR_PROPER_WRITE_WITHOUT_RESP))
		write_cb = client_write_attribute_cb;

	attr = new_attribute(&value_uuid, read_cb, write_cb);
	attr->handle = value_handle;

	device_set_attribute_database(device,
					insert_attribute(database, attr));

	store_attribute(device, attr);

	if (g_dbus_register_interface(btd_get_dbus_connection(), path,
					CHARACTERISTIC_INTERFACE,
					chr_methods, NULL, chr_properties,
					iface, NULL) == FALSE)
		error("Couldn't register characteristic interface");

	g_free(path);
}

static void insert_include(uint8_t status, uint16_t handle,
					uint8_t *value, size_t vlen,
					void *user_data)
{
	struct btd_device *device = user_data;
	GList *database = btd_device_get_attribute_database(device);
	struct btd_attribute *attr;
	bt_uuid_t uuid;

	DBG("status %d handle %#4x", status, handle);

	bt_uuid16_create(&uuid, GATT_INCLUDE_UUID);

	attr = new_const_attribute(&uuid, value, vlen);
	attr->handle = handle;

	device_set_attribute_database(device,
					insert_attribute(database, attr));

	store_attribute(device, attr);
}

static void insert_char_descriptor(uint8_t status, uint16_t handle,
					bt_uuid_t *type, void *user_data)
{
	struct btd_device *device = user_data;
	GList *l, *database = btd_device_get_attribute_database(device);
	struct btd_attribute *attr;

	DBG("status %d handle %#4x", status, handle);

	attr = new_attribute(type, NULL, NULL);
	attr->handle = handle;

	l = g_list_find_custom(database, attr, attribute_cmp);
	if (l != NULL) {
		g_free(attr);
		return;
	}

	device_set_attribute_database(device,
					insert_attribute(database, attr));

	store_attribute(device, attr);
}

bool gatt_load_from_storage(struct btd_device *device)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	char srcaddr[18], dstaddr[18];
	char filename[PATH_MAX + 1];
	char **groups, **group;
	const bdaddr_t *src, *dst;
	GKeyFile *key_file;

	src = adapter_get_address(adapter);
	ba2str(src, srcaddr);

	dst = device_get_address(device);
	ba2str(dst, dstaddr);

	DBG("src %s dst %s", dstaddr, srcaddr);

	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/%s/attrib-database",
							srcaddr, dstaddr);
	key_file = g_key_file_new();

	if (g_key_file_load_from_file(key_file, filename,
					G_KEY_FILE_NONE, NULL) == FALSE) {
		g_key_file_free(key_file);
		return false;
	}

	groups = g_key_file_get_groups(key_file, NULL);

	for (group = groups; *group; group++) {
		uint16_t handle;
		size_t buflen;
		uint8_t buf[32];
		char *uuidstr, *valuestr;
		bt_uuid_t uuid;

		DBG("group %s", *group);

		handle = strtol(*group, NULL, 10);

		uuidstr = g_key_file_get_string(key_file, *group, "Type",
								NULL);
		bt_string_to_uuid(&uuid, uuidstr);

		valuestr = g_key_file_get_string(key_file, *group, "Value",
								NULL);

		buflen = 0;
		if (valuestr)
			buflen = str2buf(valuestr, buf, sizeof(buf));

		if (uuid.type == BT_UUID16) {
			switch (uuid.value.u16) {
			case GATT_PRIM_SVC_UUID:
				insert_primary_service(0, handle, buf,
							buflen, device);
				break;
			case GATT_SND_SVC_UUID:
				insert_secondary_service(0, handle, buf,
							buflen, device);
				break;
			case GATT_CHARAC_UUID:
				insert_char_declaration(0, handle, buf,
							buflen, device);
				break;
			case GATT_INCLUDE_UUID:
				insert_include(0, handle, buf, buflen,
								device);
				break;
			default:
				insert_char_descriptor(0, handle, &uuid,
								device);
			}
		} else {
			insert_char_descriptor(0, handle, &uuid, device);
		}

		g_free(valuestr);
		g_free(uuidstr);
	}

	g_strfreev(groups);

	return true;
}

static void read_name_cb(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result,
				void *user_data)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	const char *name = btd_adapter_get_name(adapter);

	result(0, (uint8_t *) name, strlen(name), user_data);
}

static void read_appearance_cb(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result,
				void *user_data)
{
	uint8_t appearance[] = { 0x00, 0x00 };

	result(0, appearance, sizeof(appearance), user_data);
}

static void ccc_written_cb(struct btd_device *device,
			struct btd_attribute *attr, uint8_t *value,
			size_t len, uint16_t offset,
			btd_attr_write_result_t result, void *user_data)
{
	uint16_t ccc = att_get_u16(value);

	/* FIXME: How to access the sender? Missing proper storage */

	DBG("CCC: 0x%04x", ccc);

	result(0, user_data);
}

static void add_gap(void)
{
	bt_uuid_t uuid;

	/* Primary Service: <<GAP Service>> */
	bt_uuid16_create(&uuid, GENERIC_ACCESS_PROFILE_ID);
	btd_gatt_add_service(&uuid, true);

	/* Declaration and Value: <<Device Name>>*/
	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	btd_gatt_add_char(&uuid, ATT_CHAR_PROPER_READ, read_name_cb, NULL,
					BT_SECURITY_LOW, BT_SECURITY_LOW, 0);

	/* Declaration and Value: <<Appearance>>*/
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	btd_gatt_add_char(&uuid, ATT_CHAR_PROPER_READ, read_appearance_cb,
				NULL, BT_SECURITY_LOW, BT_SECURITY_LOW, 0);
}

static void add_gatt(void)
{
	bt_uuid_t uuid;

	/* Primary Service: <<GATT Service>> */
	bt_uuid16_create(&uuid, GENERIC_ATTRIB_PROFILE_ID);
	btd_gatt_add_service(&uuid, true);

	/* Declaration and Value: <<Service Changed>> */
	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	btd_gatt_add_char(&uuid, ATT_CHAR_PROPER_INDICATE, NULL, NULL,
					BT_SECURITY_LOW, BT_SECURITY_LOW, 0);

	/* Descriptor: <<Client Characteristic Configuration>> */
	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	btd_gatt_add_char_desc(&uuid, NULL, ccc_written_cb, BT_SECURITY_LOW,
							BT_SECURITY_LOW, 0);

	btd_gatt_dump_local_attribute_database();
}

static void channel_free(gpointer user_data)
{
	struct channel *channel = user_data;

	g_attrib_unref(channel->attrib);
	btd_device_unref(channel->device);
	g_free(channel);
}

static void channel_remove(gpointer user_data)
{
	g_hash_table_remove(channels, user_data);
}

static uint8_t check_attribute_security(struct btd_attribute *attr,
						struct channel *channel,
						uint16_t opcode)
{
	int op_sec_level, chan_sec_level;
	int key_size;

	switch (opcode) {
	case ATT_OP_READ_BY_TYPE_REQ:
	case ATT_OP_READ_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_READ_MULTI_REQ:
	case ATT_OP_READ_BY_GROUP_REQ:
		op_sec_level = attr->read_sec;
		break;
	case ATT_OP_WRITE_REQ:
	case ATT_OP_WRITE_CMD:
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_EXEC_WRITE_REQ:
	case ATT_OP_SIGNED_WRITE_CMD:
		op_sec_level = attr->write_sec;
		break;
	default:
		return 0;
	}

	if (op_sec_level == BT_SECURITY_LOW)
		return 0;

	chan_sec_level = g_attrib_get_sec_level(channel->attrib);

	if (chan_sec_level < op_sec_level) {
		if (op_sec_level == BT_SECURITY_HIGH)
			return ATT_ECODE_AUTHENTICATION;
		else
			return ATT_ECODE_INSUFF_ENC;
	}

	key_size = g_attrib_get_key_size(channel->attrib);

	if (key_size < attr->key_size)
		return ATT_ECODE_INSUFF_ENCR_KEY_SIZE;

	return 0;
}

static gint find_by_handle(gconstpointer a, gconstpointer b)
{
	const struct btd_attribute *attr = a;

	return attr->handle - GPOINTER_TO_UINT(b);
}

static void read_by_type_result(int err, uint8_t *value, size_t vlen,
							void *user_data)

{
	struct read_by_type_transaction *trans = user_data;
	struct channel *channel = trans->channel;
	GList *head = trans->match;
	struct btd_attribute *attr = head->data;

	if (err) {
		send_error(channel->attrib, ATT_OP_READ_REQ, attr->handle, err);
		goto done;
	}

	trans->match = g_list_delete_link(trans->match, head);

	/* According to Core v4.0 spec, page 1853, if the attribute
	 * value is longer than (ATT_MTU - 4) or 253 octets, whichever
	 * is smaller, then the first (ATT_MTU - 4) or 253 octets shall
	 * be included in this response.
	 */

	if (trans->olen == 0) {
		trans->vlen = MIN((uint16_t) (channel->mtu - 4),
							MIN(vlen, 253));

		/* First entry: Set handle-value length */
		trans->opdu[trans->olen++] = ATT_OP_READ_BY_TYPE_RESP;
		trans->opdu[trans->olen++] = 2 + trans->vlen;
	} else if (trans->vlen != MIN(vlen, 253))
		/* Length doesn't match with handle-value length */
		goto send;

	/* It there space enough for another handle-value pair? */
	if (trans->olen + 2 + trans->vlen > channel->mtu)
		goto send;

	/* Copy attribute handle into opdu */
	att_put_u16(attr->handle, &trans->opdu[trans->olen]);
	trans->olen += 2;

	/* Copy attribute value into opdu */
	memcpy(&trans->opdu[trans->olen], value, trans->vlen);
	trans->olen += trans->vlen;

	if (trans->match == NULL)
		goto send;

	/* Getting the next attribute */
	attr = trans->match->data;

	if (attr->value_len)
		read_by_type_result(0, attr->value, attr->value_len, trans);
	else
		attr->read_cb(channel->device, attr, read_by_type_result,
									trans);
	return;

send:
	g_attrib_send(channel->attrib, 0, trans->opdu, trans->olen, NULL,
								NULL, NULL);

done:
	g_source_remove(trans->timeout);
	g_list_free(trans->match);
	g_free(trans);
}

static gboolean transaction_timeout(gpointer user_data)
{
	read_by_type_result(ATT_ECODE_UNLIKELY, NULL, 0, user_data);

	return FALSE;
}

static void read_by_type(struct channel *channel, const uint8_t *ipdu,
								size_t ilen)
{
	struct read_by_type_transaction *trans;
	struct btd_attribute *attr;
	GList *list;
	uint16_t start, end;
	bt_uuid_t uuid;
	uint8_t status = 0;

	if (dec_read_by_type_req(ipdu, ilen, &start, &end, &uuid) == 0) {
		send_error(channel->attrib, ipdu[0], 0x0000,
						ATT_ECODE_INVALID_PDU);
		return;
	}

	if (start == 0x0000 || start > end) {
		send_error(channel->attrib, ipdu[0], 0x0000,
						ATT_ECODE_INVALID_HANDLE);
		return;
	}

	trans = g_malloc0(sizeof(*trans) + channel->mtu);
	trans->channel = channel; /* Weak reference */

	for (list = local_attribute_db; list; list = g_list_next(list)) {
		attr = list->data;

		if (attr->handle < start)
			continue;

		if (attr->handle > end)
			break;

		if (bt_uuid_cmp(&attr->type, &uuid) != 0)
			continue;

		/* Checking attribute consistency */
		if (attr->value_len == 0 && attr->read_cb == NULL)
			continue;

		status = check_attribute_security(attr, channel, ipdu[0]);
		if (status)
			break;

		trans->match = g_list_append(trans->match, attr);
	}

	if (trans->match == NULL) {
		if (status)
			send_error(channel->attrib, ipdu[0], start, status);
		else
			send_error(channel->attrib, ipdu[0], start,
						ATT_ECODE_ATTR_NOT_FOUND);
		g_free(trans);
		return;
	}

	trans->timeout = g_timeout_add_seconds(TRANSACTION_TIMEOUT,
						transaction_timeout, trans);

	/* Processing the first element */
	attr = trans->match->data;

	if (attr->value_len)
		read_by_type_result(0, attr->value, attr->value_len, trans);
	else
		attr->read_cb(channel->device, attr, read_by_type_result,
								trans);
}

static GList *get_char_decl_from_attr(GList *attr_node)
{
	GList *char_decl_node;
	struct btd_attribute *attr;
	bt_uuid_t uuid;

	char_decl_node = g_list_previous(attr_node);
	if (char_decl_node == NULL)
		return NULL;

	attr = char_decl_node->data;
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	if (bt_uuid_cmp(&uuid, &attr->type) != 0)
		return NULL;

	return char_decl_node;
}

static bool validate_att_operation(GList *attr_node, uint16_t opcode)
{
	GList *char_decl_node;
	struct btd_attribute *attr;

	attr = attr_node->data;

	char_decl_node = get_char_decl_from_attr(attr_node);
	if (char_decl_node == NULL)
		return true;

	attr = char_decl_node->data;

	switch (opcode) {
	case ATT_OP_WRITE_REQ:
		if (attr->value[0] & 0x08)
			return true;
	case ATT_OP_WRITE_CMD:
		if (attr->value[0] & 0x04)
			return true;
	case ATT_OP_READ_REQ:
		if (attr->value[0] & 0x02)
			return true;
	}

	return false;
}

static void read_request_result(int err, uint8_t *value, size_t len,
								void *user_data)
{
	struct att_transaction *trans = user_data;
	struct channel *channel = trans->channel;
	struct btd_attribute *attr = trans->attr;
	uint8_t opdu[channel->mtu];
	size_t olen;

	g_free(trans);

	if (err) {
		send_error(channel->attrib, ATT_OP_READ_REQ, attr->handle, err);
		return;
	}

	olen = enc_read_resp(value, len, opdu, channel->mtu);

	g_attrib_send(channel->attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static void read_request(struct channel *channel, const uint8_t *ipdu,
								size_t ilen)
{
	uint16_t handle;
	GList *list;
	struct btd_attribute *attr;
	struct att_transaction *trans;
	uint8_t status;

	if (dec_read_req(ipdu, ilen, &handle) == 0) {
		send_error(channel->attrib, ipdu[0], 0x0000,
						ATT_ECODE_INVALID_PDU);
		return;
	}

	list = g_list_find_custom(local_attribute_db,
				GUINT_TO_POINTER(handle), find_by_handle);
	if (!list) {
		send_error(channel->attrib, ipdu[0], 0x0000,
						ATT_ECODE_INVALID_HANDLE);
		return;
	}

	attr = list->data;

	status = check_attribute_security(attr, channel, ipdu[0]);
	if (status) {
		send_error(channel->attrib, ATT_OP_READ_REQ, attr->handle,
								status);
		return;
	}

	if (!validate_att_operation(list, ATT_OP_READ_REQ)) {
		send_error(channel->attrib, ATT_OP_READ_REQ, attr->handle,
						ATT_ECODE_READ_NOT_PERM);
		return;
	}

	if (attr->value_len > 0) {
		uint8_t opdu[channel->mtu];
		size_t olen = enc_read_resp(attr->value, attr->value_len, opdu,
								channel->mtu);

		g_attrib_send(channel->attrib, 0, opdu, olen, NULL, NULL,
									NULL);
		return;
	}

	if (attr->read_cb == NULL) {
		send_error(channel->attrib, ATT_OP_READ_REQ, attr->handle,
						ATT_ECODE_READ_NOT_PERM);
		return;
	}

	trans = g_new0(struct att_transaction, 1);
	trans->attr = attr;
	trans->channel = channel;

	attr->read_cb(channel->device, attr, read_request_result, trans);
}

static void read_by_group_resp(struct channel *channel, uint16_t start,
					uint16_t end, bt_uuid_t *pattern)
{
	uint8_t opdu[channel->mtu];
	GList *list;
	struct btd_attribute *last = NULL;
	uint8_t *group_start, *group_end = NULL, *group_uuid;
	unsigned int uuid_type = BT_UUID_UNSPEC;
	size_t group_len = 0, plen = 0;

	/*
	 * Read By Group Type Response format:
	 *    Attribute Opcode: 1 byte
	 *    Length: 1 byte (size of each group)
	 *    Group: start | end | <<UUID>>
	 */

	opdu[0] = ATT_OP_READ_BY_GROUP_RESP;
	group_start = &opdu[2];
	group_uuid = &opdu[6];

	for (list = local_attribute_db; list;
			last = list->data, list = g_list_next(list)) {
		struct btd_attribute *attr = list->data;

		if (attr->handle < start)
			continue;

		if (attr->handle > end)
			break;

		if (bt_uuid_cmp(&attr->type, pattern) != 0)
			continue;

		if (uuid_type != BT_UUID_UNSPEC && uuid_type != attr->type.type) {
			/*
			 * Groups should contain the same length: UUID16 and
			 * UUID128 should be sent on different ATT PDUs
			 */
			break;
		}

		/*
		 * MTU checking should not be shifted up, otherwise the
		 * handle of last end group will not be set properly.
		 */
		if ((plen + group_len) >= channel->mtu)
			break;

		/* Start Grouping handle */
		att_put_u16(attr->handle, group_start);

		/* Grouping <<UUID>>: Value is little endian */
		memcpy(group_uuid, attr->value, attr->value_len);

		if (last && group_end) {
			att_put_u16(last->handle, group_end);
			group_end += group_len;
			plen += group_len;
		}

		/* Grouping initial settings: First grouping */
		if (uuid_type == BT_UUID_UNSPEC) {
			uuid_type = attr->type.type;

			/* start(0xXXXX) | end(0xXXXX) | <<UUID>> */
			group_len = 2 + 2 + bt_uuid_len(&attr->type);

			/* 2: ATT Opcode and Length */
			plen = 2 + group_len;

			/* Size of each Attribute Data */
			opdu[1] = group_len;

			group_end = &opdu[4];
		}

		group_start += group_len;
		group_uuid += group_len;
	}

	if (plen == 0) {
		send_error(channel->attrib, ATT_OP_READ_BY_GROUP_REQ, start,
						ATT_ECODE_ATTR_NOT_FOUND);
		return;
	}

	if (group_end)
		att_put_u16(last->handle, group_end);

	g_attrib_send(channel->attrib, 0, opdu, plen, NULL, NULL, NULL);
}

static void read_by_group(struct channel *channel, const uint8_t *ipdu,
								size_t ilen)
{
	uint16_t decoded, start, end;
	bt_uuid_t pattern, prim_uuid;

	decoded = dec_read_by_grp_req(ipdu, ilen, &start, &end, &pattern);
	if (decoded == 0) {
		send_error(channel->attrib, ipdu[0], 0x0000,
						ATT_ECODE_INVALID_PDU);
		return;
	}

	if (start > end || start == 0x0000) {
		send_error(channel->attrib, ipdu[0], start,
						ATT_ECODE_INVALID_HANDLE);
		return;
	}

	 /*
	  * Restricting Read By Group Type to <<Primary>>.
	  * Removing the checking below requires changes to support
	  * dynamic values(defined in the upper layer) and additional
	  * security verification.
	  */
	bt_uuid16_create(&prim_uuid, GATT_PRIM_SVC_UUID);
	if (bt_uuid_cmp(&pattern, &prim_uuid) != 0) {
		send_error(channel->attrib, ipdu[0], start,
					ATT_ECODE_UNSUPP_GRP_TYPE);
		return;
	}

	read_by_group_resp(channel, start, end, &pattern);
}

static void value_changed(struct channel *channel, const uint8_t *ipdu,
								size_t ilen)
{
	uint8_t opdu[channel->mtu];
	struct btd_attribute *attr;
	struct notifier *notif;
	GHashTableIter iter;
	GList *list;
	uint16_t handle;
	gpointer key, value;
	bool cfm = true;

	/* Malformed PDU: Ignore */
	if (ilen < 5)
		return;

	handle = att_get_u16(&ipdu[1]);

	/* TODO: Missing checking for <<CCC>>*/
	list = g_list_find_custom(local_attribute_db,
				GUINT_TO_POINTER(handle), find_by_handle);
	if (!list)
		goto done;

	attr = list->data;

	if (attr->notifiers == NULL)
		return;

	g_hash_table_iter_init(&iter, attr->notifiers);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		notif = value;

		/* Skip opcode and handle */
		if (!notif->value_cb((uint8_t *) &ipdu[3], ilen - 3,
							notif->user_data))
			cfm = false;
	}

	/*
	 * Below: Processing Indication. If at least one client/watcher
	 * didn't get the data properly ATT confirmation should not be sent.
	 * No further indications to this client shall occur until the
	 * confirmation has been received by the server.
	 *
	 * TODO: Missing a mechanism to avoid blocking indications due
	 * missing confirmation.
	 */
	if (cfm == false)
		return;

done:
	/*
	 * From Core SPEC 4.0 page 1870:
	 * If the attribute handle or the attribute value is invalid, the
	 * client shall send a handle value confirmation in response and
	 * shall discard the handle and value from the received indication.
	 */

	if (ipdu[0] == ATT_OP_HANDLE_IND) {
		opdu[0] = ATT_OP_HANDLE_CNF;
		att_put_u16(handle, &opdu[1]);
		g_attrib_send(channel->attrib, 0, opdu, 3, NULL, NULL, NULL);
	}
}

static void write_cmd(struct channel *channel, const uint8_t *ipdu,
								size_t ilen)
{
	uint16_t handle;
	GList *list;
	struct btd_attribute *attr;
	size_t vlen;
	uint8_t value[channel->mtu];
	uint8_t status;

	if (dec_write_cmd(ipdu, ilen, &handle, value, &vlen) == 0)
		return;

	list = g_list_find_custom(local_attribute_db,
				GUINT_TO_POINTER(handle), find_by_handle);

	if (!list)
		return;

	attr = list->data;

	if (attr->write_cb == NULL)
		return;

	status = check_attribute_security(attr, channel, ipdu[0]);
	if (status)
		return;

	if (!validate_att_operation(list, ATT_OP_WRITE_CMD))
		return;

	attr->write_cb(channel->device, attr, value, vlen, 0, NULL, NULL);
}

static void write_request_result(int err, void *user_data)
{
	struct att_transaction *trans = user_data;
	struct btd_attribute *attr = trans->attr;
	struct channel *channel = trans->channel;
	uint8_t opdu[channel->mtu];
	uint16_t olen;

	if (err != 0)
		olen = enc_error_resp(ATT_OP_WRITE_REQ, attr->handle, err,
							opdu, sizeof(opdu));
	else
		olen = enc_write_resp(opdu);

	g_attrib_send(channel->attrib, 0, opdu, olen, NULL, NULL, NULL);

	g_free(trans);
}

static void write_request(struct channel *channel,
					const uint8_t *ipdu, size_t ilen)
{
	GList *list;
	struct att_transaction *trans;
	struct btd_attribute *attr;
	size_t vlen;
	uint16_t handle;
	uint8_t value[channel->mtu];
	uint8_t status;

	if (dec_write_req(ipdu, ilen, &handle, value, &vlen) == 0) {
		send_error(channel->attrib, ipdu[0], 0x0000,
						ATT_ECODE_INVALID_PDU);
		return;
	}

	list = g_list_find_custom(local_attribute_db, GUINT_TO_POINTER(handle),
								find_by_handle);
	if (!list) {
		send_error(channel->attrib, ipdu[0], handle,
						ATT_ECODE_INVALID_HANDLE);
		return;
	}

	attr = list->data;

	if (attr->write_cb == NULL) {
		send_error(channel->attrib, ipdu[0], handle,
						ATT_ECODE_WRITE_NOT_PERM);
		return;
	}

	status = check_attribute_security(attr, channel, ipdu[0]);
	if (status) {
		send_error(channel->attrib, ATT_OP_WRITE_REQ, attr->handle,
								status);
		return;
	}

	if (!validate_att_operation(list, ATT_OP_WRITE_REQ)) {
		send_error(channel->attrib, ipdu[0], handle,
						ATT_ECODE_WRITE_NOT_PERM);
		return;
	}

	trans = g_new0(struct att_transaction, 1);
	trans->channel = channel;
	trans->attr = attr;

	attr->write_cb(channel->device, attr, value, vlen, 0,
						write_request_result, trans);
}

static gboolean channel_watch_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	DBG("%p Disconnected", user_data);

	return FALSE;
}

static void channel_handler_cb(const uint8_t *ipdu, uint16_t ilen,
							gpointer user_data)
{
	struct channel *channel = user_data;

	switch (ipdu[0]) {
	case ATT_OP_ERROR:
		break;

	/* Requests */
	case ATT_OP_WRITE_CMD:
		write_cmd(channel, ipdu, ilen);
		break;

	case ATT_OP_WRITE_REQ:
		write_request(channel, ipdu, ilen);
		break;

	case ATT_OP_READ_REQ:
		read_request(channel, ipdu, ilen);
		break;

	case ATT_OP_READ_BY_TYPE_REQ:
		read_by_type(channel, ipdu, ilen);
		break;

	case ATT_OP_MTU_REQ:
	case ATT_OP_FIND_INFO_REQ:
	case ATT_OP_FIND_BY_TYPE_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_READ_MULTI_REQ:
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_EXEC_WRITE_REQ:
	case ATT_OP_SIGNED_WRITE_CMD:
		send_error(channel->attrib, ipdu[0], 0x0000,
						ATT_ECODE_REQ_NOT_SUPP);
		break;

	case ATT_OP_READ_BY_GROUP_REQ:
		read_by_group(channel, ipdu, ilen);
		break;

	/* Responses */
	case ATT_OP_MTU_RESP:
	case ATT_OP_FIND_INFO_RESP:
	case ATT_OP_FIND_BY_TYPE_RESP:
	case ATT_OP_READ_BY_TYPE_RESP:
	case ATT_OP_READ_RESP:
	case ATT_OP_READ_BLOB_RESP:
	case ATT_OP_READ_MULTI_RESP:
	case ATT_OP_READ_BY_GROUP_RESP:
	case ATT_OP_WRITE_RESP:
	case ATT_OP_PREP_WRITE_RESP:
	case ATT_OP_EXEC_WRITE_RESP:
	case ATT_OP_HANDLE_CNF:
		break;

	/* Notification & Indication */
	case ATT_OP_HANDLE_NOTIFY:
	case ATT_OP_HANDLE_IND:
		value_changed(channel, ipdu, ilen);
		break;
	}
}

void gatt_connect_cb(GIOChannel *io, GError *gerr, void *user_data)
{
	struct channel *channel;
	uint16_t mtu, cid;
	char src[18], dst[18];
	struct btd_adapter *adapter;
	struct btd_device *device;
	bt_uuid_t uuid;
	bdaddr_t sba;
	bdaddr_t dba;

	if (gerr) {
		error("ATT Connect: %s", gerr->message);
		return;
	}

	if (!bt_io_get(io, NULL,
			BT_IO_OPT_SOURCE_BDADDR, &sba,
			BT_IO_OPT_DEST_BDADDR, &dba,
			BT_IO_OPT_CID, &cid,
			BT_IO_OPT_IMTU, &mtu,
			BT_IO_OPT_INVALID))
		return;

	ba2str(&sba, src);
	ba2str(&dba, dst);

	adapter = adapter_find(&sba);
	if (!adapter) {
		error("Can't find adapter %s", src);
		return;
	}

	device = adapter_find_device(adapter, &dba);
	if (device == NULL) {
		error("Can't find device %s", dst);
		return;
	}

	channel = g_new0(struct channel, 1);
	channel->device = btd_device_ref(device);
	channel->attrib = g_attrib_new(io);
	channel->mtu = (cid == ATT_CID ? ATT_DEFAULT_LE_MTU : mtu);

	g_hash_table_insert(channels, device, channel);

	DBG("%p Connected: %s < %s CID: %d, MTU: %d", channel, src, dst,
								cid, mtu);

	g_attrib_register(channel->attrib, GATTRIB_ALL_EVENTS,
				GATTRIB_ALL_HANDLES, channel_handler_cb,
				channel, NULL);

	channel->id = g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
				G_IO_ERR | G_IO_HUP, channel_watch_cb,
				channel, (GDestroyNotify) channel_remove);

	/*
	 * FIXME: Check storage before triggering attributes discovery.
	 * Missing probe mechanism and reply for connect or pair. Fix
	 * device weak reference and disconnection when ATT operation
	 * are still pending. Fix core reverse service discovery.
	 */
	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	gatt_foreach_by_type(channel->attrib, 0x0001, 0xffff, &uuid,
				insert_primary_service, device);

	bt_uuid16_create(&uuid, GATT_SND_SVC_UUID);
	gatt_foreach_by_type(channel->attrib, 0x0001, 0xffff, &uuid,
				insert_secondary_service, device);

	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	gatt_foreach_by_type(channel->attrib, 0x0001, 0xffff, &uuid,
				insert_char_declaration, device);

	bt_uuid16_create(&uuid, GATT_INCLUDE_UUID);
	gatt_foreach_by_type(channel->attrib, 0x0001, 0xffff, &uuid,
					insert_include, device);

	gatt_foreach_by_info(channel->attrib, 0x0001, 0xffff,
				insert_char_descriptor, device);
}

void btd_gatt_service_manager_init(void)
{
	GError *gerr = NULL;

	if (!(g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL))
		return;

	DBG("Starting GATT server");

	bredr_io = bt_io_listen(gatt_connect_cb, NULL, NULL, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, BDADDR_ANY,
					BT_IO_OPT_PSM, ATT_PSM,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);

	if (bredr_io == NULL) {
		error("%s", gerr->message);
		g_error_free(gerr);
		return;
	}

	/* LE socket */
	le_io = bt_io_listen(gatt_connect_cb, NULL, NULL, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, BDADDR_ANY,
					BT_IO_OPT_SOURCE_TYPE, BDADDR_LE_PUBLIC,
					BT_IO_OPT_CID, ATT_CID,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);
	if (le_io == NULL) {
		error("%s", gerr->message);
		g_error_free(gerr);
		/* Doesn't have LE support, continue */
	}

	add_gap();
	add_gatt();

	g_dbus_register_interface(btd_get_dbus_connection(),
			"/org/bluez", "org.bluez.gatt.ServiceManager1",
			methods, NULL, NULL, NULL, NULL);

	channels = g_hash_table_new_full(g_int_hash, g_int_equal, NULL,
							channel_free);
}

void btd_gatt_service_manager_cleanup(void)
{
	g_dbus_unregister_interface(btd_get_dbus_connection(),
			"/org/bluez", "org.bluez.gatt.ServiceManager1");

	if (le_io != NULL) {
		g_io_channel_shutdown(le_io, FALSE, NULL);
		g_io_channel_unref(le_io);
	}

	if (bredr_io != NULL) {
		g_io_channel_shutdown(bredr_io, FALSE, NULL);
		g_io_channel_unref(bredr_io);
	}

	g_hash_table_destroy(channels);
}
