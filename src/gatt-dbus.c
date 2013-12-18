/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Instituto Nokia de Tecnologia - INdT
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
#include <errno.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "adapter.h"
#include "device.h"
#include "lib/uuid.h"
#include "dbus-common.h"
#include "log.h"

#include "error.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "src/shared/io.h"
#include "gatt.h"
#include "gatt-dbus.h"

#define GATT_MGR_IFACE			"org.bluez.GattManager1"
#define SERVICE_IFACE			"org.bluez.GattService1"
#define CHARACTERISTIC_IFACE		"org.bluez.GattCharacteristic1"

#define REGISTER_TIMER         1

struct service_data {
	char *path;
	struct btd_attribute *attr;
};

struct external_app {
	char *owner;
	GDBusClient *client;
	GSList *proxies;
	unsigned int watch;
	GSList *services;
	guint register_timer;
};

struct external_write_data {
	btd_attr_write_result_t result_cb;
	void *user_data;
};

static GSList *external_apps;

/*
 * Attribute to Proxy hash table. Used to map incoming
 * ATT operations to its external characteristic proxy.
 */
static GHashTable *proxy_hash;

static void service_free(struct service_data *service)
{
	g_free(service->path);
	g_free(service);
}

static int service_path_cmp(gconstpointer a, gconstpointer b)
{
	const struct service_data *service = a;
	const char *path = b;

	return g_strcmp0(service->path, path);
}

static int proxy_path_cmp(gconstpointer a, gconstpointer b)
{
	GDBusProxy *proxy1 = (GDBusProxy *) a;
	GDBusProxy *proxy2 = (GDBusProxy *) b;
	const char *path1 = g_dbus_proxy_get_path(proxy1);
	const char *path2 = g_dbus_proxy_get_path(proxy2);

	return g_strcmp0(path1, path2);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	struct external_app *eapp = user_data;
	const char *interface, *path;

	interface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	DBG("path %s iface %s", path, interface);

	if (g_strcmp0(interface, CHARACTERISTIC_IFACE) != 0 &&
		g_strcmp0(interface, SERVICE_IFACE) != 0)
		return;

	/*
	 * Object path follows a hierarchical organization. Add the
	 * proxies sorted by path helps the logic to register the
	 * object path later.
	 */
	eapp->proxies = g_slist_insert_sorted(eapp->proxies, proxy,
							proxy_path_cmp);
}

static bool remove_service(struct external_app *eapp, const char *path)
{
	struct service_data *service;
	GSList *list;

	list = g_slist_find_custom(eapp->services, path,
						service_path_cmp);
	if (list == NULL)
		return false;

	 /* Removing service path from the list and from the database */
	service = list->data;

	eapp->services = g_slist_remove(eapp->services, service);

	if (service->attr)
		btd_gatt_remove_service(service->attr);

	service_free(service);

	return true;
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	struct external_app *eapp = user_data;
	const char *interface, *path;

	interface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	DBG("path %s iface %s", path, interface);

	eapp->proxies = g_slist_remove(eapp->proxies, proxy);

	remove_service(eapp, path);
}

static void external_app_watch_destroy(gpointer user_data)
{
	struct external_app *eapp = user_data;

	external_apps = g_slist_remove(external_apps, eapp);

	g_dbus_client_unref(eapp->client);

	if (eapp->register_timer)
		g_source_remove(eapp->register_timer);

	g_slist_free_full(eapp->services, (GDestroyNotify) service_free);
	g_free(eapp->owner);
	g_free(eapp);
}

static int external_app_owner_cmp(gconstpointer a, gconstpointer b)
{
	const struct external_app *eapp = a;
	const char *sender = b;

	return g_strcmp0(eapp->owner, sender);
}

static struct external_app *new_external_app(DBusConnection *conn,
					const char *sender, const char *path)
{
	struct external_app *eapp;
	GDBusClient *client;

	client = g_dbus_client_new(conn, sender, "/");
	if (client == NULL)
		return NULL;

	eapp = g_new0(struct external_app, 1);

	eapp->watch = g_dbus_add_disconnect_watch(btd_get_dbus_connection(),
			sender, NULL, eapp, external_app_watch_destroy);
	if (eapp->watch == 0) {
		g_dbus_client_unref(client);
		g_free(eapp);
		return NULL;
	}

	eapp->owner = g_strdup(sender);
	eapp->client = client;

	g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
								NULL, eapp);

	return eapp;
}

static bool property_string2int(const char *proper, uint8_t *out)
{
	/* Regular Properties: See core spec 4.1 page 2183 */
	if (strcmp("broadcast", proper) == 0)
		*out = GATT_CHR_PROP_BROADCAST;
	else if (strcmp("read", proper) == 0)
		*out = GATT_CHR_PROP_READ;
	else if (strcmp("write-without-response", proper) == 0)
		*out = GATT_CHR_PROP_WRITE_WITHOUT_RESP;
	else if (strcmp("write", proper) == 0)
		*out = GATT_CHR_PROP_WRITE;
	else if (strcmp("notify", proper) == 0)
		*out = GATT_CHR_PROP_NOTIFY;
	else if (strcmp("indicate", proper) == 0)
		*out = GATT_CHR_PROP_INDICATE;
	else if (strcmp("authenticated-signed-writes", proper) == 0)
		*out = GATT_CHR_PROP_AUTH;

	/* TODO: Extended properties. Ref core spec 4.1 page 2185  */
	else
		return false;

	return true;
}

static uint8_t property_string2bitmask(DBusMessageIter *iter)
{
	DBusMessageIter istr;
	uint8_t prop_bitmask = 0, prop;
	const char *str;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY) {
		error("Invalid type for Properties");
		return 0;
	}

	dbus_message_iter_recurse(iter, &istr);

	do {
		if (dbus_message_iter_get_arg_type(&istr) !=
				DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&istr, &str);
		if (!property_string2int(str, &prop))
			return 0;

		prop_bitmask |= prop;
	} while (dbus_message_iter_next(&istr));

	return prop_bitmask;
}

static void read_external_char_cb(struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{
	DBusMessageIter iter, array;
	GDBusProxy *proxy;
	uint8_t *value;
	int len;

	/*
	 * Remote device is trying to read the informed attribute,
	 * "Value" should be read from the proxy. GDBusProxy tracks
	 * properties changes automatically, it is not necessary to
	 * get the value directly from the GATT server.
	 */
	proxy = g_hash_table_lookup(proxy_hash, attr);
	if (proxy == NULL) {
		result(ENOENT, NULL, 0, user_data);
		return;
	}

	if (!g_dbus_proxy_get_property(proxy, "Value", &iter)) {
		/* Unusual situation, read property will checked earlier */
		result(EPERM, NULL, 0, user_data);
		return;
	}

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		DBG("External service inconsistent!");
		result(EPERM, NULL, 0, user_data);
		return;
	}

	dbus_message_iter_recurse(&iter, &array);
	dbus_message_iter_get_fixed_array(&array, &value, &len);

	DBG("attribute: %p read %d bytes", attr, len);

	result(0, value, len, user_data);
}

static void write_char_reply(const DBusError *derr, void *user_data)
{
	struct external_write_data *wdata = user_data;
	int err = 0;

	/*
	 * Security requirements shall be handled by the core. If external
	 * applications returns an error, the reasons will be restricted to
	 * invalid argument or application specific errors.
	 */

	if (dbus_error_is_set(derr) == FALSE)
		goto done;

	DBG("Write reply: %s", derr->message);

	if (dbus_error_has_name(derr, DBUS_ERROR_NO_REPLY))
		err = ETIMEDOUT;
	else if (dbus_error_has_name(derr, ERROR_INTERFACE ".InvalidArguments"))
		err = EINVAL;
	else
		err = EPROTO;

done:
	if (wdata && wdata->result_cb)
		wdata->result_cb(err, wdata->user_data);
}

static void write_external_char_cb(struct btd_attribute *attr,
					const uint8_t *value, size_t len,
					btd_attr_write_result_t result,
					void *user_data)
{
	GDBusProxy *proxy;

	proxy = g_hash_table_lookup(proxy_hash, attr);
	if (proxy == NULL) {
		result(ENOENT, user_data);
		return;
	}

	if (result) {
		struct external_write_data *wdata;

		wdata = g_new0(struct external_write_data, 1);
		wdata->result_cb = result;
		wdata->user_data = user_data;

		g_dbus_proxy_set_property_array(proxy, "Value", DBUS_TYPE_BYTE,
						value, len, write_char_reply,
						wdata, g_free);
	} else {
		/*
		 * Caller is not interested in the Set method call result.
		 * This flow implements the ATT Write Command scenario, where
		 * the remote doesn't receive ATT response.
		 */
		g_dbus_proxy_set_property_array(proxy, "Value", DBUS_TYPE_BYTE,
						value, len, write_char_reply,
						NULL, NULL);
	}

	DBG("Server: Write characteristic callback %s",
					g_dbus_proxy_get_path(proxy));
}

static int register_external_characteristic(GDBusProxy *proxy)
{
	DBusMessageIter iter;
	const char *uuid;
	bt_uuid_t btuuid;
	uint8_t prop_bitmask;
	struct btd_attribute *attr;

	if (!g_dbus_proxy_get_property(proxy, "UUID", &iter))
		return -EINVAL;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return -EINVAL;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (!g_dbus_proxy_get_property(proxy, "Flags", &iter))
		return -EINVAL;

	prop_bitmask = property_string2bitmask(&iter);

	if (!prop_bitmask)
		return -EINVAL;

	if (bt_string_to_uuid(&btuuid, uuid) < 0)
		return -EINVAL;

	attr = btd_gatt_add_char(&btuuid, prop_bitmask, read_external_char_cb,
						write_external_char_cb);
	if (attr == NULL)
		return -EINVAL;

	/* Attribute to Proxy hash table */
	DBG("Adding proxy %p", proxy);
	g_hash_table_insert(proxy_hash, attr, g_dbus_proxy_ref(proxy));

	return 0;
}

static struct btd_attribute *register_external_service(GDBusProxy *proxy)
{
	DBusMessageIter iter;
	const char *uuid;
	bt_uuid_t btuuid;

	if (!g_dbus_proxy_get_property(proxy, "UUID", &iter))
		return NULL;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return NULL;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (bt_string_to_uuid(&btuuid, uuid) < 0)
		return NULL;

	return btd_gatt_add_service(&btuuid);
}

static gboolean finish_register(gpointer user_data)
{
	struct external_app *eapp = user_data;
	struct service_data *service = NULL;
	GSList *lprx, *lsvc;

	/*
	 * It is not possible to detect when the last proxy object
	 * was reported. "Proxy added" handler reports objects
	 * added on demand or returned by GetManagedObjects().
	 * This timer helps to register all the GATT declarations
	 * (services, characteristics and descriptors) after fetching
	 * all the D-Bus objects.
	 */

	eapp->register_timer = 0;

	for (lprx = eapp->proxies; lprx; lprx= g_slist_next(lprx)) {
		const char *interface, *path;
		GDBusProxy *proxy = lprx->data;

		interface = g_dbus_proxy_get_interface(proxy);
		path = g_dbus_proxy_get_path(proxy);

		if (g_strcmp0(SERVICE_IFACE, interface) == 0) {
			/*
			 * Check if the service was registered with
			 * register_service().
			 */
			service = NULL;
			lsvc = g_slist_find_custom(eapp->services, path,
							service_path_cmp);
			if (!lsvc)
				continue;

			service = lsvc->data;
			if (service->attr)
				continue;

			service->attr = register_external_service(proxy);

			DBG("External service: %s", path);
		} else if (service &&
			g_strcmp0(CHARACTERISTIC_IFACE, interface) == 0 &&
			g_str_has_prefix(path, service->path) == TRUE) {

			if (register_external_characteristic(proxy) < 0)
				DBG("Inconsistent external characteristic: %s",
									path);
			else
				DBG("External characteristic: %s", path);
		}
	}

	return FALSE;
}

static DBusMessage *register_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct external_app *eapp;
	struct service_data *service;
	DBusMessageIter iter;
	const char *path, *sender = dbus_message_get_sender(msg);
	GSList *list;

	DBG("Registering GATT Service: %s", sender);

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &path);

	/*
	 * If we already have created a GDBusClient for the current
	 * application, then we do not need another instance.
	 */
	list = g_slist_find_custom(external_apps, sender,
						external_app_owner_cmp);
	if (list) {
		/* Additional services assigned to the same application */
		eapp = list->data;

		if (g_slist_find_custom(eapp->services, path,
							service_path_cmp))
			return btd_error_already_exists(msg);

		if (eapp->register_timer > 0)
			g_source_remove(eapp->register_timer);
	} else {
		/* First service of a given application */
		eapp = new_external_app(conn, sender, path);
		if (eapp == NULL)
			return btd_error_failed(msg, "Not enough resources");

		external_apps = g_slist_prepend(external_apps, eapp);

	}

	service = g_new0(struct service_data, 1);
	service->path = g_strdup(path);
	eapp->services = g_slist_prepend(eapp->services, service);

	DBG("New app %p: %s", eapp, path);
	eapp->register_timer = g_timeout_add_seconds(REGISTER_TIMER,
							finish_register, eapp);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *unregister_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBusMessageIter iter;
	const char *path, *sender;
	GSList *list;

	DBG("Unregistering GATT Service");

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &path);

	/* Search by owner */
	sender = dbus_message_get_sender(msg);
	list = g_slist_find_custom(external_apps, sender,
						external_app_owner_cmp);
	if (list == NULL)
		return btd_error_does_not_exist(msg);

	/* Remove from the local attribute database */
	if (!remove_service(list->data, path))
		return btd_error_does_not_exist(msg);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable methods[] = {
	{ GDBUS_EXPERIMENTAL_METHOD("RegisterService",
				GDBUS_ARGS({ "service", "o"},
						{ "options", "a{sv}"}),
				NULL, register_service) },
	{ GDBUS_EXPERIMENTAL_METHOD("UnregisterService",
				GDBUS_ARGS({"service", "o"}),
				NULL, unregister_service) },
	{ }
};

gboolean gatt_dbus_manager_register(void)
{
	proxy_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
				NULL, (GDestroyNotify) g_dbus_proxy_unref);

	return g_dbus_register_interface(btd_get_dbus_connection(),
					"/org/bluez", GATT_MGR_IFACE,
					methods, NULL, NULL, NULL, NULL);
}

void gatt_dbus_manager_unregister(void)
{
	g_hash_table_destroy(proxy_hash);
	proxy_hash = NULL;

	g_dbus_unregister_interface(btd_get_dbus_connection(), "/org/bluez",
							GATT_MGR_IFACE);
}
