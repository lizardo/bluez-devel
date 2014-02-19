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

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/signalfd.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#define GATT_MGR_IFACE			"org.bluez.GattManager1"
#define SERVICE_IFACE			"org.bluez.GattService1"

/* Immediate Alert Service UUID */
#define IAS_UUID			"00001802-0000-1000-8000-00805f9b34fb"

static GMainLoop *main_loop;
static GSList *services;

static gboolean service_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	const char *uuid = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &uuid);

	return TRUE;
}

static gboolean service_get_includes(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	return TRUE;
}

static gboolean service_exist_includes(const GDBusPropertyTable *property,
							void *user_data)
{
	return FALSE;
}

static const GDBusPropertyTable service_properties[] = {
	{ "UUID", "s", service_get_uuid },
	{ "Includes", "ao", service_get_includes, NULL,
					service_exist_includes },
	{ }
};

static char *register_service(DBusConnection *conn, const char *uuid)
{
	static int id = 1;
	char *path;

	path = g_strdup_printf("/service%d", id++);
	if (g_dbus_register_interface(conn, path, SERVICE_IFACE,
				NULL, NULL, service_properties,
				g_strdup(uuid), g_free) == FALSE) {
		printf("Couldn't register service interface\n");
		g_free(path);
		return NULL;
	}

	return path;
}

static void create_services(DBusConnection *conn)
{
	char *service_path;

	service_path = register_service(conn, IAS_UUID);

	services = g_slist_prepend(services, service_path);

	printf("Registered service: %s\n", service_path);
}

static void register_external_service_reply(DBusPendingCall *call,
							void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;

	dbus_error_init(&derr);
	dbus_set_error_from_message(&derr, reply);

	if (dbus_error_is_set(&derr))
		printf("RegisterService: %s\n", derr.message);
	else
		printf("RegisterService: OK\n");

	dbus_message_unref(reply);
	dbus_error_free(&derr);
}

static void register_external_service(gpointer a, gpointer b)
{
	DBusConnection *conn = b;
	const char *path = a;
	DBusMessage *msg;
	DBusPendingCall *call;
	DBusMessageIter iter, dict;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
					GATT_MGR_IFACE, "RegisterService");
	if (msg == NULL) {
		printf("Couldn't allocate D-Bus message\n");
		return;
	}

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	/* TODO: Add options dictionary */

	dbus_message_iter_close_container(&iter, &dict);

	if (g_dbus_send_message_with_reply(conn, msg, &call, -1) == FALSE) {
		dbus_message_unref(msg);
		return;
	}

	dbus_pending_call_set_notify(call, register_external_service_reply,
								NULL, NULL);

	dbus_pending_call_unref(call);
}

static void connect_handler(DBusConnection *conn, void *user_data)
{
	g_slist_foreach(services, register_external_service, conn);
}

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	static bool __terminated = false;
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		if (!__terminated) {
			printf("Terminating\n");
			g_main_loop_quit(main_loop);
		}

		__terminated = true;
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

int main(int argc, char *argv[])
{
	GDBusClient *client;
	DBusConnection *dbus_conn;
	guint signal;

	signal = setup_signalfd();
	if (signal == 0)
		return -errno;

	dbus_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);

	main_loop = g_main_loop_new(NULL, FALSE);

	g_dbus_attach_object_manager(dbus_conn);

	printf("gatt-service unique name: %s\n",
				dbus_bus_get_unique_name(dbus_conn));

	create_services(dbus_conn);

	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");

	g_dbus_client_set_connect_watch(client, connect_handler, NULL);

	g_main_loop_run(main_loop);

	g_dbus_client_unref(client);

	g_source_remove(signal);

	g_slist_free_full(services, g_free);
	dbus_connection_unref(dbus_conn);

	return 0;
}
