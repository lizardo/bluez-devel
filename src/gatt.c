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

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>

#include "log.h"
#include "lib/uuid.h"
#include "attrib/att.h"
#include "src/shared/io.h"

#include "gatt-dbus.h"
#include "gatt.h"

/* Common GATT UUIDs */
static const bt_uuid_t primary_uuid  = { .type = BT_UUID16,
					.value.u16 = GATT_PRIM_SVC_UUID };

struct btd_attribute {
	uint16_t handle;
	bt_uuid_t type;
	uint16_t value_len;
	uint8_t value[0];
};

static struct io *server_io;
static GList *local_attribute_db;
static uint16_t next_handle = 0x0001;

static void write_pdu(int sk, const uint8_t *pdu, size_t plen)
{
	if (write(sk, pdu, plen) < 0)
		error("Error sending ATT PDU (0x%02X): %s (%d)", pdu[0],
						strerror(errno), errno);
}

static int local_database_add(uint16_t handle, struct btd_attribute *attr)
{
	attr->handle = handle;

	local_attribute_db = g_list_append(local_attribute_db, attr);

	return 0;
}

struct btd_attribute *btd_gatt_add_service(const bt_uuid_t *uuid)
{
	uint16_t len = bt_uuid_len(uuid);
	struct btd_attribute *attr = g_malloc0(sizeof(struct btd_attribute) +
									len);

	/*
	 * Service DECLARATION
	 *
	 *   TYPE         ATTRIBUTE VALUE
	 * +-------+---------------------------------+
	 * |0x2800 | 0xYYYY...                       |
	 * | (1)   | (2)                             |
	 * +------+----------------------------------+
	 * (1) - 2 octets: Primary/Secondary Service UUID
	 * (2) - 2 or 16 octets: Service UUID
	 */

	attr->type = primary_uuid;

	att_put_uuid(*uuid, attr->value);
	attr->value_len = len;

	if (local_database_add(next_handle, attr) < 0) {
		g_free(attr);
		return NULL;
	}

	/* TODO: missing overflow checking */
	next_handle = next_handle + 1;

	return attr;
}

static void send_error(int sk, uint8_t opcode, uint16_t handle, uint8_t ecode)
{
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	size_t plen;

	plen = enc_error_resp(opcode, handle, ecode, pdu, sizeof(pdu));
	write_pdu(sk, pdu, plen);
}

static bool channel_handler_cb(struct io *io, void *user_data)
{
	uint8_t ipdu[ATT_DEFAULT_LE_MTU];
	ssize_t ilen;
	int sk = io_get_fd(io);

	ilen = read(sk, ipdu, sizeof(ipdu));
	if (ilen < 0) {
		int err = errno;
		DBG("ATT channel read: %s(%d)", strerror(err), err);
		return false;
	}

	switch (ipdu[0]) {
	case ATT_OP_ERROR:
		break;

	/* Requests */
	case ATT_OP_WRITE_CMD:
	case ATT_OP_WRITE_REQ:
	case ATT_OP_READ_REQ:
	case ATT_OP_READ_BY_TYPE_REQ:
	case ATT_OP_MTU_REQ:
	case ATT_OP_FIND_INFO_REQ:
	case ATT_OP_FIND_BY_TYPE_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_READ_MULTI_REQ:
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_EXEC_WRITE_REQ:
	case ATT_OP_READ_BY_GROUP_REQ:
	case ATT_OP_SIGNED_WRITE_CMD:
		send_error(sk, ipdu[0], 0x0000, ATT_ECODE_REQ_NOT_SUPP);
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
		break;
	}

	return true;
}

static void channel_watch_destroy(void *user_data)
{
	struct io *io = user_data;

	io_destroy(io);
}

static bool unix_accept_cb(struct io *io, void *user_data)
{
	struct sockaddr_un uaddr;
	socklen_t len = sizeof(uaddr);
	struct io *nio;
	int err, nsk, sk;

	sk = io_get_fd(io);

	nsk = accept(sk, (struct sockaddr *) &uaddr, &len);
	if (nsk < 0) {
		err = errno;
		error("ATT UNIX socket accept: %s(%d)", strerror(err), err);
		return true;
	}

	DBG("ATT UNIX socket: %d", nsk);
	nio = io_new(nsk);

	io_set_close_on_destroy(nio, true);
	io_set_read_handler(nio, channel_handler_cb, nio,
						channel_watch_destroy);

	return true;
}

void gatt_init(void)
{
	struct sockaddr_un uaddr  = {
		.sun_family     = AF_UNIX,
		.sun_path       = "\0/bluetooth/unix_att",
	};
	int sk, err;

	DBG("Starting GATT server");

	gatt_dbus_manager_register();

	sk = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC , 0);
	if (sk < 0) {
		err = errno;
		error("ATT UNIX socket: %s(%d)", strerror(err), err);
		return;
	}

	if (bind(sk, (struct sockaddr *) &uaddr, sizeof(uaddr)) < 0) {
		err = errno;
		error("binding ATT UNIX socket: %s(%d)", strerror(err), err);
		close(sk);
		return;
	}

	if (listen(sk, 5) < 0) {
		err = errno;
		error("listen ATT UNIX socket: %s(%d)", strerror(err), err);
		close(sk);
		return;
	}

	server_io = io_new(sk);
	io_set_close_on_destroy(server_io, true);
	io_set_read_handler(server_io, unix_accept_cb, NULL, NULL);
}

void gatt_cleanup(void)
{
	DBG("Stopping GATT server");

	gatt_dbus_manager_unregister();
	io_destroy(server_io);
}
