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

static const bt_uuid_t chr_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_CHARAC_UUID };

struct btd_attribute {
	uint16_t handle;
	bt_uuid_t type;
	btd_attr_read_t read_cb;
	btd_attr_write_t write_cb;
	uint16_t value_len;
	uint8_t value[0];
};

struct procedure_data {
	uint16_t handle;		/* Operation handle */
	struct io *io;			/* Connection reference */
	GList *match;			/* List of matching attributes */
	size_t vlen;			/* Pattern: length of each value */
	size_t olen;				/* Output PDU length */
	uint8_t opdu[ATT_DEFAULT_LE_MTU];	/* Output PDU */
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

static bool is_service(struct btd_attribute *attr)
{
	if (attr->type.type != BT_UUID16)
		return false;

	if (attr->type.value.u16 == GATT_PRIM_SVC_UUID ||
			attr->type.value.u16 == GATT_SND_SVC_UUID)
		return true;

	return false;
}

static uint8_t errno_to_att(int err)
{
	switch (err) {
	case EACCES:
		return ATT_ECODE_AUTHORIZATION;
	case EINVAL:
		return ATT_ECODE_INVAL_ATTR_VALUE_LEN;
	case ENOENT:
		return ATT_ECODE_ATTR_NOT_FOUND;
	default:
		return ATT_ECODE_UNLIKELY;
	}
}

static int find_by_handle(const void *a, const void *b)
{
	const struct btd_attribute *attr = a;

	return attr->handle - GPOINTER_TO_UINT(b);
}

void btd_gatt_read_attribute(struct btd_attribute *attr,
					btd_attr_read_result_t result,
					void *user_data)
{
	/*
	 * When read_cb is available, it means that the attribute value
	 * is dynamic, and its value must be read from the external
	 * implementation. If "value_len" is set, the attribute value is
	 * constant. Additional checking are performed by the attribute server
	 * when the ATT Read request arrives based on the characteristic
	 * properties. At this point, properties bitmask doesn't need to be
	 * checked.
	 */
	if (attr->read_cb)
		attr->read_cb(attr, result, user_data);
	else if (attr->value_len > 0)
		result(0, attr->value, attr->value_len, user_data);
	else
		result(EPERM, NULL, 0, user_data);
}

/*
 * Helper function to create new attributes containing constant/static values.
 * eg: declaration of services/characteristics, and characteristics with
 * fixed values.
 */
static struct btd_attribute *new_const_attribute(const bt_uuid_t *type,
							const uint8_t *value,
							uint16_t len)
{
	struct btd_attribute *attr = g_malloc0(sizeof(struct btd_attribute) +
									len);

	memcpy(&attr->type, type, sizeof(*type));
	memcpy(&attr->value, value, len);
	attr->value_len = len;

	return attr;
}

static int local_database_add(uint16_t handle, struct btd_attribute *attr)
{
	attr->handle = handle;

	local_attribute_db = g_list_append(local_attribute_db, attr);

	return 0;
}

struct btd_attribute *btd_gatt_add_service(const bt_uuid_t *uuid)
{
	struct btd_attribute *attr;
	uint16_t len = bt_uuid_len(uuid);
	uint8_t value[len];

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

	/* Set attribute value */
	att_put_uuid(*uuid, value);

	attr = new_const_attribute(&primary_uuid, value, len);

	if (local_database_add(next_handle, attr) < 0) {
		g_free(attr);
		return NULL;
	}

	/* TODO: missing overflow checking */
	next_handle = next_handle + 1;

	return attr;
}

void btd_gatt_remove_service(struct btd_attribute *service)
{
	GList *list = g_list_find(local_attribute_db, service);
	bool first_node = local_attribute_db == list;

	if (list == NULL)
		return;

	/* Remove service declaration attribute */
	g_free(list->data);
	list = g_list_delete_link(list, list);

	/* Remove all characteristics until next service declaration */
	while (list && !is_service(list->data)) {
		g_free(list->data);
		list = g_list_delete_link(list, list);
	}

	/*
	 * When removing the first node, local attribute database head
	 * needs to be updated. Node removed from middle doesn't change
	 * the list head address.
	 */
	if (first_node)
		local_attribute_db = list;
}

struct btd_attribute *btd_gatt_add_char(bt_uuid_t *uuid, uint8_t properties,
						btd_attr_read_t read_cb,
						btd_attr_write_t write_cb)
{
	struct btd_attribute *char_decl, *char_value = NULL;

	/* Attribute value length */
	uint16_t len = 1 + 2 + bt_uuid_len(uuid);
	uint8_t value[len];

	/*
	 * Characteristic DECLARATION
	 *
	 *   TYPE         ATTRIBUTE VALUE
	 * +-------+---------------------------------+
	 * |0x2803 | 0xXX 0xYYYY 0xZZZZ...           |
	 * | (1)   |  (2)   (3)   (4)                |
	 * +------+----------------------------------+
	 * (1) - 2 octets: Characteristic declaration UUID
	 * (2) - 1 octet : Properties
	 * (3) - 2 octets: Handle of the characteristic Value
	 * (4) - 2 or 16 octets: Characteristic UUID
	 */

	value[0] = properties;

	/*
	 * Since we don't know yet the characteristic value attribute
	 * handle, we skip and set it later.
	 */

	att_put_uuid(*uuid, &value[3]);

	char_decl = new_const_attribute(&chr_uuid, value, len);
	if (local_database_add(next_handle, char_decl) < 0)
		goto fail;

	next_handle = next_handle + 1;

	/*
	 * Characteristic VALUE
	 *
	 *   TYPE         ATTRIBUTE VALUE
	 * +----------+---------------------------------+
	 * |0xZZZZ... | 0x...                           |
	 * |  (1)     |  (2)                            |
	 * +----------+---------------------------------+
	 * (1) - 2 or 16 octets: Characteristic UUID
	 * (2) - N octets: Value is read dynamically from the service
	 * implementation (external entity).
	 */

	char_value = g_new0(struct btd_attribute, 1);
	memcpy(&char_value->type, uuid, sizeof(char_value->type));
	char_value->read_cb = read_cb;
	char_value->write_cb = write_cb;

	if (local_database_add(next_handle, char_value) < 0)
		goto fail;

	next_handle = next_handle + 1;

	/*
	 * Update characteristic value handle in characteristic declaration
	 * attribute. For local attributes, we can assume that the handle
	 * representing the characteristic value will get the next available
	 * handle. However, for remote attribute this assumption is not valid.
	 */
	att_put_u16(char_value->handle, &char_decl->value[1]);

	return char_value;

fail:
	g_free(char_decl);
	g_free(char_value);

	return NULL;
}

static void send_error(int sk, uint8_t opcode, uint16_t handle, uint8_t ecode)
{
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	size_t plen;

	plen = enc_error_resp(opcode, handle, ecode, pdu, sizeof(pdu));
	write_pdu(sk, pdu, plen);
}

static void read_by_group_resp(int sk, uint16_t start,
					uint16_t end, bt_uuid_t *pattern)
{
	uint8_t opdu[ATT_DEFAULT_LE_MTU];
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

		if (uuid_type != BT_UUID_UNSPEC &&
						uuid_type != attr->type.type) {
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
		if ((plen + group_len) >= ATT_DEFAULT_LE_MTU)
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
		send_error(sk, ATT_OP_READ_BY_GROUP_REQ, start,
						ATT_ECODE_ATTR_NOT_FOUND);
		return;
	}

	if (group_end)
		att_put_u16(last->handle, group_end);

	write_pdu(sk, opdu, plen);
}

static void read_by_group(int sk, const uint8_t *ipdu, ssize_t ilen)
{
	uint16_t decoded, start, end;
	bt_uuid_t pattern;

	decoded = dec_read_by_grp_req(ipdu, ilen, &start, &end, &pattern);
	if (decoded == 0) {
		send_error(sk, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	if (start > end || start == 0x0000) {
		send_error(sk, ipdu[0], start, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	 /*
	  * Restricting Read By Group Type to <<Primary>>.
	  * Removing the checking below requires changes to support
	  * dynamic values(defined in the upper layer) and additional
	  * security verification.
	  */
	if (bt_uuid_cmp(&pattern, &primary_uuid) != 0) {
		send_error(sk, ipdu[0], start, ATT_ECODE_UNSUPP_GRP_TYPE);
		return;
	}

	read_by_group_resp(sk, start, end, &pattern);
}

static void read_by_type_result(int sk, uint8_t *value, size_t vlen,
								void *user_data)
{
	struct procedure_data *proc = user_data;
	GList *head = proc->match;
	struct btd_attribute *attr = head->data;

	proc->match = g_list_delete_link(proc->match, head);

	/* According to Core v4.0 spec, page 1853, if the attribute
	 * value is longer than (ATT_MTU - 4) or 253 octets, whichever
	 * is smaller, then the first (ATT_MTU - 4) or 253 octets shall
	 * be included in this response.
	 * TODO: Replace ATT_DEFAULT_LE_MTU by the correct transport MTU
	 */

	if (proc->olen == 0) {
		proc->vlen = MIN((uint16_t) (ATT_DEFAULT_LE_MTU - 4),
							MIN(vlen, 253));

		/* First entry: Set handle-value length */
		proc->opdu[proc->olen++] = ATT_OP_READ_BY_TYPE_RESP;
		proc->opdu[proc->olen++] = 2 + proc->vlen;
	} else if (proc->vlen != MIN(vlen, 253))
		/* Length doesn't match with handle-value length */
		goto send;

	/* It there space enough for another handle-value pair? */
	if (proc->olen + 2 + proc->vlen > ATT_DEFAULT_LE_MTU)
		goto send;

	/* Copy attribute handle into opdu */
	att_put_u16(attr->handle, &proc->opdu[proc->olen]);
	proc->olen += 2;

	/* Copy attribute value into opdu */
	memcpy(&proc->opdu[proc->olen], value, proc->vlen);
	proc->olen += proc->vlen;

	if (proc->match == NULL)
		goto send;

	/* Getting the next attribute */
	attr = proc->match->data;

	read_by_type_result(sk, attr->value, attr->value_len, proc);

	return;

send:
	write_pdu(sk, proc->opdu, proc->olen);
	g_list_free(proc->match);
	g_free(proc);
}

static void read_by_type(int sk, const uint8_t *ipdu, size_t ilen)
{
	struct procedure_data *proc;
	struct btd_attribute *attr;
	GList *list;
	uint16_t start, end;
	bt_uuid_t uuid;

	if (dec_read_by_type_req(ipdu, ilen, &start, &end, &uuid) == 0) {
		send_error(sk, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	DBG("Read By Type: 0x%04x to 0x%04x", start, end);

	if (start == 0x0000 || start > end) {
		send_error(sk, ipdu[0], start, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	proc = g_malloc0(sizeof(*proc));

	for (list = local_attribute_db; list; list = g_list_next(list)) {
		attr = list->data;

		if (attr->handle < start)
			continue;

		if (attr->handle > end)
			break;

		if (bt_uuid_cmp(&attr->type, &uuid) != 0)
			continue;

		/* Checking attribute consistency */
		if (attr->value_len == 0)
			continue;

		proc->match = g_list_append(proc->match, attr);
	}

	if (proc->match == NULL) {
		send_error(sk, ipdu[0], start, ATT_ECODE_ATTR_NOT_FOUND);
		g_free(proc);
		return;
	}

	attr = proc->match->data;
	read_by_type_result(sk, attr->value, attr->value_len, proc);
}

static void read_request_result(int err, uint8_t *value, size_t len,
							void *user_data)
{
	struct procedure_data *proc = user_data;
	int sk = io_get_fd(proc->io);

	if (err) {
		send_error(sk, ATT_OP_READ_REQ, proc->handle,
						errno_to_att(err));
		return;
	}

	proc->olen = enc_read_resp(value, len, proc->opdu, sizeof(proc->opdu));
	write_pdu(sk, proc->opdu, proc->olen);
	g_free(proc);
}

static void read_request(struct io *io, const uint8_t *ipdu, size_t ilen)
{
	struct procedure_data *proc;
	uint16_t handle;
	GList *list;
	struct btd_attribute *attr;
	int sk = io_get_fd(io);

	if (dec_read_req(ipdu, ilen, &handle) == 0) {
		send_error(sk, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	list = g_list_find_custom(local_attribute_db,
				GUINT_TO_POINTER(handle), find_by_handle);
	if (!list) {
		send_error(sk, ipdu[0], 0x0000, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	attr = list->data;

	/* TODO: permission/property checking missing */

	/* Constant value */
	if (attr->value_len > 0) {
		uint8_t opdu[ATT_DEFAULT_LE_MTU];
		size_t olen = enc_read_resp(attr->value, attr->value_len, opdu,
								sizeof(opdu));

		write_pdu(sk, opdu, olen);
		return;
	}

	/* Dynamic value provided by external entity */
	if (attr->read_cb == NULL) {
		send_error(sk, ATT_OP_READ_REQ, handle,
						ATT_ECODE_READ_NOT_PERM);
		return;
	}

	/*
	 * For external characteristics (GATT server), the read callback
	 * is mapped to a simple proxy function call.
	 */
	proc = g_malloc0(sizeof(*proc));
	proc->io = io;
	proc->handle = handle;

	attr->read_cb(attr, read_request_result, proc);
}

static void write_cmd(int sk, const uint8_t *ipdu, size_t ilen)
{
	uint16_t handle;
	GList *list;
	struct btd_attribute *attr;
	size_t vlen;
	uint8_t value[ATT_DEFAULT_LE_MTU];

	if (dec_write_cmd(ipdu, ilen, &handle, value, &vlen) == 0)
		return;

	list = g_list_find_custom(local_attribute_db,
				GUINT_TO_POINTER(handle), find_by_handle);

	if (!list) {
		DBG("Attribute 0x%04x: not found", handle);
		return;
	}

	attr = list->data;

	if (attr->write_cb == NULL) {
		DBG("Attribute 0x%04x: Write not allowed", handle);
		return;
	}

	attr->write_cb(attr, value, vlen, NULL, NULL);
}

static void write_request_result(int err, void *user_data)
{
	struct procedure_data *proc = user_data;
	uint16_t olen;
	int sk = io_get_fd(proc->io);

	DBG("Write Request (0x%04X) status: %d", proc->handle, err);

	if (err != 0)
		olen = enc_error_resp(ATT_OP_WRITE_REQ, proc->handle,
						errno_to_att(err), proc->opdu,
						sizeof(proc->opdu));
	else
		olen = enc_write_resp(proc->opdu);

	write_pdu(sk, proc->opdu, olen);
	g_free(proc);
}

static void write_request(struct io *io, const uint8_t *ipdu, size_t ilen)
{
	struct procedure_data *proc;
	struct btd_attribute *attr;
	GList *list;
	size_t vlen;
	uint16_t handle;
	uint8_t value[ATT_DEFAULT_LE_MTU];
	int sk = io_get_fd(io);

	if (dec_write_req(ipdu, ilen, &handle, value, &vlen) == 0) {
		send_error(sk, ipdu[0], handle, ATT_ECODE_INVALID_PDU);
		return;
	}

	list = g_list_find_custom(local_attribute_db, GUINT_TO_POINTER(handle),
								find_by_handle);
	if (!list) {
		send_error(sk, ipdu[0], handle, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	attr = list->data;

	if (attr->write_cb == NULL) {
		send_error(sk, ipdu[0], handle, ATT_ECODE_WRITE_NOT_PERM);
		return;
	}

	/*
	 * For external characteristics (GATT server), the write callback
	 * is mapped to a DBusProxy simple proxy Set property method call.
	 */

	proc = g_malloc0(sizeof(*proc));
	proc->io = io;
	proc->handle = handle;

	DBG("Write Request (0x%04X)", proc->handle);
	attr->write_cb(attr, value, vlen, write_request_result, proc);
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
	case ATT_OP_MTU_REQ:
	case ATT_OP_FIND_INFO_REQ:
	case ATT_OP_FIND_BY_TYPE_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_READ_MULTI_REQ:
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_EXEC_WRITE_REQ:
	case ATT_OP_SIGNED_WRITE_CMD:
		send_error(sk, ipdu[0], 0x0000, ATT_ECODE_REQ_NOT_SUPP);
		break;

	case ATT_OP_READ_BY_GROUP_REQ:
		read_by_group(sk, ipdu, ilen);
		break;
	case ATT_OP_READ_BY_TYPE_REQ:
		read_by_type(sk, ipdu, ilen);
		break;
	case ATT_OP_READ_REQ:
		read_request(io, ipdu, ilen);
		break;
	case ATT_OP_WRITE_CMD:
		write_cmd(sk, ipdu, ilen);
		break;
	case ATT_OP_WRITE_REQ:
		write_request(io, ipdu, ilen);
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
