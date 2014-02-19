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
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <glib.h>

#include "adapter.h"
#include "device.h"
#include "log.h"
#include "lib/uuid.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "src/shared/io.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"

#include "textfile.h"
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
	struct attio *attio;		/* Queue reference */
	GList *match;			/* List of matching attributes */
	size_t vlen;			/* Pattern: length of each value */
	size_t olen;				/* Output PDU length */
	uint8_t opdu[ATT_DEFAULT_LE_MTU];	/* Output PDU */
};

struct attio {
	struct io *io;
	struct queue *request_queue;	/* Outgoing requests */
	struct queue *reply_queue;	/* Notification/Indication/Responses */
	unsigned int next_request_id;
	bool writer_active;
};

struct att_request {
	unsigned int id;
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	size_t plen;
};

static struct io *server_io;
static GSList *iolist;
static GList *local_attribute_db;
static uint16_t next_handle = 0x0001;
static struct btd_attribute *gatt, *gap;
static struct btd_attribute *service_changed;

/* Callbacks used for notifying attribute database changes */
static btd_attr_func_t attr_added_cb;
static btd_attr_func_t attr_removed_cb;
static void *attr_cb_user_data;

static void write_watch_destroy(void *user_data)
{
	struct attio *attio = user_data;

	attio->writer_active = false;
}

static bool can_write_data(struct io *io, void *user_data)
{
	struct attio *attio = user_data;
	int sk = io_get_fd(io);
	struct att_request *request;

	request = queue_pop_head(attio->request_queue);
	if (!request)
		return false;

	if (write(sk, request->pdu, request->plen) < 0)
		error("Error sending ATT PDU (0x%02X): %s (%d)",
				request->pdu[0], strerror(errno), errno);

	free(request);

	return false;

}

static void wakeup_writer(struct attio *attio)
{
	if (attio->writer_active)
		return;

	io_set_write_handler(attio->io, can_write_data, attio,
						write_watch_destroy);
}

static unsigned int pdu_send(struct attio *attio, const uint8_t *pdu,
								size_t plen)
{
	struct att_request *request;

	request = new0(struct att_request, 1);
	request->id = attio->next_request_id++;
	memcpy(request->pdu, pdu, plen);
	request->plen = plen;

	if (!queue_push_tail(attio->request_queue, request)) {
		free(request);
		return 0;
	}

	wakeup_writer(attio);

	return request->id;
}

static bool is_service(const struct btd_attribute *attr)
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

static struct btd_device *sock_get_device(int sk)
{
	struct btd_adapter *adapter;
	struct sockaddr_l2 l2addr;
	socklen_t l2len;
	int err;

	l2len = sizeof(l2addr);
	memset(&l2addr, 0, sizeof(l2addr));
	if (getsockname(sk, (struct sockaddr *) &l2addr, &l2len) == 0) {
		/*
		 * If this system call fails, there are something more
		 * critical. It doesn't make sense to reply or continue
		 * any GATT sub-procedure.
		 */
		err = errno;
		error("getsockname(): %s(%d)", strerror(err), err);
		/* TODO: return */
	}

	adapter = adapter_find(&l2addr.l2_bdaddr);

	l2len = sizeof(l2addr);
	memset(&l2addr, 0, sizeof(l2addr));
	if (getpeername(sk, (struct sockaddr *) &l2addr, &l2len) == 0) {
		err = errno;
		error("getpeername(): %s(%d)", strerror(err), err);
		/* TODO: return */
	}

	return btd_adapter_get_device(adapter, &l2addr.l2_bdaddr,
						l2addr.l2_bdaddr_type);

}

static GList *get_char_decl_from_attr(GList *attr_node)
{
	GList *char_decl_node;
	/*
	 * If any declaration is given (instead of a characteristic value), the
	 * previous attribute is always different from a characteristic declaration.
	 * A characteristic DECLARATION is always followed by a characteristic VALUE
	 * attribute.
	 */

	char_decl_node = g_list_previous(attr_node);
	while (char_decl_node) {
		struct btd_attribute *attr = char_decl_node->data;

		if (bt_uuid_cmp(&chr_uuid, &attr->type) == 0)
			return char_decl_node;

		char_decl_node = g_list_previous(char_decl_node);
	}

	return NULL;
}

static int read_ccc(struct btd_device *device, const char *key, uint16_t *value)
{
	char *filename;
	GKeyFile *key_file = g_key_file_new();
	gboolean ret;

	/* FIXME: Development purpose only. Remove it later. */
	if (!device)
		filename = g_strdup("/tmp/unix/gatt-settings");
	else
		filename = btd_device_get_storage_path(device, "gatt-settings");

	ret = g_key_file_load_from_file(key_file, filename, 0, NULL);
	if (ret == FALSE)
		goto done;

	*value = g_key_file_get_integer(key_file, "CCC", key, NULL);

	DBG("Read CCC handle: %s value: 0x%04x", key, *value);

done:
	g_free(filename);
	g_key_file_free(key_file);

	return (ret ? 0 : -ENOENT);
}

static void read_ccc_cb(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{

	GList *decl, *list = g_list_find(local_attribute_db, attr);
	struct btd_attribute *decl_attr;
	uint16_t value_handle, cccint = 0;
	uint8_t cccval[] = { 0x00, 0x00 };
	char key[6];

	/*
	 * When notification or indication arrives, it contains the handle of
	 * Characteristic Attribute value. In order to simplify the logic, the
	 * CCC storage uses the Attribute Characteristic value handle as key
	 * instead of using the Descriptor handle.
	 */

	decl = get_char_decl_from_attr(list);
	decl_attr = decl->data;

	value_handle = att_get_u16(decl_attr->value + 1);

	sprintf(key, "0x%04X", value_handle);

	read_ccc(device, key, &cccint);

	DBG("Read CCC %p handle: 0x%04x value: 0x%04x", attr, value_handle,
								cccint);

	att_put_u16(cccint, cccval);
	result(0, cccval, sizeof(cccval), user_data);
}

static int write_ccc(struct btd_device *device, const char *key, uint16_t ccc)
{
	GKeyFile *key_file;
	char *filename, *data;
	gboolean ret = FALSE;
	size_t rlen;

	/* FIXME: Development purpose only. Remove it later. */
	if (device)
		filename = btd_device_get_storage_path(device, "gatt-settings");
	else
		filename = g_strdup("/tmp/unix/gatt-settings");

	key_file = g_key_file_new();
	g_key_file_load_from_file(key_file, filename, 0, NULL);

	g_key_file_set_integer(key_file, "CCC", key, ccc);
	data = g_key_file_to_data(key_file, &rlen, NULL);
	if (rlen > 0) {
		create_file(filename, S_IRUSR | S_IWUSR);
		ret = g_file_set_contents(filename, data, rlen, NULL);
	}

	g_free(data);
	g_free(filename);
	g_key_file_free(key_file);

	return (ret ? 0 : -EIO);
}

static void write_ccc_cb(struct btd_device *device,
				struct btd_attribute *attr,
				const uint8_t *value, size_t len,
				btd_attr_write_result_t result,
				void *user_data)
{
	GList *decl, *list = g_list_find(local_attribute_db, attr);
	struct btd_attribute *decl_attr;
	uint16_t handle, ccc;
	char key[6];

	if (len != 2) {
		DBG("Invalid size for Characteristic Configuration Bits");
		if (result)
			result(EINVAL, user_data);
		return;
	}

	/*
	 * When notification or indication arrives, it contains the handle of
	 * Characteristic Attribute value. In order to simplify the logic, the
	 * CCC storage uses the Attribute Characteristic value handle as key
	 * instead of using the Descriptor handle.
	 */

	decl = get_char_decl_from_attr(list);
	decl_attr = decl->data;

	handle = att_get_u16(decl_attr->value + 1);
	sprintf(key, "0x%04X", handle);

	ccc = att_get_u16(value);
	write_ccc(device, key, ccc);

	DBG("Write CCC %p handle: 0x%04X value: 0x%04x", attr, handle, ccc);

	if (result)
		result(0, user_data);
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
		attr->read_cb(NULL, attr, result, user_data);
	else if (attr->value_len > 0)
		result(0, attr->value, attr->value_len, user_data);
	else
		result(EPERM, NULL, 0, user_data);
}

void btd_gatt_write_attribute(struct btd_attribute *attr,
				uint8_t *value, size_t len,
				btd_attr_write_result_t result,
				void *user_data)
{
	GSList *list;
	char key[6];

	/*
	 * Supports writting LOCAL attributes only. If this function gets
	 * called means that PropertyChanged was received. The external
	 * application doesn't control the connected devices. Here, we check
	 * if it is necessary to send notification or indication.
	 *
	 * Assuming that the API is being used properly, the given attribute
	 * MUST be characteristic "Value". It doesn't make sense to change
	 * attribute value of other types.
	 *
	 * The current API doesn't support notifying when and who received the
	 * ATT notification/indication.
	 */

	if (!iolist) {
		DBG("No peers connected to send notification or indication");
		if (result)
			result(0, user_data);
		return;
	}

	sprintf(key, "0x%04X", attr->handle);

	DBG("Writing attribute: %s", key);

	for (list = iolist; list; list = g_slist_next(list)) {
		uint8_t opdu[ATT_DEFAULT_LE_MTU];
		size_t olen;
		struct attio *attio = list->data;
		int sk = io_get_fd(attio->io);
		struct btd_device *device = sock_get_device(sk);
		uint16_t ccc;

		if (read_ccc(device, key, &ccc) < 0)
			continue;

		if (ccc & GATT_CLIENT_CHARAC_CFG_IND_BIT)
			olen = enc_indication(attr->handle, value, len,
							opdu, sizeof(opdu));
		else
			olen = enc_notification(attr->handle, value, len,
							opdu, sizeof(opdu));

		pdu_send(attio, opdu, olen);
	}

	if (result)
		result(0, user_data);
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

static struct btd_attribute *new_attribute(const bt_uuid_t *type,
						btd_attr_read_t read_cb,
						btd_attr_write_t write_cb)
{
	struct btd_attribute *attr = g_new0(struct btd_attribute, 1);

	attr->type = *type;
	attr->read_cb = read_cb;
	attr->write_cb = write_cb;

	return attr;
}

static int local_database_add(uint16_t handle, struct btd_attribute *attr)
{
	attr->handle = handle;

	local_attribute_db = g_list_append(local_attribute_db, attr);

	if (attr_added_cb)
		attr_added_cb(attr, attr->handle, &attr->type, attr->read_cb,
				attr->write_cb, attr->value_len, attr->value,
				attr_cb_user_data);

	return 0;
}

void btd_gatt_database_for_each(btd_attr_func_t func, void *user_data)
{
	GList *l;

	for (l = local_attribute_db; l; l = l->next) {
		struct btd_attribute *attr = l->data;

		func(attr, attr->handle, &attr->type, attr->read_cb,
				attr->write_cb, attr->value_len, attr->value,
				user_data);
	}
}

void btd_gatt_database_notify_update(btd_attr_func_t attr_added,
						btd_attr_func_t attr_removed,
						void *user_data)
{
	attr_added_cb = attr_added;
	attr_removed_cb = attr_removed;
	attr_cb_user_data = user_data;
}

static int cmp_uuid(const void *a, const void *b)
{
	const struct btd_attribute *attr = a;
	const bt_uuid_t *svc_uuid = b;
	bt_uuid_t uuid;

	if (!is_service(attr))
		return -1;

	if (attr->value_len == 2)
		uuid = att_get_uuid16(attr->value);
	else if (attr->value_len == 16)
		uuid = att_get_uuid128(attr->value);
	else
		return -1;

	return bt_uuid_cmp(svc_uuid, &uuid);
}

void btd_gatt_get_svc_range(bt_uuid_t *uuid, uint16_t *start, uint16_t *end)
{
	struct btd_attribute *attr;
	GList *l;

	l = g_list_find_custom(local_attribute_db, uuid, cmp_uuid);
	if (!l) {
		*start = 0;
		*end = 0;
		return;
	}

	attr = l->data;
	*start = attr->handle;
	*end = attr->handle;
	l = l->next;

	while (l) {
		attr = l->data;

		if (is_service(attr))
			break;

		*end = attr->handle;
		l = l->next;
	}
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

static GList *remove_local_attr(GList *node)
{
	struct btd_attribute *attr = node->data;

	if (attr_removed_cb)
		attr_removed_cb(attr, attr->handle, &attr->type, attr->read_cb,
				attr->write_cb, attr->value_len, attr->value,
				attr_cb_user_data);

	g_free(node->data);

	return g_list_delete_link(node, node);
}

void btd_gatt_remove_service(struct btd_attribute *service)
{
	GList *list = g_list_find(local_attribute_db, service);
	bool first_node = local_attribute_db == list;

	if (list == NULL)
		return;

	/* Remove service declaration attribute */
	list = remove_local_attr(list);

	/* Remove all characteristics until next service declaration */
	while (list && !is_service(list->data))
		list = remove_local_attr(list);

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

	char_value = new_attribute(uuid, read_cb, write_cb);

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

	if (properties & (GATT_CHR_PROP_INDICATE | GATT_CHR_PROP_NOTIFY)) {
		bt_uuid_t cfg_uuid;

		bt_uuid16_create(&cfg_uuid, GATT_CLIENT_CHARAC_CFG_UUID);
		if (btd_gatt_add_char_desc(&cfg_uuid, read_ccc_cb,
							write_ccc_cb) == NULL)
			goto fail;
	}

	return char_value;

fail:
	g_free(char_decl);
	g_free(char_value);

	return NULL;
}

struct btd_attribute *btd_gatt_add_char_desc(bt_uuid_t *uuid,
						btd_attr_read_t read_cb,
						btd_attr_write_t write_cb)
{
	struct btd_attribute *attr;

	/*
	 * From Core SPEC 4.1 page 2184:
	 * Characteristic descriptor declaration permissions are defined by a
	 * higher layer profile or are implementation specific. A client shall
	 * not assume all characteristic descriptor declarations are readable.
	 *
	 * The read/write callbacks presence will define the descriptor
	 * permissions managed directly by the core. The upper layer can define
	 * additional permissions constraints.
	 */

	attr = new_attribute(uuid, read_cb, write_cb);

	if (local_database_add(next_handle, attr) < 0) {
		g_free(attr);
		return NULL;
	}

	next_handle = next_handle + 1;

	return attr;
}

static void send_error(struct attio *attio, uint8_t opcode,
					uint16_t handle, uint8_t ecode)
{
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	size_t plen;

	plen = enc_error_resp(opcode, handle, ecode, pdu, sizeof(pdu));
	pdu_send(attio, pdu, plen);
}

static void read_by_group_resp(struct attio *attio, uint16_t start,
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
		send_error(attio, ATT_OP_READ_BY_GROUP_REQ, start,
						ATT_ECODE_ATTR_NOT_FOUND);
		return;
	}

	if (group_end)
		att_put_u16(last->handle, group_end);

	pdu_send(attio, opdu, plen);
}

static void read_by_group(struct attio *attio, const uint8_t *ipdu, ssize_t ilen)
{
	uint16_t decoded, start, end;
	bt_uuid_t pattern;

	decoded = dec_read_by_grp_req(ipdu, ilen, &start, &end, &pattern);
	if (decoded == 0) {
		send_error(attio, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	if (start > end || start == 0x0000) {
		send_error(attio, ipdu[0], start, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	 /*
	  * Restricting Read By Group Type to <<Primary>>.
	  * Removing the checking below requires changes to support
	  * dynamic values(defined in the upper layer) and additional
	  * security verification.
	  */
	if (bt_uuid_cmp(&pattern, &primary_uuid) != 0) {
		send_error(attio, ipdu[0], start, ATT_ECODE_UNSUPP_GRP_TYPE);
		return;
	}

	read_by_group_resp(attio, start, end, &pattern);
}

static void read_by_type_result(struct attio *attio, uint8_t *value,
						size_t vlen, void *user_data)
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

	read_by_type_result(attio, attr->value, attr->value_len, proc);

	return;

send:
	pdu_send(proc->attio, proc->opdu, proc->olen);
	g_list_free(proc->match);
	g_free(proc);
}

static void read_by_type(struct attio *attio, const uint8_t *ipdu, size_t ilen)
{
	struct procedure_data *proc;
	struct btd_attribute *attr;
	GList *list;
	uint16_t start, end;
	bt_uuid_t uuid;

	if (dec_read_by_type_req(ipdu, ilen, &start, &end, &uuid) == 0) {
		send_error(attio, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	DBG("Read By Type: 0x%04x to 0x%04x", start, end);

	if (start == 0x0000 || start > end) {
		send_error(attio, ipdu[0], start, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	proc = g_malloc0(sizeof(*proc));
	proc->attio = attio;

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
		send_error(attio, ipdu[0], start, ATT_ECODE_ATTR_NOT_FOUND);
		g_free(proc);
		return;
	}

	attr = proc->match->data;
	read_by_type_result(attio, attr->value, attr->value_len, proc);
}

static bool validate_att_operation(GList *attr_node, uint8_t opcode)
{
	GList *char_decl_node;
	struct btd_attribute *decl_attr;
	bool is_descriptor = false;

	/*
	 * All declarations are readable, and NOT writeable, some descriptors
	 * may have restrictions defined in the upper layer. For those, we let
	 * the proxy to return an error. For all attributes, except
	 * characteristic VALUE attribute we allow reading without checking
	 * permissions.
	 */

	char_decl_node = get_char_decl_from_attr(attr_node);
	decl_attr = (char_decl_node ? char_decl_node->data : NULL);

	if (decl_attr) {
		uint16_t handle = att_get_u16(decl_attr->value + 1);
		struct btd_attribute *attr = attr_node->data;
		is_descriptor = attr->handle != handle;
	}

	if (is_descriptor) {
		/*
		 * Allow reading or writing descriptor. The caller must
		 * check if read or write callback is available.
		 */
		return true;
	}

	/*
	 * "decl_attr" contains the reference to a characteristic DECLARATION when
	 * the given attribute node is a characteristic VALUE or descriptor,
	 * otherwise the search will return NULL.
	 */
	switch (opcode) {
	case ATT_OP_WRITE_REQ:
		if (decl_attr == NULL)
			return false;

		if (decl_attr->value[0] & GATT_CHR_PROP_WRITE)
			return true;
		break;
	case ATT_OP_WRITE_CMD:
		if (decl_attr == NULL)
			return false;

		if (decl_attr->value[0] & GATT_CHR_PROP_WRITE_WITHOUT_RESP)
			return true;
		break;
	case ATT_OP_READ_REQ:
		if (decl_attr == NULL)
			return true;

		if (decl_attr->value[0] & GATT_CHR_PROP_READ)
			return true;
	}

	return false;
}

static void read_request_result(int err, uint8_t *value, size_t len,
							void *user_data)
{
	struct procedure_data *proc = user_data;

	if (err) {
		send_error(proc->attio, ATT_OP_READ_REQ, proc->handle,
						errno_to_att(err));
		return;
	}

	proc->olen = enc_read_resp(value, len, proc->opdu, sizeof(proc->opdu));
	pdu_send(proc->attio, proc->opdu, proc->olen);
	g_free(proc);
}

static void read_request(struct attio *attio, const uint8_t *ipdu, size_t ilen)
{
	struct procedure_data *proc;
	uint16_t handle;
	GList *list;
	struct btd_device *device;
	struct btd_attribute *attr;
	int sk = io_get_fd(attio->io);

	if (dec_read_req(ipdu, ilen, &handle) == 0) {
		send_error(attio, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	list = g_list_find_custom(local_attribute_db,
				GUINT_TO_POINTER(handle), find_by_handle);
	if (!list) {
		send_error(attio, ipdu[0], 0x0000, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	attr = list->data;

	if (!validate_att_operation(list, ATT_OP_READ_REQ)) {
		send_error(attio, ATT_OP_READ_REQ, attr->handle,
						ATT_ECODE_READ_NOT_PERM);
		return;
	}

	/* Constant value */
	if (attr->value_len > 0) {
		uint8_t opdu[ATT_DEFAULT_LE_MTU];
		size_t olen = enc_read_resp(attr->value, attr->value_len, opdu,
								sizeof(opdu));

		pdu_send(attio, opdu, olen);
		return;
	}

	/* Dynamic value provided by external entity */
	if (attr->read_cb == NULL) {
		send_error(attio, ATT_OP_READ_REQ, handle,
						ATT_ECODE_READ_NOT_PERM);
		return;
	}

	/*
	 * For external characteristics (GATT server), the read callback
	 * is mapped to a simple proxy function call.
	 */
	proc = g_malloc0(sizeof(*proc));
	proc->attio = attio;
	proc->handle = handle;

	device = sock_get_device(sk);
	attr->read_cb(device, attr, read_request_result, proc);
}

static void write_cmd(int sk, const uint8_t *ipdu, size_t ilen)
{
	uint16_t handle;
	GList *list;
	struct btd_device *device;
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

	if (!validate_att_operation(list, ATT_OP_WRITE_CMD)) {
		DBG("Attribute 0x%04x: Write Command not allowed", handle);
		return;
	}

	if (attr->write_cb == NULL) {
		DBG("Attribute 0x%04x: Write not allowed", handle);
		return;
	}

	device = sock_get_device(sk);
	attr->write_cb(device, attr, value, vlen, NULL, NULL);
}

static void write_request_result(int err, void *user_data)
{
	struct procedure_data *proc = user_data;
	uint16_t olen;

	DBG("Write Request (0x%04X) status: %d", proc->handle, err);

	if (err != 0)
		olen = enc_error_resp(ATT_OP_WRITE_REQ, proc->handle,
						errno_to_att(err), proc->opdu,
						sizeof(proc->opdu));
	else
		olen = enc_write_resp(proc->opdu);

	pdu_send(proc->attio, proc->opdu, olen);
	g_free(proc);
}

static void write_request(struct attio *attio, const uint8_t *ipdu,
							size_t ilen)
{
	struct procedure_data *proc;
	struct btd_attribute *attr;
	struct btd_device *device;
	GList *list;
	size_t vlen;
	uint16_t handle;
	uint8_t value[ATT_DEFAULT_LE_MTU];
	int sk = io_get_fd(attio->io);

	if (dec_write_req(ipdu, ilen, &handle, value, &vlen) == 0) {
		send_error(attio, ipdu[0], handle, ATT_ECODE_INVALID_PDU);
		return;
	}

	list = g_list_find_custom(local_attribute_db, GUINT_TO_POINTER(handle),
								find_by_handle);
	if (!list) {
		send_error(attio, ipdu[0], handle, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	attr = list->data;

	if (attr->write_cb == NULL) {
		send_error(attio, ipdu[0], handle, ATT_ECODE_WRITE_NOT_PERM);
		return;
	}

	if (!validate_att_operation(list, ATT_OP_WRITE_REQ)) {
		send_error(attio, ipdu[0], handle, ATT_ECODE_WRITE_NOT_PERM);
		return;
	}

	/*
	 * For external characteristics (GATT server), the write callback
	 * is mapped to a DBusProxy simple proxy Set property method call.
	 */

	proc = g_malloc0(sizeof(*proc));
	proc->attio = attio;
	proc->handle = handle;

	DBG("Write Request (0x%04X)", proc->handle);
	device = sock_get_device(sk);
	attr->write_cb(device, attr, value, vlen, write_request_result, proc);
}

static void find_info_request(struct attio *attio, const uint8_t *ipdu,
								size_t ilen)
{
	struct btd_attribute *attr;
	size_t pairlen = 0, olen = 0, uuid_len;
	uint16_t start, end;
	uint8_t opdu[ATT_DEFAULT_LE_MTU];
	uint8_t format = ATT_FIND_INFO_RESP_FMT_16BIT;
	GList *list;

	if (dec_find_info_req(ipdu, ilen, &start, &end) == 0) {
		send_error(attio, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	if (start == 0x0000 || start > end) {
		send_error(attio, ipdu[0], 0x0000, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	/* ATT command to implement Discover All Characteristic Descriptors.
	 * handle-uuid pairs must be grouped based on UUIDs length.
	 *
	 * Packet formats:
	 *  16-bit Blueototh UUID: 0x05 0x01 0xhhhh 2-octets ...
	 * 128-bit Bluetooth UUID: 0x05 0x02 0xhhhh 16-octets
	 *
	 *
	 * 0x05: ATT Opcode for Find Information Response
	 * 0x01 or 0x02: Format 16 or 128-bit UUID
	 * 0xhhhh: attribute handle
	 */

	for (list = local_attribute_db; list; list = g_list_next(list)) {
		attr = list->data;

		if (attr->handle < start)
			continue;

		if (attr->handle > end)
			break;

		uuid_len = (size_t) bt_uuid_len(&attr->type);

		if (olen == 0) {

			/* opcode and format */
			olen = 2;

			/* handle-uuid pair length */
			pairlen = uuid_len + 2;

			format = attr->type.type == BT_UUID16 ?
					ATT_FIND_INFO_RESP_FMT_16BIT :
					ATT_FIND_INFO_RESP_FMT_128BIT;
		} else if (pairlen != uuid_len + 2)
			/* Different UUID format after the first loop */
			break;

		/* Check it there space enough for another handle-uuid pair */
		if (olen + pairlen > ATT_DEFAULT_LE_MTU)
			break;

		/* Copy attribute handle into opdu */
		att_put_u16(attr->handle, &opdu[olen]);
		olen += 2;

		/* Copy attribute UUID into opdu */
		att_put_uuid(attr->type, &opdu[olen]);
		olen += uuid_len;
	}

	if (olen == 0) {
		send_error(attio, ipdu[0], start, ATT_ECODE_ATTR_NOT_FOUND);
		return;
	}

	/* Set opcode and data format */
	opdu[0] = ATT_OP_FIND_INFO_RESP;
	opdu[1] = format;

	pdu_send(attio, opdu, olen);
}

static bool channel_handler_cb(struct io *io, void *user_data)
{
	struct attio *attio = user_data;
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
	case ATT_OP_FIND_BY_TYPE_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_READ_MULTI_REQ:
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_EXEC_WRITE_REQ:
	case ATT_OP_SIGNED_WRITE_CMD:
		send_error(attio, ipdu[0], 0x0000, ATT_ECODE_REQ_NOT_SUPP);
		break;

	case ATT_OP_READ_BY_GROUP_REQ:
		read_by_group(attio, ipdu, ilen);
		break;
	case ATT_OP_READ_BY_TYPE_REQ:
		read_by_type(attio, ipdu, ilen);
		break;
	case ATT_OP_READ_REQ:
		read_request(attio, ipdu, ilen);
		break;
	case ATT_OP_WRITE_CMD:
		write_cmd(sk, ipdu, ilen);
		break;
	case ATT_OP_WRITE_REQ:
		write_request(attio, ipdu, ilen);
		break;
	case ATT_OP_FIND_INFO_REQ:
		find_info_request(attio, ipdu, ilen);
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
	struct attio *attio = user_data;

	io_destroy(attio->io);
	iolist = g_slist_remove(iolist, attio);
	g_free(attio);
}

static bool write_service_changed_cb(struct io *io, void *user_data)
{
	struct attio *attio = user_data;
	uint8_t range[] = { 0x01, 0x00, 0xff, 0xff};
	uint8_t opdu[ATT_DEFAULT_LE_MTU];
	size_t olen;

	DBG("ATT: Sending <<Service Changed>>");

	olen = enc_indication(service_changed->handle, range, sizeof(range),
							opdu, sizeof(opdu));
	pdu_send(attio, opdu, olen);

	return false;
}

static bool unix_accept_cb(struct io *io, void *user_data)
{
	struct sockaddr_un uaddr;
	socklen_t len = sizeof(uaddr);
	struct attio *attio;
	int err, nsk, sk;

	sk = io_get_fd(io);

	nsk = accept(sk, (struct sockaddr *) &uaddr, &len);
	if (nsk < 0) {
		err = errno;
		error("ATT UNIX socket accept: %s(%d)", strerror(err), err);
		return true;
	}

	DBG("ATT UNIX socket: %d", nsk);
	attio = new0(struct attio, 1);
	attio->io = io_new(nsk);
	attio->writer_active = false;

	iolist = g_slist_append(iolist, attio);

	io_set_close_on_destroy(attio->io, true);
	io_set_read_handler(attio->io, channel_handler_cb, attio,
						channel_watch_destroy);

	/*
	 * While the support for Service Changed in not implemented, send
	 * indication when the link is established ignoring if the device is
	 * bonded or not.
	 */
	io_set_write_handler(attio->io, write_service_changed_cb, attio, NULL);

	return true;
}

static void read_name_cb(struct btd_device *device, struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{
	struct btd_adapter *adapter = btd_adapter_get_default();
	const char *name = adapter ? btd_adapter_get_name(adapter) : "";

	DBG("Reading GAP <<Device Name>>: %s", name);

	result(0, (uint8_t *) name, strlen(name), user_data);
}

static uint16_t appearance_from_class(uint16_t dev_class)
{
	switch ((dev_class & 0x1f00) >> 8) {
	case 0x01:
		/* Generic Computer */
		return 128;
	case 0x02:
		/* Generic Phone */
		return 64;
	}

	/* FIXME: We should build GAP appearance from the currently running
	 * GATT services. */

	/* Unknown */
	return 0;
}

static void read_appearance_cb(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{
	struct btd_adapter *adapter = btd_adapter_get_default();
	uint32_t dev_class = adapter ? btd_adapter_get_class(adapter) : 0x0000;
	uint16_t appearance = appearance_from_class(dev_class);
	uint8_t atval[2];

	DBG("Reading GAP <<Appearance>>: 0x%04x", appearance);
	att_put_u16(appearance, atval);

	result(0, atval, sizeof(atval), user_data);
}

static struct btd_attribute *gap_profile_add(void)
{
	struct btd_attribute *attr;
	bt_uuid_t uuid;
	uint8_t properties = GATT_CHR_PROP_READ;

	bt_uuid16_create(&uuid, GENERIC_ACCESS_PROFILE_ID);
	attr = btd_gatt_add_service(&uuid);
	if (!attr)
		return NULL;

	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	if (!btd_gatt_add_char(&uuid, properties, read_name_cb, NULL)) {
		btd_gatt_remove_service(attr);
		return NULL;
	}

	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	if (!btd_gatt_add_char(&uuid, properties, read_appearance_cb, NULL)) {
		btd_gatt_remove_service(attr);
		return NULL;
	}

	return attr;
}

static struct btd_attribute *gatt_profile_add(void)
{
	struct btd_attribute *attr;
	bt_uuid_t uuid;
	uint8_t properties = GATT_CHR_PROP_INDICATE;

	bt_uuid16_create(&uuid, GENERIC_ATTRIB_PROFILE_ID);
	attr = btd_gatt_add_service(&uuid);
	if (!attr)
		return NULL;

	/*
	 * «Service Changed» characteristic is a control-point attribute.
	 * CCC should be enabled by the clients to get indications when the
	 * have changed. Permissions: No Authentication, No Authorization,
	 * Not Readable, Not Writable.
	 *
	 * TODO: Manage CCC & indications when connections to bonded
	 * devices are established.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	service_changed = btd_gatt_add_char(&uuid, properties, NULL, NULL);
	if (!service_changed) {
		btd_gatt_remove_service(attr);
		return NULL;
	}

	return attr;
}

void gatt_init(void)
{
	struct sockaddr_un uaddr  = {
		.sun_family     = AF_UNIX,
		.sun_path       = "\0/bluetooth/unix_att",
	};
	int sk = -1, err;

	DBG("Starting GATT server");

	/* Add mandatory GATT service: GAP */
	gap = gap_profile_add();
	if (!gap) {
		error("GATT: Can't add GAP Profile service!");
		goto fail;
	}

	/* Add mandatory GATT services: GATT */
	gatt = gatt_profile_add();
	if (!gatt) {
		error("GATT: Can't add GATT Profile service!");
		goto fail;
	}

	gatt_dbus_manager_register();

	sk = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC , 0);
	if (sk < 0) {
		err = errno;
		error("ATT UNIX socket: %s(%d)", strerror(err), err);
		goto fail;
	}

	if (bind(sk, (struct sockaddr *) &uaddr, sizeof(uaddr)) < 0) {
		err = errno;
		error("binding ATT UNIX socket: %s(%d)", strerror(err), err);
		goto fail;
	}

	if (listen(sk, 5) < 0) {
		err = errno;
		error("listen ATT UNIX socket: %s(%d)", strerror(err), err);
		goto fail;
	}

	server_io = io_new(sk);
	io_set_close_on_destroy(server_io, true);
	io_set_read_handler(server_io, unix_accept_cb, NULL, NULL);

	return;

fail:
	if (sk > 0)
		close(sk);

	if (gap)
		btd_gatt_remove_service(gap);

	if (gatt)
		btd_gatt_remove_service(gatt);
}

void gatt_cleanup(void)
{
	DBG("Stopping GATT server");

	gatt_dbus_manager_unregister();
	io_destroy(server_io);
}
