/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>
#include <stdbool.h>
#include <glib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "lib/uuid.h"
#include "att.h"
#include "gattrib.h"
#include "gatt_lib.h"

struct discover_primary {
	GAttrib *attrib;
	bt_uuid_t uuid;
	GSList *primaries;
	gatt_cb_t cb;
	void *user_data;
};

/* Used for the Included Services Discovery (ISD) procedure */
struct included_discovery {
	GAttrib		*attrib;
	int		refs;
	int		err;
	uint16_t	end_handle;
	GSList		*includes;
	gatt_cb_t	cb;
	void		*user_data;
};

struct included_uuid_query {
	struct included_discovery	*isd;
	struct gatt_included		*included;
};

struct discover_char {
	GAttrib *attrib;
	bt_uuid_t *uuid;
	uint16_t end;
	GSList *characteristics;
	gatt_cb_t cb;
	void *user_data;
};

static void discover_primary_free(struct discover_primary *dp)
{
	g_slist_free_full(dp->primaries, g_free);
	g_attrib_unref(dp->attrib);
	g_free(dp);
}

static struct included_discovery *isd_ref(struct included_discovery *isd)
{
	__sync_fetch_and_add(&isd->refs, 1);

	return isd;
}

static void isd_unref(struct included_discovery *isd)
{
	if (__sync_sub_and_fetch(&isd->refs, 1) > 0)
		return;

	if (isd->err)
		isd->cb(isd->err, NULL, isd->user_data);
	else
		isd->cb(isd->err, isd->includes, isd->user_data);

	g_slist_free_full(isd->includes, g_free);
	g_attrib_unref(isd->attrib);
	g_free(isd);
}

static void discover_char_free(struct discover_char *dc)
{
	g_slist_free_full(dc->characteristics, g_free);
	g_attrib_unref(dc->attrib);
	g_free(dc->uuid);
	g_free(dc);
}

static guint16 encode_discover_primary(uint16_t start, uint16_t end,
				bt_uuid_t *uuid, uint8_t *pdu, size_t len)
{
	bt_uuid_t prim;
	guint16 plen;

	bt_uuid16_create(&prim, GATT_PRIM_SVC_UUID);

	if (uuid == NULL) {
		/* Discover all primary services */
		plen = enc_read_by_grp_req(start, end, &prim, pdu, len);
	} else {
		uint16_t u16;
		uint128_t u128;
		const void *value;
		size_t vlen;

		/* Discover primary service by service UUID */

		if (uuid->type == BT_UUID16) {
			u16 = htobs(uuid->value.u16);
			value = &u16;
			vlen = sizeof(u16);
		} else {
			htob128(&uuid->value.u128, &u128);
			value = &u128;
			vlen = sizeof(u128);
		}

		plen = enc_find_by_type_req(start, end, &prim, value, vlen,
								pdu, len);
	}

	return plen;
}

static void primary_by_uuid_cb(guint8 status, const guint8 *ipdu,
					guint16 iplen, gpointer user_data)

{
	struct discover_primary *dp = user_data;
	GSList *ranges, *last;
	struct att_range *range;
	uint16_t last_handle;
	uint8_t *buf;
	guint16 oplen;
	int err = 0;
	size_t buflen;

	if (status) {
		err = status;
		goto done;
	}

	ranges = dec_find_by_type_resp(ipdu, iplen);
	if (ranges == NULL)
		goto done;

	dp->primaries = g_slist_concat(dp->primaries, ranges);

	last = g_slist_last(ranges);
	range = last->data;
	last_handle = range->end;

	/* From the Core spec: "It is permitted to end the sub-procedure early
	 * if a desired primary service is found prior to discovering all the
	 * primary services of the specified service UUID supported on the
	 * server."
	 *
	 * In other words, this callback will receive the partial list of
	 * discovered services, and if it returns false, the procedure is
	 * interrupted.
	 */
	if (dp->cb(err, dp->primaries, dp->user_data)) {
		g_slist_free_full(dp->primaries, g_free);
		dp->primaries = NULL;
	} else {
		discover_primary_free(dp);
		return;
	}

	if (last_handle == 0xffff) {
		/* From Core spec ESR06: "This sub-procedure is complete when
		 * the Error Response is received and the Error Code is set to
		 * <<Attribute Not Found>> or when the End Group Handle in the
		 * [Find by Type] Response is 0xFFFF."
		 *
		 * To avoid the caller having to check for the second case, we
		 * set the error code artificially here.
		 */
		err = ATT_ECODE_ATTR_NOT_FOUND;
		goto done;
	}

	buf = g_attrib_get_buffer(dp->attrib, &buflen);
	oplen = encode_discover_primary(last_handle + 1, 0xffff, &dp->uuid,
								buf, buflen);

	if (oplen == 0)
		goto done;

	g_attrib_send(dp->attrib, 0, buf, oplen, primary_by_uuid_cb, dp, NULL);
	return;

done:
	dp->cb(err, dp->primaries, dp->user_data);
	discover_primary_free(dp);
}

static void primary_all_cb(guint8 status, const guint8 *ipdu, guint16 iplen,
							gpointer user_data)
{
	struct discover_primary *dp = user_data;
	struct att_data_list *list;
	unsigned int i, err;
	uint16_t start, end;

	if (status) {
		err = status;
		goto done;
	}

	list = dec_read_by_grp_resp(ipdu, iplen);
	if (list == NULL) {
		err = ATT_ECODE_IO;
		goto done;
	}

	for (i = 0, end = 0; i < list->num; i++) {
		const uint8_t *data = list->data[i];
		struct gatt_primary *primary;
		bt_uuid_t uuid;

		start = att_get_u16(&data[0]);
		end = att_get_u16(&data[2]);

		if (list->len == 6) {
			bt_uuid_t uuid16 = att_get_uuid16(&data[4]);
			bt_uuid_to_uuid128(&uuid16, &uuid);
		} else if (list->len == 20) {
			uuid = att_get_uuid128(&data[4]);
		} else {
			/* Skipping invalid data */
			continue;
		}

		primary = g_try_new0(struct gatt_primary, 1);
		if (!primary) {
			att_data_list_free(list);
			err = ATT_ECODE_INSUFF_RESOURCES;
			goto done;
		}
		primary->range.start = start;
		primary->range.end = end;
		bt_uuid_to_string(&uuid, primary->uuid, sizeof(primary->uuid));
		dp->primaries = g_slist_append(dp->primaries, primary);
	}

	att_data_list_free(list);
	err = 0;

	/* From the Core spec: "It is permitted to end the sub-procedure early
	 * if a desired primary service is found prior to discovering all the
	 * primary services on the server."
	 *
	 * In other words, this callback will receive the partial list of
	 * discovered services, and if it returns false, the procedure is
	 * interrupted.
	 */
	if (dp->cb(err, dp->primaries, dp->user_data)) {
		g_slist_free_full(dp->primaries, g_free);
		dp->primaries = NULL;
	} else {
		discover_primary_free(dp);
		return;
	}

	if (end != 0xffff) {
		size_t buflen;
		uint8_t *buf = g_attrib_get_buffer(dp->attrib, &buflen);
		guint16 oplen = encode_discover_primary(end + 1, 0xffff, NULL,
								buf, buflen);

		g_attrib_send(dp->attrib, 0, buf, oplen, primary_all_cb,
								dp, NULL);

		return;
	} else {
		/* From Core spec ESR06: "This sub-procedure is complete when
		 * the Error Response is received and the Error Code is set to
		 * <<Attribute Not Found>> or when the End Group Handle in the
		 * Read by Type Group Response is 0xFFFF."
		 *
		 * To avoid the caller having to check for the second case, we
		 * set the error code artificially here.
		 */
		err = ATT_ECODE_ATTR_NOT_FOUND;
	}

done:
	dp->cb(err, dp->primaries, dp->user_data);
	discover_primary_free(dp);
}

guint gatt_discover_primary(GAttrib *attrib, bt_uuid_t *uuid, gatt_cb_t func,
							gpointer user_data)
{
	struct discover_primary *dp;
	size_t buflen;
	uint8_t *buf = g_attrib_get_buffer(attrib, &buflen);
	GAttribResultFunc cb;
	guint16 plen;

	plen = encode_discover_primary(0x0001, 0xffff, uuid, buf, buflen);
	if (plen == 0)
		return 0;

	dp = g_try_new0(struct discover_primary, 1);
	if (dp == NULL)
		return 0;

	dp->attrib = g_attrib_ref(attrib);
	dp->cb = func;
	dp->user_data = user_data;

	if (uuid) {
		dp->uuid = *uuid;
		cb = primary_by_uuid_cb;
	} else
		cb = primary_all_cb;

	return g_attrib_send(attrib, 0, buf, plen, cb, dp, NULL);
}

static void resolve_included_uuid_cb(uint8_t status, const uint8_t *pdu,
					uint16_t len, gpointer user_data)
{
	struct included_uuid_query *query = user_data;
	struct included_discovery *isd = query->isd;
	struct gatt_included *incl = query->included;
	unsigned int err = status;
	bt_uuid_t uuid;
	size_t buflen;
	uint8_t *buf;

	if (err)
		goto done;

	buf = g_attrib_get_buffer(isd->attrib, &buflen);
	if (dec_read_resp(pdu, len, buf, buflen) != 16) {
		err = ATT_ECODE_IO;
		goto done;
	}

	uuid = att_get_uuid128(buf);
	bt_uuid_to_string(&uuid, incl->uuid, sizeof(incl->uuid));
	isd->includes = g_slist_append(isd->includes, incl);

done:
	if (err)
		g_free(incl);

	if (isd->err == 0)
		isd->err = err;

	isd_unref(isd);

	g_free(query);
}

static guint resolve_included_uuid(struct included_discovery *isd,
					struct gatt_included *incl)
{
	struct included_uuid_query *query;
	size_t buflen;
	uint8_t *buf = g_attrib_get_buffer(isd->attrib, &buflen);
	guint16 oplen = enc_read_req(incl->range.start, buf, buflen);

	query = g_new0(struct included_uuid_query, 1);
	query->isd = isd_ref(isd);
	query->included = incl;

	return g_attrib_send(isd->attrib, 0, buf, oplen,
				resolve_included_uuid_cb, query, NULL);
}

static struct gatt_included *included_from_buf(const uint8_t *buf, gsize len)
{
	struct gatt_included *incl = g_new0(struct gatt_included, 1);

	incl->handle = att_get_u16(&buf[0]);
	incl->range.start = att_get_u16(&buf[2]);
	incl->range.end = att_get_u16(&buf[4]);

	if (len == 8) {
		bt_uuid_t uuid128;
		bt_uuid_t uuid16 = att_get_uuid16(&buf[6]);

		bt_uuid_to_uuid128(&uuid16, &uuid128);
		bt_uuid_to_string(&uuid128, incl->uuid, sizeof(incl->uuid));
	}

	return incl;
}

static void find_included_cb(uint8_t status, const uint8_t *pdu, uint16_t len,
							gpointer user_data);

static guint find_included(struct included_discovery *isd, uint16_t start)
{
	bt_uuid_t uuid;
	size_t buflen;
	uint8_t *buf = g_attrib_get_buffer(isd->attrib, &buflen);
	guint16 oplen;

	bt_uuid16_create(&uuid, GATT_INCLUDE_UUID);
	oplen = enc_read_by_type_req(start, isd->end_handle, &uuid,
							buf, buflen);

	return g_attrib_send(isd->attrib, 0, buf, oplen, find_included_cb,
							isd_ref(isd), NULL);
}

static void find_included_cb(uint8_t status, const uint8_t *pdu, uint16_t len,
							gpointer user_data)
{
	struct included_discovery *isd = user_data;
	uint16_t last_handle = isd->end_handle;
	unsigned int err = status;
	struct att_data_list *list;
	int i;

	if (err == ATT_ECODE_ATTR_NOT_FOUND)
		err = 0;

	if (status)
		goto done;

	list = dec_read_by_type_resp(pdu, len);
	if (list == NULL) {
		err = ATT_ECODE_IO;
		goto done;
	}

	if (list->len != 6 && list->len != 8) {
		err = ATT_ECODE_IO;
		att_data_list_free(list);
		goto done;
	}

	for (i = 0; i < list->num; i++) {
		struct gatt_included *incl;

		incl = included_from_buf(list->data[i], list->len);
		last_handle = incl->handle;

		/* 128 bit UUID, needs resolving */
		if (list->len == 6) {
			resolve_included_uuid(isd, incl);
			continue;
		}

		isd->includes = g_slist_append(isd->includes, incl);
	}

	att_data_list_free(list);

	if (last_handle < isd->end_handle)
		find_included(isd, last_handle + 1);

done:
	if (isd->err == 0)
		isd->err = err;

	isd_unref(isd);
}

unsigned int gatt_find_included(GAttrib *attrib, uint16_t start, uint16_t end,
					gatt_cb_t func, gpointer user_data)
{
	struct included_discovery *isd;

	isd = g_new0(struct included_discovery, 1);
	isd->attrib = g_attrib_ref(attrib);
	isd->end_handle = end;
	isd->cb = func;
	isd->user_data = user_data;

	return find_included(isd, start);
}

static void char_discovered_cb(guint8 status, const guint8 *ipdu, guint16 iplen,
							gpointer user_data)
{
	struct discover_char *dc = user_data;
	struct att_data_list *list;
	unsigned int i, err;
	bool continue_discovery;
	uint16_t last = 0;

	if (status) {
		err = status;
		goto done;
	}

	list = dec_read_by_type_resp(ipdu, iplen);
	if (list == NULL) {
		err = ATT_ECODE_IO;
		goto done;
	}

	for (i = 0; i < list->num; i++) {
		uint8_t *value = list->data[i];
		struct gatt_char *chars;
		bt_uuid_t uuid;

		last = att_get_u16(value);

		if (list->len == 7) {
			bt_uuid_t uuid16 = att_get_uuid16(&value[5]);
			bt_uuid_to_uuid128(&uuid16, &uuid);
		} else
			uuid = att_get_uuid128(&value[5]);

		if (dc->uuid && bt_uuid_cmp(dc->uuid, &uuid))
			continue;

		chars = g_try_new0(struct gatt_char, 1);
		if (!chars) {
			err = ATT_ECODE_INSUFF_RESOURCES;
			goto done;
		}

		chars->handle = last;
		chars->properties = value[2];
		chars->value_handle = att_get_u16(&value[3]);
		bt_uuid_to_string(&uuid, chars->uuid, sizeof(chars->uuid));
		dc->characteristics = g_slist_append(dc->characteristics,
									chars);
	}

	att_data_list_free(list);

	/* From the Core spec: "It is permitted to end the sub-procedure early
	 * if a desired characteristic is found prior to discovering all the
	 * characteristics of the specified service supported on the server."
	 *
	 * In other words, this callback will receive the partial list
	 * of discovered characteristics, and if it returns false, the
	 * procedure is interrupted.
	 */
	if (dc->characteristics != NULL) {
		continue_discovery = dc->cb(status, dc->characteristics,
								dc->user_data);
		g_slist_free_full(dc->characteristics, g_free);
		dc->characteristics = NULL;

		if (!continue_discovery)
			goto data_free;
	}

	if (last != 0 && (last + 1 < dc->end)) {
		bt_uuid_t uuid;
		guint16 oplen;
		size_t buflen;
		uint8_t *buf;

		buf = g_attrib_get_buffer(dc->attrib, &buflen);

		bt_uuid16_create(&uuid, GATT_CHARAC_UUID);

		oplen = enc_read_by_type_req(last + 1, dc->end, &uuid, buf,
									buflen);

		if (oplen == 0)
			return;

		g_attrib_send(dc->attrib, 0, buf, oplen, char_discovered_cb,
								dc, NULL);

		return;
	}

	/* Procedure has finished */
	err = ATT_ECODE_ATTR_NOT_FOUND;

done:
	dc->cb(err, dc->characteristics, dc->user_data);
data_free:
	discover_char_free(dc);
}

guint gatt_discover_char(GAttrib *attrib, uint16_t start, uint16_t end,
						bt_uuid_t *uuid, gatt_cb_t func,
						gpointer user_data)
{
	size_t buflen;
	uint8_t *buf = g_attrib_get_buffer(attrib, &buflen);
	struct discover_char *dc;
	bt_uuid_t type_uuid;
	guint16 plen;

	bt_uuid16_create(&type_uuid, GATT_CHARAC_UUID);

	plen = enc_read_by_type_req(start, end, &type_uuid, buf, buflen);
	if (plen == 0)
		return 0;

	dc = g_try_new0(struct discover_char, 1);
	if (dc == NULL)
		return 0;

	dc->attrib = g_attrib_ref(attrib);
	dc->cb = func;
	dc->user_data = user_data;
	dc->end = end;
	dc->uuid = g_memdup(uuid, sizeof(bt_uuid_t));

	return g_attrib_send(attrib, 0, buf, plen, char_discovered_cb,
								dc, NULL);
}

struct read_char_by_uuid {
	gatt_cb_t func;
	void *user_data;
};

static void gatt_att_free(gpointer data)
{
	struct gatt_att *gatt_att = data;

	g_free(gatt_att->value);
	g_free(gatt_att);
}

static void read_char_by_uuid_cb(uint8_t status, const uint8_t *pdu,
						uint16_t plen, void *user_data)
{
	struct read_char_by_uuid *rd = user_data;
	struct att_data_list *att_list = NULL;
	GSList *gatt_list = NULL;
	int i;

	if (status != 0)
		goto done;

	att_list = dec_read_by_type_resp(pdu, plen);
	if (att_list == NULL) {
		status = ATT_ECODE_IO;
		goto done;
	}

	for (i = 0; i < att_list->num; i++) {
		uint8_t *data = att_list->data[i];
		struct gatt_att *gatt_att = g_new0(struct gatt_att, 1);
		gatt_att->handle = att_get_u16(&data[0]);
		gatt_att->size = att_list->len - 2;
		gatt_att->value = g_memdup(&data[2], gatt_att->size);
		gatt_list = g_slist_prepend(gatt_list, gatt_att);
	}

done:
	att_data_list_free(att_list);
	rd->func(status, gatt_list, rd->user_data);
	g_slist_free_full(gatt_list, gatt_att_free);
}

guint gatt_read_char_by_uuid(GAttrib *attrib, uint16_t start, uint16_t end,
						bt_uuid_t *uuid, gatt_cb_t func,
						gpointer user_data)
{
	struct read_char_by_uuid *data;
	size_t buflen;
	uint8_t *buf = g_attrib_get_buffer(attrib, &buflen);
	guint16 plen;

	plen = enc_read_by_type_req(start, end, uuid, buf, buflen);
	if (plen == 0)
		return 0;

	data = g_new0(struct read_char_by_uuid, 1);
	data->func = func;
	data->user_data = user_data;

	return g_attrib_send(attrib, 0, buf, plen, read_char_by_uuid_cb, data,
									g_free);
}

struct read_long_data {
	GAttrib *attrib;
	gatt_read_char_cb_t func;
	void *user_data;
	guint8 *buffer;
	guint16 size;
	guint16 handle;
	guint id;
	int ref;
};

static void read_long_destroy(gpointer user_data)
{
	struct read_long_data *long_read = user_data;

	if (__sync_sub_and_fetch(&long_read->ref, 1) > 0)
		return;

	if (long_read->buffer != NULL)
		g_free(long_read->buffer);

	g_free(long_read);
}

static void read_blob_helper(guint8 status, const guint8 *rpdu, guint16 rlen,
							gpointer user_data)
{
	struct read_long_data *long_read = user_data;
	uint8_t *buf;
	size_t buflen;
	guint8 *tmp;
	guint16 plen;
	guint id;

	if (status != 0 || rlen == 1) {
		status = 0;
		goto done;
	}

	tmp = g_try_realloc(long_read->buffer, long_read->size + rlen - 1);

	if (tmp == NULL) {
		status = ATT_ECODE_INSUFF_RESOURCES;
		goto done;
	}

	memcpy(&tmp[long_read->size], &rpdu[1], rlen - 1);
	long_read->buffer = tmp;
	long_read->size += rlen - 1;

	buf = g_attrib_get_buffer(long_read->attrib, &buflen);
	if (rlen < buflen)
		goto done;

	plen = enc_read_blob_req(long_read->handle, long_read->size - 1,
								buf, buflen);
	id = g_attrib_send(long_read->attrib, long_read->id, buf, plen,
				read_blob_helper, long_read, read_long_destroy);

	if (id != 0) {
		__sync_fetch_and_add(&long_read->ref, 1);
		return;
	}

	status = ATT_ECODE_IO;

done:
	if (status != 0)
		long_read->func(status, NULL, 0, long_read->user_data);
	else
		long_read->func(status, long_read->buffer + 1,
				long_read->size - 1, long_read->user_data);
}

static void read_char_helper(guint8 status, const guint8 *rpdu,
					guint16 rlen, gpointer user_data)
{
	struct read_long_data *long_read = user_data;
	size_t buflen;
	uint8_t *buf = g_attrib_get_buffer(long_read->attrib, &buflen);
	guint16 plen;
	guint id;

	if (status != 0 || rlen < buflen)
		goto done;

	long_read->buffer = g_malloc(rlen);
	if (long_read->buffer == NULL) {
		status = ATT_ECODE_INSUFF_RESOURCES;
		goto done;
	}

	memcpy(long_read->buffer, rpdu, rlen);
	long_read->size = rlen;

	plen = enc_read_blob_req(long_read->handle, rlen - 1, buf, buflen);

	id = g_attrib_send(long_read->attrib, long_read->id, buf, plen,
				read_blob_helper, long_read, read_long_destroy);
	if (id != 0) {
		__sync_fetch_and_add(&long_read->ref, 1);
		return;
	}

	status = ATT_ECODE_IO;

done:
	if (dec_read_resp(rpdu, rlen, NULL, 0) < 0)
		status = ATT_ECODE_INVALID_PDU;

	if (status != 0)
		long_read->func(status, NULL, 0, long_read->user_data);
	else
		long_read->func(status, rpdu + 1, rlen - 1,
							long_read->user_data);
}

guint gatt_read_char(GAttrib *attrib, uint16_t handle, gatt_read_char_cb_t func,
							void *user_data)
{
	uint8_t *buf;
	size_t buflen;
	guint16 plen;
	guint id;
	struct read_long_data *long_read;

	long_read = g_try_new0(struct read_long_data, 1);

	if (long_read == NULL)
		return 0;

	long_read->attrib = attrib;
	long_read->func = func;
	long_read->user_data = user_data;
	long_read->handle = handle;

	buf = g_attrib_get_buffer(attrib, &buflen);
	plen = enc_read_req(handle, buf, buflen);
	id = g_attrib_send(attrib, 0, buf, plen, read_char_helper,
						long_read, read_long_destroy);
	if (id == 0)
		g_free(long_read);
	else {
		__sync_fetch_and_add(&long_read->ref, 1);
		long_read->id = id;
	}

	return id;
}

struct write_long_data {
	GAttrib *attrib;
	gatt_write_char_cb_t func;
	void *user_data;
	guint16 handle;
	uint16_t offset;
	uint8_t *value;
	size_t vlen;
};

struct gatt_write_char_data {
	gatt_write_char_cb_t func;
	void *user_data;
};

static void execute_write_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gatt_write_char_data *data = user_data;

	if (status != 0)
		goto done;

	if (dec_exec_write_resp(pdu, plen) == 0)
		status = ATT_ECODE_IO;

done:
	data->func(status, data->user_data);
}

static guint execute_write(GAttrib *attrib, uint8_t flags,
				gatt_write_char_cb_t func, void *user_data)
{
	struct gatt_write_char_data *data;
	uint8_t *buf;
	size_t buflen;
	guint16 plen;

	buf = g_attrib_get_buffer(attrib, &buflen);
	plen = enc_exec_write_req(flags, buf, buflen);
	if (plen == 0)
		return 0;

	data = g_new0(struct gatt_write_char_data, 1);
	data->func = func;
	data->user_data = user_data;

	return g_attrib_send(attrib, 0, buf, plen, execute_write_cb, data,
									g_free);
}

static guint prepare_write(struct write_long_data *long_write);

static void prepare_write_cb(guint8 status, const guint8 *rpdu, guint16 rlen,
							gpointer user_data)
{
	struct write_long_data *long_write = user_data;

	if (status != 0) {
		long_write->func(status, long_write->user_data);
		return;
	}

	/* Skip Prepare Write Response PDU header (5 bytes) */
	long_write->offset += rlen - 5;

	if (long_write->offset == long_write->vlen) {
		execute_write(long_write->attrib, ATT_WRITE_ALL_PREP_WRITES,
				long_write->func, long_write->user_data);
		g_free(long_write->value);
		g_free(long_write);

		return;
	}

	prepare_write(long_write);
}

static guint prepare_write(struct write_long_data *long_write)
{
	GAttrib *attrib = long_write->attrib;
	uint16_t handle = long_write->handle;
	uint16_t offset = long_write->offset;
	uint8_t *buf, *value = long_write->value + offset;
	size_t buflen, vlen = long_write->vlen - offset;
	guint16 plen;

	buf = g_attrib_get_buffer(attrib, &buflen);

	plen = enc_prep_write_req(handle, offset, value, vlen, buf, buflen);
	if (plen == 0)
		return 0;

	return g_attrib_send(attrib, 0, buf, plen, prepare_write_cb, long_write,
									NULL);
}

static void gatt_write_char_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gatt_write_char_data *data = user_data;

	if (status != 0)
		goto done;

	if (dec_write_resp(pdu, plen) == 0)
		status = ATT_ECODE_IO;

done:
	data->func(status, data->user_data);
}

guint gatt_write_char(GAttrib *attrib, uint16_t handle, const uint8_t *value,
					size_t vlen, gatt_write_char_cb_t func,
					void *user_data)
{
	uint8_t *buf;
	size_t buflen;
	struct write_long_data *long_write;

	buf = g_attrib_get_buffer(attrib, &buflen);

	/* Use Write Request if payload fits on a single transfer, including 3
	 * bytes for the header. */
	if (vlen <= buflen - 3) {
		struct gatt_write_char_data *data;

		uint16_t plen;

		plen = enc_write_req(handle, value, vlen, buf, buflen);
		if (plen == 0)
			return 0;

		data = g_new0(struct gatt_write_char_data, 1);
		data->func = func;
		data->user_data = user_data;

		return g_attrib_send(attrib, 0, buf, plen, gatt_write_char_cb,
								data, g_free);
	}

	/* Write Long Characteristic Values */
	long_write = g_try_new0(struct write_long_data, 1);
	if (long_write == NULL)
		return 0;

	long_write->attrib = attrib;
	long_write->func = func;
	long_write->user_data = user_data;
	long_write->handle = handle;
	long_write->value = g_memdup(value, vlen);
	long_write->vlen = vlen;

	return prepare_write(long_write);
}

struct gatt_exchange_mtu_data {
	gatt_exchange_mtu_cb_t func;
	void *user_data;
};

static void gatt_exchange_mtu_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gatt_exchange_mtu_data *data = user_data;
	uint16_t rmtu = 0;

	if (status != 0)
		goto done;

	if (dec_mtu_resp(pdu, plen, &rmtu) == 0)
		status = ATT_ECODE_IO;

done:
	data->func(status, rmtu, data->user_data);
}

guint gatt_exchange_mtu(GAttrib *attrib, uint16_t mtu,
				gatt_exchange_mtu_cb_t func, void *user_data)
{
	struct gatt_exchange_mtu_data *data;
	uint8_t *buf;
	size_t buflen;
	guint16 plen;

	data = g_new0(struct gatt_exchange_mtu_data, 1);
	data->func = func;
	data->user_data = user_data;

	buf = g_attrib_get_buffer(attrib, &buflen);
	plen = enc_mtu_req(mtu, buf, buflen);

	return g_attrib_send(attrib, 0, buf, plen, gatt_exchange_mtu_cb, data,
									g_free);
}

struct discover_char_desc_data {
	GAttrib *attrib;
	uint16_t end;
	gatt_cb_t func;
	gpointer user_data;
};

static void gatt_discover_char_desc_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct discover_char_desc_data *data = user_data;
	struct att_data_list *list;
	GSList *char_descs = NULL;
	uint16_t last_handle = 0xffff;
	bool continue_discovery;
	uint8_t format;
	unsigned int i;

	if (status != 0)
		goto done;

	list = dec_find_info_resp(pdu, plen, &format);
	if (list == NULL) {
		status = ATT_ECODE_IO;
		goto done;
	}

	for (i = 0; i < list->num; i++) {
		uint8_t *value = list->data[i];
		struct gatt_char_desc *desc;

		desc = g_new0(struct gatt_char_desc, 1);
		desc->handle = att_get_u16(value);
		last_handle = desc->handle;

		if (format == ATT_FIND_INFO_RESP_FMT_16BIT)
			desc->uuid = att_get_uuid16(&value[2]);
		else
			desc->uuid = att_get_uuid128(&value[2]);

		char_descs = g_slist_append(char_descs, desc);
	}

	att_data_list_free(list);

	/* From the Core spec: "It is permitted to end the sub-procedure early
	 * if a desired Characteristic Descriptor is found prior to discovering
	 * all the characteristic descriptors of the specified characteristic."
	 *
	 * In other words, this callback will receive the partial list of
	 * discovered descriptors, and if it returns false, the procedure is
	 * interrupted.
	 */
	continue_discovery = data->func(status, char_descs, data->user_data);
	g_slist_free_full(char_descs, g_free);

	if (!continue_discovery)
		goto data_free;

	if (last_handle != 0xffff && last_handle < data->end) {
		uint8_t *buf;
		size_t buflen;
		uint16_t plen;

		buf = g_attrib_get_buffer(data->attrib, &buflen);
		plen = enc_find_info_req(last_handle + 1, data->end, buf,
									buflen);
		g_attrib_send(data->attrib, 0, buf, plen,
					gatt_discover_char_desc_cb, data, NULL);

		return;
	} else
		/* Procedure has finished */
		status = ATT_ECODE_ATTR_NOT_FOUND;

done:
	data->func(status, NULL, data->user_data);
data_free:
	g_attrib_unref(data->attrib);
	g_free(data);
}

guint gatt_discover_char_desc(GAttrib *attrib, uint16_t start, uint16_t end,
					gatt_cb_t func, gpointer user_data)
{
	struct discover_char_desc_data *data;
	uint8_t *buf;
	size_t buflen;
	guint16 plen;

	buf = g_attrib_get_buffer(attrib, &buflen);
	plen = enc_find_info_req(start, end, buf, buflen);
	if (plen == 0)
		return 0;

	data = g_new0(struct discover_char_desc_data, 1);
	data->attrib = g_attrib_ref(attrib);
	data->end = end;
	data->func = func;
	data->user_data = user_data;

	return g_attrib_send(attrib, 0, buf, plen, gatt_discover_char_desc_cb,
								data, NULL);
}

guint gatt_write_cmd(GAttrib *attrib, uint16_t handle, uint8_t *value, int vlen,
				GDestroyNotify notify, gpointer user_data)
{
	uint8_t *buf;
	size_t buflen;
	guint16 plen;

	buf = g_attrib_get_buffer(attrib, &buflen);
	plen = enc_write_cmd(handle, value, vlen, buf, buflen);
	return g_attrib_send(attrib, 0, buf, plen, NULL, user_data, notify);
}

static sdp_data_t *proto_seq_find(sdp_list_t *proto_list)
{
	sdp_list_t *list;
	uuid_t proto;

	sdp_uuid16_create(&proto, ATT_UUID);

	for (list = proto_list; list; list = list->next) {
		sdp_list_t *p;
		for (p = list->data; p; p = p->next) {
			sdp_data_t *seq = p->data;
			if (seq && seq->dtd == SDP_UUID16 &&
				sdp_uuid16_cmp(&proto, &seq->val.uuid) == 0)
				return seq->next;
		}
	}

	return NULL;
}

static gboolean parse_proto_params(sdp_list_t *proto_list, uint16_t *psm,
						uint16_t *start, uint16_t *end)
{
	sdp_data_t *seq1, *seq2;

	if (psm)
		*psm = sdp_get_proto_port(proto_list, L2CAP_UUID);

	/* Getting start and end handle */
	seq1 = proto_seq_find(proto_list);
	if (!seq1 || seq1->dtd != SDP_UINT16)
		return FALSE;

	seq2 = seq1->next;
	if (!seq2 || seq2->dtd != SDP_UINT16)
		return FALSE;

	if (start)
		*start = seq1->val.uint16;

	if (end)
		*end = seq2->val.uint16;

	return TRUE;
}

gboolean gatt_parse_record(const sdp_record_t *rec,
					uuid_t *prim_uuid, uint16_t *psm,
					uint16_t *start, uint16_t *end)
{
	sdp_list_t *list;
	uuid_t uuid;
	gboolean ret;

	if (sdp_get_service_classes(rec, &list) < 0)
		return FALSE;

	memcpy(&uuid, list->data, sizeof(uuid));
	sdp_list_free(list, free);

	if (sdp_get_access_protos(rec, &list) < 0)
		return FALSE;

	ret = parse_proto_params(list, psm, start, end);

	sdp_list_foreach(list, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(list, NULL);

	/* FIXME: replace by bt_uuid_t after uuid_t/sdp code cleanup */
	if (ret && prim_uuid)
		memcpy(prim_uuid, &uuid, sizeof(uuid_t));

	return ret;
}
