/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/mgmt.h>

#include "log.h"
#include "adapter.h"
#include "manager.h"
#include "device.h"
#include "event.h"
#include "oob.h"
#include "eir.h"
#include "mgmt.h"

#define MGMT_BUF_SIZE 1024

struct pending_uuid {
	uuid_t uuid;
	uint8_t svc_hint;
};

static int max_index = -1;
static struct controller_info {
	gboolean valid;
	gboolean notified;
	bdaddr_t bdaddr;
	uint8_t version;
	uint16_t manufacturer;
	uint32_t supported_settings;
	uint32_t current_settings;
	uint8_t dev_class[3];
	GSList *connections;
	uint8_t discov_type;

	gboolean pending_uuid;
	GSList *pending_uuids;

	gboolean pending_class;
	uint8_t major;
	uint8_t minor;

	gboolean pending_powered;
	gboolean pending_cod_change;
} *controllers = NULL;

static int mgmt_sock = -1;
static guint mgmt_watch = 0;

static uint8_t mgmt_version = 0;
static uint16_t mgmt_revision = 0;

static void read_version_complete(int sk, void *buf, size_t len)
{
	struct mgmt_hdr hdr;
	struct mgmt_rp_read_version *rp = buf;

	if (len < sizeof(*rp)) {
		error("Too small read version complete event"
				" (probably an old kernel)");
		abort();
	}

	mgmt_revision = btohs(bt_get_unaligned(&rp->revision));
	mgmt_version = rp->version;

	DBG("version %u revision %u", mgmt_version, mgmt_revision);

	if (mgmt_version < 1) {
		error("Version 1 of mgmt needed (kernel has version %u)",
								mgmt_version);
		abort();
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = htobs(MGMT_OP_READ_INDEX_LIST);
	hdr.index = htobs(MGMT_INDEX_NONE);
	if (write(sk, &hdr, sizeof(hdr)) < 0)
		error("Unable to read controller index list: %s (%d)",
						strerror(errno), errno);
}

static void add_controller(uint16_t index)
{
	struct controller_info *info;

	if (index > max_index) {
		size_t size = sizeof(struct controller_info) * (index + 1);
		max_index = index;
		controllers = g_realloc(controllers, size);
	}

	info = &controllers[index];

	memset(info, 0, sizeof(*info));

	info->valid = TRUE;

	DBG("Added controller %u", index);
}

static void read_info(int sk, uint16_t index)
{
	struct mgmt_hdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = htobs(MGMT_OP_READ_INFO);
	hdr.index = htobs(index);

	if (write(sk, &hdr, sizeof(hdr)) < 0)
		error("Unable to send read_info command: %s (%d)",
						strerror(errno), errno);
}

static void get_connections(int sk, uint16_t index)
{
	struct mgmt_hdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = htobs(MGMT_OP_GET_CONNECTIONS);
	hdr.index = htobs(index);

	if (write(sk, &hdr, sizeof(hdr)) < 0)
		error("Unable to send get_connections command: %s (%d)",
						strerror(errno), errno);
}

static void mgmt_index_added(int sk, uint16_t index)
{
	add_controller(index);
	read_info(sk, index);
}

static void remove_controller(uint16_t index)
{
	if (index > max_index)
		return;

	if (!controllers[index].valid)
		return;

	btd_manager_unregister_adapter(index);

	g_slist_free_full(controllers[index].pending_uuids, g_free);
	controllers[index].pending_uuids = NULL;

	memset(&controllers[index], 0, sizeof(struct controller_info));

	DBG("Removed controller %u", index);
}

static void mgmt_index_removed(int sk, uint16_t index)
{
	remove_controller(index);
}

static int mgmt_set_mode(int index, uint16_t opcode, uint8_t val)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_mode)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_mode *cp = (void *) &buf[sizeof(*hdr)];

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(opcode);
	hdr->index = htobs(index);
	hdr->len = htobs(sizeof(*cp));

	cp->val = val;

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

static int mgmt_set_connectable(int index, gboolean connectable)
{
	DBG("index %d connectable %d", index, connectable);
	return mgmt_set_mode(index, MGMT_OP_SET_CONNECTABLE, connectable);
}

int mgmt_set_discoverable(int index, gboolean discoverable, uint16_t timeout)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_set_discoverable)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_set_discoverable *cp = (void *) &buf[sizeof(*hdr)];

	DBG("index %d discoverable %d", index, discoverable);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_SET_DISCOVERABLE);
	hdr->index = htobs(index);
	hdr->len = htobs(sizeof(*cp));

	cp->val = discoverable;
	cp->timeout = timeout;

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_set_pairable(int index, gboolean pairable)
{
	DBG("index %d pairable %d", index, pairable);
	return mgmt_set_mode(index, MGMT_OP_SET_PAIRABLE, pairable);
}

static inline int mgmt_powered(uint32_t settings)
{
	return (settings & MGMT_SETTING_POWERED) != 0;
}

static inline int mgmt_connectable(uint32_t settings)
{
	return (settings & MGMT_SETTING_CONNECTABLE) != 0;
}

static inline int mgmt_fast_connectable(uint32_t settings)
{
	return (settings & MGMT_SETTING_FAST_CONNECTABLE) != 0;
}

static inline int mgmt_discoverable(uint32_t settings)
{
	return (settings & MGMT_SETTING_DISCOVERABLE) != 0;
}

static inline int mgmt_pairable(uint32_t settings)
{
	return (settings & MGMT_SETTING_PAIRABLE) != 0;
}

static inline int mgmt_ssp(uint32_t settings)
{
	return (settings & MGMT_SETTING_SSP) != 0;
}

static inline int mgmt_bredr(uint32_t settings)
{
	return (settings & MGMT_SETTING_BREDR) != 0;
}

static inline int mgmt_high_speed(uint32_t settings)
{
	return (settings & MGMT_SETTING_HS) != 0;
}

static inline int mgmt_low_energy(uint32_t settings)
{
	return (settings & MGMT_SETTING_LE) != 0;
}

static uint8_t create_mode(uint32_t settings)
{
	uint8_t mode = 0;

	if (mgmt_connectable(settings))
		mode |= SCAN_PAGE;

	if (mgmt_discoverable(settings))
		mode |= SCAN_INQUIRY;

	return mode;
}

static void update_settings(struct btd_adapter *adapter, uint32_t settings)
{
	struct controller_info *info;
	gboolean pairable;
	uint8_t on_mode;
	uint16_t index, discoverable_timeout;

	DBG("new settings %x", settings);

	btd_adapter_get_mode(adapter, NULL, &on_mode, &discoverable_timeout,
								&pairable);

	index = adapter_get_dev_id(adapter);

	info = &controllers[index];

	if (on_mode == MODE_DISCOVERABLE && !mgmt_discoverable(settings)) {
		if(!mgmt_connectable(settings))
			mgmt_set_connectable(index, TRUE);
		mgmt_set_discoverable(index, TRUE, discoverable_timeout);
	} else if (on_mode == MODE_CONNECTABLE && !mgmt_connectable(settings)) {
		mgmt_set_connectable(index, TRUE);
	} else if (mgmt_powered(settings)) {
		adapter_mode_changed(adapter, create_mode(settings));
	}

	if (mgmt_pairable(settings) != pairable)
		mgmt_set_pairable(index, pairable);

	if (mgmt_ssp(info->supported_settings) && !mgmt_ssp(settings))
		mgmt_set_mode(index, MGMT_OP_SET_SSP, 1);

	if (mgmt_low_energy(info->supported_settings) &&
						!mgmt_low_energy(settings))
		mgmt_set_mode(index, MGMT_OP_SET_LE, 1);
}

static int mgmt_update_powered(struct btd_adapter *adapter,
						struct controller_info *info,
						uint32_t settings)
{
	if (!mgmt_powered(settings)) {
		btd_adapter_stop(adapter);
		g_slist_free_full(info->pending_uuids, g_free);
		info->pending_uuids = NULL;
		info->pending_uuid = FALSE;
		info->pending_class = FALSE;
		info->pending_cod_change = FALSE;
		return 0;
	}

	btd_adapter_start(adapter);

	update_settings(adapter, settings);

	return 0;
}

static int mode_changed(uint32_t s1, uint32_t s2)
{
	if (mgmt_connectable(s1) != mgmt_connectable(s2))
		return 1;

	if (mgmt_discoverable(s1) != mgmt_discoverable(s2))
		return 1;

	return 0;
}

static void mgmt_new_settings(int sk, uint16_t index, void *buf, size_t len)
{
	uint32_t settings, *ev = buf;
	struct controller_info *info;
	struct btd_adapter *adapter;
	gboolean old_power, new_power, old_pairable, new_pairable;

	if (len < sizeof(*ev)) {
		error("Too small new settings event");
		return;
	}

	DBG("hci%u new settings", index);

	if (index > max_index) {
		error("Unexpected index %u in new_settings event", index);
		return;
	}

	info = &controllers[index];

	adapter = manager_find_adapter(&info->bdaddr);
	if (adapter == NULL) {
		DBG("Adapter not found");
		return;
	}

	settings = bt_get_le32(ev);

	old_power = mgmt_powered(info->current_settings);
	new_power = mgmt_powered(settings);

	if (new_power != old_power)
		mgmt_update_powered(adapter, info, settings);
	else if (new_power && mode_changed(settings, info->current_settings))
		adapter_mode_changed(adapter, create_mode(settings));

	old_pairable = mgmt_pairable(info->current_settings);
	new_pairable = mgmt_pairable(settings);

	/* Check for pairable change, except when powered went from True
	 * to False (in which case we always get all settings as False) */
	if ((!old_power || new_power) && new_pairable != old_pairable)
		btd_adapter_pairable_changed(adapter, mgmt_pairable(settings));

	info->current_settings = settings;
}

static void bonding_complete(struct controller_info *info, bdaddr_t *bdaddr,
								uint8_t status)
{
	struct btd_adapter *adapter;

	adapter = manager_find_adapter(&info->bdaddr);
	if (adapter != NULL)
		adapter_bonding_complete(adapter, bdaddr, status);
}

static void mgmt_new_link_key(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_new_link_key *ev = buf;
	struct controller_info *info;

	if (len != sizeof(*ev)) {
		error("mgmt_new_link_key event size mismatch (%zu != %zu)",
							len, sizeof(*ev));
		return;
	}

	DBG("Controller %u new key of type %u pin_len %u", index,
					ev->key.type, ev->key.pin_len);

	if (index > max_index) {
		error("Unexpected index %u in new_key event", index);
		return;
	}

	if (ev->key.pin_len > 16) {
		error("Invalid PIN length (%u) in new_key event",
							ev->key.pin_len);
		return;
	}

	info = &controllers[index];

	if (ev->store_hint)
		btd_event_link_key_notify(&info->bdaddr, &ev->key.addr.bdaddr,
						ev->key.val, ev->key.type,
						ev->key.pin_len);

	bonding_complete(info, &ev->key.addr.bdaddr, 0);
}

static void mgmt_device_connected(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_device_connected *ev = buf;
	struct eir_data eir_data;
	struct controller_info *info;
	uint16_t eir_len;
	char addr[18];

	if (len < sizeof(*ev)) {
		error("Too small device_connected event");
		return;
	}

	eir_len = bt_get_le16(&ev->eir_len);
	if (len < sizeof(*ev) + eir_len) {
		error("Too small device_connected event");
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);

	DBG("hci%u device %s connected eir_len %u", index, addr, eir_len);

	if (index > max_index) {
		error("Unexpected index %u in device_connected event", index);
		return;
	}

	info = &controllers[index];

	memset(&eir_data, 0, sizeof(eir_data));
	if (eir_len > 0)
		eir_parse(&eir_data, ev->eir, eir_len);

	btd_event_conn_complete(&info->bdaddr, &ev->addr.bdaddr,
						ev->addr.type,
						eir_data.name,
						eir_data.dev_class);

	eir_data_free(&eir_data);
}

static void mgmt_device_disconnected(int sk, uint16_t index, void *buf,
								size_t len)
{
	struct mgmt_addr_info *ev = buf;
	struct controller_info *info;
	char addr[18];

	if (len < sizeof(*ev)) {
		error("Too small device_disconnected event");
		return;
	}

	ba2str(&ev->bdaddr, addr);

	DBG("hci%u device %s disconnected", index, addr);

	if (index > max_index) {
		error("Unexpected index %u in device_disconnected event", index);
		return;
	}

	info = &controllers[index];

	btd_event_disconn_complete(&info->bdaddr, &ev->bdaddr);
}

static void mgmt_connect_failed(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_connect_failed *ev = buf;
	struct controller_info *info;
	char addr[18];

	if (len < sizeof(*ev)) {
		error("Too small connect_failed event");
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);

	DBG("hci%u %s status %u", index, addr, ev->status);

	if (index > max_index) {
		error("Unexpected index %u in connect_failed event", index);
		return;
	}

	info = &controllers[index];

	btd_event_conn_failed(&info->bdaddr, &ev->addr.bdaddr, ev->status);

	/* In the case of security mode 3 devices */
	bonding_complete(info, &ev->addr.bdaddr, ev->status);
}

int mgmt_pincode_reply(int index, bdaddr_t *bdaddr, const char *pin,
								size_t pin_len)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_pin_code_reply)];
	struct mgmt_hdr *hdr = (void *) buf;
	size_t buf_len;
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("index %d addr %s pinlen %zu", index, addr, pin_len);

	memset(buf, 0, sizeof(buf));

	if (pin == NULL) {
		struct mgmt_cp_pin_code_neg_reply *cp;

		hdr->opcode = htobs(MGMT_OP_PIN_CODE_NEG_REPLY);
		hdr->len = htobs(sizeof(*cp));
		hdr->index = htobs(index);

		cp = (void *) &buf[sizeof(*hdr)];
		bacpy(&cp->addr.bdaddr, bdaddr);
		cp->addr.type = BDADDR_BREDR;

		buf_len = sizeof(*hdr) + sizeof(*cp);
	} else {
		struct mgmt_cp_pin_code_reply *cp;

		if (pin_len > 16)
			return -EINVAL;

		hdr->opcode = htobs(MGMT_OP_PIN_CODE_REPLY);
		hdr->len = htobs(sizeof(*cp));
		hdr->index = htobs(index);

		cp = (void *) &buf[sizeof(*hdr)];
		bacpy(&cp->addr.bdaddr, bdaddr);
		cp->addr.type = BDADDR_BREDR;
		cp->pin_len = pin_len;
		memcpy(cp->pin_code, pin, pin_len);

		buf_len = sizeof(*hdr) + sizeof(*cp);
	}

	if (write(mgmt_sock, buf, buf_len) < 0)
		return -errno;

	return 0;
}

static void mgmt_pin_code_request(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_pin_code_request *ev = buf;
	struct controller_info *info;
	char addr[18];
	int err;

	if (len < sizeof(*ev)) {
		error("Too small pin_code_request event");
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);

	DBG("hci%u %s", index, addr);

	if (index > max_index) {
		error("Unexpected index %u in pin_code_request event", index);
		return;
	}

	info = &controllers[index];

	err = btd_event_request_pin(&info->bdaddr, &ev->addr.bdaddr,
								ev->secure);
	if (err < 0) {
		error("btd_event_request_pin: %s", strerror(-err));
		mgmt_pincode_reply(index, &ev->addr.bdaddr, NULL, 0);
	}
}

int mgmt_confirm_reply(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type,
							gboolean success)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_user_confirm_reply)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_user_confirm_reply *cp;
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("index %d addr %s success %d", index, addr, success);

	memset(buf, 0, sizeof(buf));

	if (success)
		hdr->opcode = htobs(MGMT_OP_USER_CONFIRM_REPLY);
	else
		hdr->opcode = htobs(MGMT_OP_USER_CONFIRM_NEG_REPLY);

	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	cp = (void *) &buf[sizeof(*hdr)];
	bacpy(&cp->addr.bdaddr, bdaddr);
	cp->addr.type = bdaddr_type;

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_passkey_reply(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type,
							uint32_t passkey)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_user_passkey_reply)];
	struct mgmt_hdr *hdr = (void *) buf;
	size_t buf_len;
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("index %d addr %s passkey %06u", index, addr, passkey);

	memset(buf, 0, sizeof(buf));

	hdr->index = htobs(index);
	if (passkey == INVALID_PASSKEY) {
		struct mgmt_cp_user_passkey_neg_reply *cp;

		hdr->opcode = htobs(MGMT_OP_USER_PASSKEY_NEG_REPLY);
		hdr->len = htobs(sizeof(*cp));

		cp = (void *) &buf[sizeof(*hdr)];
		bacpy(&cp->addr.bdaddr, bdaddr);
		cp->addr.type = bdaddr_type;

		buf_len = sizeof(*hdr) + sizeof(*cp);
	} else {
		struct mgmt_cp_user_passkey_reply *cp;

		hdr->opcode = htobs(MGMT_OP_USER_PASSKEY_REPLY);
		hdr->len = htobs(sizeof(*cp));

		cp = (void *) &buf[sizeof(*hdr)];
		bacpy(&cp->addr.bdaddr, bdaddr);
		cp->addr.type = bdaddr_type;
		cp->passkey = htobl(passkey);

		buf_len = sizeof(*hdr) + sizeof(*cp);
	}

	if (write(mgmt_sock, buf, buf_len) < 0)
		return -errno;

	return 0;
}

static void mgmt_passkey_request(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_user_passkey_request *ev = buf;
	struct controller_info *info;
	char addr[18];
	int err;

	if (len < sizeof(*ev)) {
		error("Too small passkey_request event");
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);

	DBG("hci%u %s", index, addr);

	if (index > max_index) {
		error("Unexpected index %u in passkey_request event", index);
		return;
	}

	info = &controllers[index];

	err = btd_event_user_passkey(&info->bdaddr, &ev->addr.bdaddr);
	if (err < 0) {
		error("btd_event_user_passkey: %s", strerror(-err));
		mgmt_passkey_reply(index, &ev->addr.bdaddr, ev->addr.type,
							INVALID_PASSKEY);
	}
}

struct confirm_data {
	int index;
	bdaddr_t bdaddr;
	uint8_t type;
};

static gboolean confirm_accept(gpointer user_data)
{
	struct confirm_data *data = user_data;
	struct controller_info *info = &controllers[data->index];

	DBG("auto-accepting incoming pairing request");

	if (data->index > max_index || !info->valid)
		return FALSE;

	mgmt_confirm_reply(data->index, &data->bdaddr, data->type, TRUE);

	return FALSE;
}

static void mgmt_user_confirm_request(int sk, uint16_t index, void *buf,
								size_t len)
{
	struct mgmt_ev_user_confirm_request *ev = buf;
	struct controller_info *info;
	char addr[18];
	int err;

	if (len < sizeof(*ev)) {
		error("Too small user_confirm_request event");
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);

	DBG("hci%u %s confirm_hint %u", index, addr, ev->confirm_hint);

	if (index > max_index) {
		error("Unexpected index %u in user_confirm_request event",
									index);
		return;
	}

	if (ev->confirm_hint) {
		struct confirm_data *data;

		data = g_new0(struct confirm_data, 1);
		data->index = index;
		bacpy(&data->bdaddr, &ev->addr.bdaddr);
		data->type = ev->addr.type;

		g_timeout_add_seconds_full(G_PRIORITY_DEFAULT, 1,
						confirm_accept, data, g_free);
		return;
	}

	info = &controllers[index];

	err = btd_event_user_confirm(&info->bdaddr, &ev->addr.bdaddr,
							btohl(ev->value));
	if (err < 0) {
		error("btd_event_user_confirm: %s", strerror(-err));
		mgmt_confirm_reply(index, &ev->addr.bdaddr, ev->addr.type,
									FALSE);
	}
}

static void uuid_to_uuid128(uuid_t *uuid128, const uuid_t *uuid)
{
	if (uuid->type == SDP_UUID16)
		sdp_uuid16_to_uuid128(uuid128, uuid);
	else if (uuid->type == SDP_UUID32)
		sdp_uuid32_to_uuid128(uuid128, uuid);
	else
		memcpy(uuid128, uuid, sizeof(*uuid));
}

int mgmt_add_uuid(int index, uuid_t *uuid, uint8_t svc_hint)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_add_uuid)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_add_uuid *cp = (void *) &buf[sizeof(*hdr)];
	struct controller_info *info = &controllers[index];
	uuid_t uuid128;
	uint128_t uint128;

	DBG("index %d", index);

	if (info->pending_uuid) {
		struct pending_uuid *pending = g_new0(struct pending_uuid, 1);

		memcpy(&pending->uuid, uuid, sizeof(*uuid));
		pending->svc_hint = svc_hint;

		info->pending_uuids = g_slist_append(info->pending_uuids,
								pending);
		return 0;
	}

	uuid_to_uuid128(&uuid128, uuid);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_ADD_UUID);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	ntoh128((uint128_t *) uuid128.value.uuid128.data, &uint128);
	htob128(&uint128, (uint128_t *) cp->uuid);

	cp->svc_hint = svc_hint;

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	info->pending_uuid = TRUE;

	return 0;
}

int mgmt_remove_uuid(int index, uuid_t *uuid)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_remove_uuid)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_remove_uuid *cp = (void *) &buf[sizeof(*hdr)];
	uuid_t uuid128;
	uint128_t uint128;

	DBG("index %d", index);

	uuid_to_uuid128(&uuid128, uuid);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_REMOVE_UUID);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	ntoh128((uint128_t *) uuid128.value.uuid128.data, &uint128);
	htob128(&uint128, (uint128_t *) cp->uuid);

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

static int clear_uuids(int index)
{
	uuid_t uuid_any;

	memset(&uuid_any, 0, sizeof(uuid_any));
	uuid_any.type = SDP_UUID128;

	return mgmt_remove_uuid(index, &uuid_any);
}

static void read_index_list_complete(int sk, void *buf, size_t len)
{
	struct mgmt_rp_read_index_list *rp = buf;
	uint16_t num;
	int i;

	if (len < sizeof(*rp)) {
		error("Too small read index list complete event");
		return;
	}

	num = btohs(bt_get_unaligned(&rp->num_controllers));

	if (num * sizeof(uint16_t) + sizeof(*rp) != len) {
		error("Incorrect packet size for index list event");
		return;
	}

	for (i = 0; i < num; i++) {
		uint16_t index;

		index = btohs(bt_get_unaligned(&rp->index[i]));

		add_controller(index);
		read_info(sk, index);
	}
}

int mgmt_set_powered(int index, gboolean powered)
{
	struct controller_info *info = &controllers[index];

	DBG("index %d powered %d pending_uuid %u", index, powered,
							info->pending_uuid);

	if (powered) {
		if (info->pending_uuid) {
			info->pending_powered = TRUE;
			return 0;
		}
	} else {
		info->pending_powered = FALSE;
	}

	return mgmt_set_mode(index, MGMT_OP_SET_POWERED, powered);
}

int mgmt_set_name(int index, const char *name)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_set_local_name)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_set_local_name *cp = (void *) &buf[sizeof(*hdr)];

	DBG("index %d, name %s", index, name);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_SET_LOCAL_NAME);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	strncpy((char *) cp->name, name, sizeof(cp->name) - 1);

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_set_dev_class(int index, uint8_t major, uint8_t minor)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_set_dev_class)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_set_dev_class *cp = (void *) &buf[sizeof(*hdr)];
	struct controller_info *info = &controllers[index];

	DBG("index %d major %u minor %u", index, major, minor);

	if (info->pending_uuid) {
		info->major = major;
		info->minor = minor;
		info->pending_class = TRUE;
		return 0;
	}

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_SET_DEV_CLASS);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	cp->major = major;
	cp->minor = minor;

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

static void read_info_complete(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_rp_read_info *rp = buf;
	struct controller_info *info;
	struct btd_adapter *adapter;
	const char *name;
	uint8_t mode, major, minor;
	char addr[18];

	if (len < sizeof(*rp)) {
		error("Too small read info complete event");
		return;
	}

	if (index > max_index) {
		error("Unexpected index %u in read info complete", index);
		return;
	}

	info = &controllers[index];

	bacpy(&info->bdaddr, &rp->bdaddr);
	info->version = rp->version;
	info->manufacturer = btohs(bt_get_unaligned(&rp->manufacturer));

	memcpy(&info->supported_settings, &rp->supported_settings,
					sizeof(info->supported_settings));
	memcpy(&info->current_settings, &rp->current_settings,
					sizeof(info->current_settings));

	memcpy(info->dev_class, rp->dev_class, sizeof(info->dev_class));

	ba2str(&info->bdaddr, addr);
	DBG("hci%u addr %s version %u manufacturer %u class 0x%02x%02x%02x\n",
		index, addr, info->version, info->manufacturer,
		info->dev_class[2], info->dev_class[1], info->dev_class[0]);
	DBG("hci%u settings", index);
	DBG("hci%u name %s", index, (char *) rp->name);
	DBG("hci%u short name %s", index, (char *) rp->short_name);

	clear_uuids(index);

	adapter = btd_manager_register_adapter(index,
					mgmt_powered(info->current_settings));
	if (adapter == NULL) {
		error("mgmtops: unable to register adapter");
		return;
	}

	update_settings(adapter, info->current_settings);

	name = btd_adapter_get_name(adapter);

	DBG("mgmtops setting name %s", name);

	if (name)
		mgmt_set_name(index, name);
	else
		adapter_name_changed(adapter, (char *) rp->name);

	btd_adapter_get_class(adapter, &major, &minor);
	mgmt_set_dev_class(index, major, minor);

	btd_adapter_get_mode(adapter, &mode, NULL, NULL, NULL);
	if (mode == MODE_OFF && mgmt_powered(info->current_settings)) {
		mgmt_set_powered(index, FALSE);
		return;
	}

	if (mode != MODE_OFF) {
		if (mgmt_powered(info->current_settings)) {
			get_connections(sk, index);
			btd_adapter_start(adapter);
		} else
			mgmt_set_powered(index, TRUE);
	}

	btd_adapter_unref(adapter);
}

static void disconnect_complete(int sk, uint16_t index, uint8_t status,
							void *buf, size_t len)
{
	struct mgmt_rp_disconnect *rp = buf;
	struct controller_info *info;
	char addr[18];

	if (len < sizeof(*rp)) {
		error("Too small disconnect complete event");
		return;
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status != 0) {
		error("Disconnecting %s failed with status %u", addr, status);
		return;
	}

	DBG("hci%d %s disconnected", index, addr);

	if (index > max_index) {
		error("Unexpected index %u in disconnect complete", index);
		return;
	}

	info = &controllers[index];

	btd_event_disconn_complete(&info->bdaddr, &rp->addr.bdaddr);

	bonding_complete(info, &rp->addr.bdaddr, HCI_CONNECTION_TERMINATED);
}

static void pair_device_complete(int sk, uint16_t index, uint8_t status,
							void *buf, size_t len)
{
	struct mgmt_rp_pair_device *rp = buf;
	struct controller_info *info;
	char addr[18];

	if (len < sizeof(*rp)) {
		error("Too small pair_device complete event");
		return;
	}

	ba2str(&rp->addr.bdaddr, addr);

	DBG("hci%d %s pairing complete status %u", index, addr, status);

	if (index > max_index) {
		error("Unexpected index %u in pair_device complete", index);
		return;
	}

	info = &controllers[index];

	bonding_complete(info, &rp->addr.bdaddr, status);
}

static void get_connections_complete(int sk, uint16_t index, void *buf,
								size_t len)
{
	struct mgmt_rp_get_connections *rp = buf;
	struct controller_info *info;
	int i;

	if (len < sizeof(*rp)) {
		error("Too small get_connections complete event");
		return;
	}

	if (len < (sizeof(*rp) + (rp->conn_count * sizeof(bdaddr_t)))) {
		error("Too small get_connections complete event");
		return;
	}

	if (index > max_index) {
		error("Unexpected index %u in get_connections complete",
								index);
		return;
	}

	info = &controllers[index];

	for (i = 0; i < rp->conn_count; i++) {
		bdaddr_t *bdaddr = g_memdup(&rp->addr[i], sizeof(bdaddr_t));
		info->connections = g_slist_append(info->connections, bdaddr);
	}
}

static void set_local_name_complete(int sk, uint16_t index, void *buf,
								size_t len)
{
	struct mgmt_cp_set_local_name *rp = buf;
	struct controller_info *info;
	struct btd_adapter *adapter;

	if (len < sizeof(*rp)) {
		error("Too small set_local_name complete event");
		return;
	}

	DBG("hci%d name %s", index, (char *) rp->name);

	if (index > max_index) {
		error("Unexpected index %u in set_local_name complete", index);
		return;
	}

	info = &controllers[index];

	adapter = manager_find_adapter(&info->bdaddr);
	if (adapter == NULL) {
		DBG("Adapter not found");
		return;
	}

	adapter_name_changed(adapter, (char *) rp->name);
}

static void read_local_oob_data_complete(int sk, uint16_t index, void *buf,
								size_t len)
{
	struct mgmt_rp_read_local_oob_data *rp = buf;
	struct btd_adapter *adapter;

	if (len != sizeof(*rp)) {
		error("read_local_oob_data_complete event size mismatch "
					"(%zu != %zu)", len, sizeof(*rp));
		return;
	}

	if (index > max_index) {
		error("Unexpected index %u in read_local_oob_data_complete",
								index);
		return;
	}

	DBG("hci%u", index);

	adapter = manager_find_adapter_by_id(index);

	if (adapter)
		oob_read_local_data_complete(adapter, rp->hash, rp->randomizer);
}

static void start_discovery_complete(int sk, uint16_t index, uint8_t status,
						     void *buf, size_t len)
{
	uint8_t *type = buf;
	struct btd_adapter *adapter;

	if (len != sizeof(*type)) {
		error("start_discovery_complete event size mismatch "
					"(%zu != %zu)", len, sizeof(*type));
		return;
	}

	DBG("hci%u type %u status %u", index, *type, status);

	if (index > max_index) {
		error("Invalid index %u in start_discovery_complete", index);
		return;
	}

	if (!status)
		return;

	adapter = manager_find_adapter_by_id(index);
	if (adapter)
		/* Start discovery failed, inform upper layers. */
		adapter_set_discovering(adapter, FALSE);
}

static void read_local_oob_data_failed(int sk, uint16_t index)
{
	struct btd_adapter *adapter;

	if (index > max_index) {
		error("Unexpected index %u in read_local_oob_data_failed",
								index);
		return;
	}

	DBG("hci%u", index);

	adapter = manager_find_adapter_by_id(index);

	if (adapter)
		oob_read_local_data_complete(adapter, NULL, NULL);
}

static void handle_pending_uuids(uint16_t index)
{
	struct controller_info *info;
	struct pending_uuid *pending;

	DBG("index %d", index);

	info = &controllers[index];

	info->pending_uuid = FALSE;

	if (g_slist_length(info->pending_uuids) == 0) {
		if (info->pending_class) {
			info->pending_class = FALSE;
			mgmt_set_dev_class(index, info->major, info->minor);
		}

		if (info->pending_powered) {
			info->pending_powered = FALSE;
			mgmt_set_powered(index, TRUE);
		}

		return;
	}

	pending = info->pending_uuids->data;

	mgmt_add_uuid(index, &pending->uuid, pending->svc_hint);

	info->pending_uuids = g_slist_remove(info->pending_uuids, pending);
	g_free(pending);
}

static void mgmt_add_uuid_complete(int sk, uint16_t index, void *buf,
								size_t len)
{
	DBG("index %d", index);

	if (index > max_index) {
		error("Unexpected index %u in add_uuid_complete event", index);
		return;
	}

	handle_pending_uuids(index);
}

static void mgmt_cmd_complete(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_cmd_complete *ev = buf;
	uint16_t opcode;

	DBG("");

	if (len < sizeof(*ev)) {
		error("Too small management command complete event packet");
		return;
	}

	opcode = btohs(bt_get_unaligned(&ev->opcode));

	len -= sizeof(*ev);

	switch (opcode) {
	case MGMT_OP_READ_VERSION:
		read_version_complete(sk, ev->data, len);
		break;
	case MGMT_OP_READ_INDEX_LIST:
		read_index_list_complete(sk, ev->data, len);
		break;
	case MGMT_OP_READ_INFO:
		read_info_complete(sk, index, ev->data, len);
		break;
	case MGMT_OP_SET_POWERED:
		mgmt_new_settings(sk, index, ev->data, len);
		break;
	case MGMT_OP_SET_DISCOVERABLE:
		mgmt_new_settings(sk, index, ev->data, len);
		break;
	case MGMT_OP_SET_CONNECTABLE:
		mgmt_new_settings(sk, index, ev->data, len);
		break;
	case MGMT_OP_SET_PAIRABLE:
		mgmt_new_settings(sk, index, ev->data, len);
		break;
	case MGMT_OP_SET_SSP:
		DBG("set_ssp complete");
		break;
	case MGMT_OP_SET_LE:
		DBG("set_le complete");
		break;
	case MGMT_OP_ADD_UUID:
		mgmt_add_uuid_complete(sk, index, ev->data, len);
		break;
	case MGMT_OP_REMOVE_UUID:
		DBG("remove_uuid complete");
		break;
	case MGMT_OP_SET_DEV_CLASS:
		DBG("set_dev_class complete");
		break;
	case MGMT_OP_LOAD_LINK_KEYS:
		DBG("load_link_keys complete");
		break;
	case MGMT_OP_CANCEL_PAIR_DEVICE:
		DBG("cancel_pair_device complete");
		break;
	case MGMT_OP_UNPAIR_DEVICE:
		DBG("unpair_device complete");
		break;
	case MGMT_OP_DISCONNECT:
		DBG("disconnect complete");
		disconnect_complete(sk, index, ev->status, ev->data, len);
		break;
	case MGMT_OP_GET_CONNECTIONS:
		get_connections_complete(sk, index, ev->data, len);
		break;
	case MGMT_OP_PIN_CODE_REPLY:
		DBG("pin_code_reply complete");
		break;
	case MGMT_OP_PIN_CODE_NEG_REPLY:
		DBG("pin_code_neg_reply complete");
		break;
	case MGMT_OP_SET_IO_CAPABILITY:
		DBG("set_io_capability complete");
		break;
	case MGMT_OP_PAIR_DEVICE:
		pair_device_complete(sk, index, ev->status, ev->data, len);
		break;
	case MGMT_OP_USER_CONFIRM_REPLY:
		DBG("user_confirm_reply complete");
		break;
	case MGMT_OP_USER_CONFIRM_NEG_REPLY:
		DBG("user_confirm_net_reply complete");
		break;
	case MGMT_OP_SET_LOCAL_NAME:
		set_local_name_complete(sk, index, ev->data, len);
		break;
	case MGMT_OP_READ_LOCAL_OOB_DATA:
		read_local_oob_data_complete(sk, index, ev->data, len);
		break;
	case MGMT_OP_ADD_REMOTE_OOB_DATA:
		DBG("add_remote_oob_data complete");
		break;
	case MGMT_OP_REMOVE_REMOTE_OOB_DATA:
		DBG("remove_remote_oob_data complete");
		break;
	case MGMT_OP_BLOCK_DEVICE:
		DBG("block_device complete");
		break;
	case MGMT_OP_UNBLOCK_DEVICE:
		DBG("unblock_device complete");
		break;
	case MGMT_OP_SET_FAST_CONNECTABLE:
		DBG("set_fast_connectable complete");
		break;
	case MGMT_OP_START_DISCOVERY:
		start_discovery_complete(sk, index, ev->status, ev->data, len);
		break;
	case MGMT_OP_STOP_DISCOVERY:
		DBG("stop_discovery complete");
		break;
	case MGMT_OP_SET_DEVICE_ID:
		DBG("set_did complete");
		break;
	default:
		error("Unknown command complete for opcode %u", opcode);
		break;
	}
}

static void mgmt_add_uuid_busy(int sk, uint16_t index)
{
	struct controller_info *info;

	DBG("index %d", index);

	info = &controllers[index];
	info->pending_cod_change = TRUE;
}

static void mgmt_cmd_status(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_cmd_status *ev = buf;
	uint16_t opcode;

	if (len < sizeof(*ev)) {
		error("Too small management command status event packet");
		return;
	}

	opcode = btohs(bt_get_unaligned(&ev->opcode));

	if (!ev->status) {
		DBG("%s (0x%04x) cmd_status %u", mgmt_opstr(opcode), opcode,
								ev->status);
		return;
	}

	switch (opcode) {
	case MGMT_OP_READ_LOCAL_OOB_DATA:
		read_local_oob_data_failed(sk, index);
		break;
	case MGMT_OP_ADD_UUID:
		if (ev->status == MGMT_STATUS_BUSY) {
			mgmt_add_uuid_busy(sk, index);
			return;
		}
		break;
	}

	error("hci%u: %s (0x%04x) failed: %s (0x%02x)", index,
			mgmt_opstr(opcode), opcode, mgmt_errstr(ev->status),
			ev->status);
}

static void mgmt_controller_error(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_controller_error *ev = buf;

	if (len < sizeof(*ev)) {
		error("Too small management controller error event packet");
		return;
	}

	DBG("index %u error_code %u", index, ev->error_code);
}

static void mgmt_auth_failed(int sk, uint16_t index, void *buf, size_t len)
{
	struct controller_info *info;
	struct mgmt_ev_auth_failed *ev = buf;

	if (len < sizeof(*ev)) {
		error("Too small mgmt_auth_failed event packet");
		return;
	}

	DBG("hci%u auth failed status %u", index, ev->status);

	if (index > max_index) {
		error("Unexpected index %u in auth_failed event", index);
		return;
	}

	info = &controllers[index];

	bonding_complete(info, &ev->addr.bdaddr, ev->status);
}

static void mgmt_local_name_changed(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_cp_set_local_name *ev = buf;
	struct controller_info *info;
	struct btd_adapter *adapter;

	if (len < sizeof(*ev)) {
		error("Too small mgmt_local_name_changed event packet");
		return;
	}

	DBG("hci%u local name changed: %s", index, (char *) ev->name);

	if (index > max_index) {
		error("Unexpected index %u in name_changed event", index);
		return;
	}

	info = &controllers[index];

	adapter = manager_find_adapter(&info->bdaddr);
	if (adapter)
		adapter_name_changed(adapter, (char *) ev->name);
}

static void mgmt_device_found(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_device_found *ev = buf;
	struct controller_info *info;
	char addr[18];
	uint32_t flags;
	uint16_t eir_len;
	uint8_t *eir;
	gboolean confirm_name;

	if (len < sizeof(*ev)) {
		error("mgmt_device_found too short (%zu bytes)", len);
		return;
	}

	eir_len = bt_get_le16(&ev->eir_len);
	if (len != sizeof(*ev) + eir_len) {
		error("mgmt_device_found event size mismatch (%zu != %zu)",
						len, sizeof(*ev) + eir_len);
		return;
	}

	if (index > max_index) {
		error("Unexpected index %u in device_found event", index);
		return;
	}

	info = &controllers[index];

	if (eir_len == 0)
		eir = NULL;
	else
		eir = ev->eir;

	flags = btohl(ev->flags);

	ba2str(&ev->addr.bdaddr, addr);
	DBG("hci%u addr %s, rssi %d flags 0x%04x eir_len %u",
			index, addr, ev->rssi, flags, eir_len);

	if (flags & MGMT_DEV_FOUND_LEGACY_PAIRING)
		btd_event_set_legacy_pairing(&info->bdaddr, &ev->addr.bdaddr,
									TRUE);
	else
		btd_event_set_legacy_pairing(&info->bdaddr, &ev->addr.bdaddr,
									FALSE);

	confirm_name = (flags & MGMT_DEV_FOUND_CONFIRM_NAME);

	btd_event_device_found(&info->bdaddr, &ev->addr.bdaddr,
						ev->addr.type,
						ev->rssi, confirm_name,
						eir, eir_len);
}

static void mgmt_discovering(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_discovering *ev = buf;
	struct controller_info *info;
	struct btd_adapter *adapter;

	if (len < sizeof(*ev)) {
		error("Too small discovering event");
		return;
	}

	DBG("Controller %u type %u discovering %u", index,
					ev->type, ev->discovering);

	if (index > max_index) {
		error("Unexpected index %u in discovering event", index);
		return;
	}

	info = &controllers[index];

	adapter = manager_find_adapter(&info->bdaddr);
	if (!adapter)
		return;

	adapter_set_discovering(adapter, ev->discovering);
}

static void mgmt_device_blocked(int sk, uint16_t index, void *buf, size_t len)
{
	struct controller_info *info;
	struct mgmt_ev_device_blocked *ev = buf;
	char addr[18];

	if (len < sizeof(*ev)) {
		error("Too small mgmt_device_blocked event packet");
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);
	DBG("Device blocked, index %u, addr %s", index, addr);

	if (index > max_index) {
		error("Unexpected index %u in device_blocked event", index);
		return;
	}

	info = &controllers[index];

	btd_event_device_blocked(&info->bdaddr, &ev->addr.bdaddr);
}

static void mgmt_device_unblocked(int sk, uint16_t index, void *buf, size_t len)
{
	struct controller_info *info;
	struct mgmt_ev_device_unblocked *ev = buf;
	char addr[18];

	if (len < sizeof(*ev)) {
		error("Too small mgmt_device_unblocked event packet");
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);
	DBG("Device unblocked, index %u, addr %s", index, addr);

	if (index > max_index) {
		error("Unexpected index %u in device_unblocked event", index);
		return;
	}

	info = &controllers[index];

	btd_event_device_unblocked(&info->bdaddr, &ev->addr.bdaddr);
}

static void mgmt_device_unpaired(int sk, uint16_t index, void *buf, size_t len)
{
	struct controller_info *info;
	struct mgmt_ev_device_unpaired *ev = buf;
	char addr[18];

	if (len < sizeof(*ev)) {
		error("Too small mgmt_device_unpaired event packet");
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);
	DBG("Device upaired, index %u, addr %s", index, addr);

	if (index > max_index) {
		error("Unexpected index %u in device_unpaired event", index);
		return;
	}

	info = &controllers[index];

	btd_event_device_unpaired(&info->bdaddr, &ev->addr.bdaddr);
}

static void mgmt_new_ltk(int sk, uint16_t index, void *buf, size_t len)
{
	struct mgmt_ev_new_long_term_key *ev = buf;
	struct controller_info *info;

	if (len != sizeof(*ev)) {
		error("mgmt_new_ltk event size mismatch (%zu != %zu)",
							len, sizeof(*ev));
		return;
	}

	DBG("Controller %u new LTK authenticated %u enc_size %u", index,
				ev->key.authenticated, ev->key.enc_size);

	if (index > max_index) {
		error("Unexpected index %u in new_key event", index);
		return;
	}

	info = &controllers[index];

	if (ev->store_hint) {
		btd_event_ltk_notify(&info->bdaddr, &ev->key.addr.bdaddr,
				ev->key.addr.type, ev->key.val, ev->key.master,
				ev->key.authenticated, ev->key.enc_size,
				ev->key.ediv, ev->key.rand);
	}

	if (ev->key.master)
		bonding_complete(info, &ev->key.addr.bdaddr, 0);
}

static void mgmt_cod_changed(int sk, uint16_t index)
{
	struct controller_info *info;

	DBG("index %d", index);

	if (index > max_index) {
		error("Unexpected index %u in mgmt_cod_changed event", index);
		return;
	}

	info = &controllers[index];

	if (info->pending_cod_change) {
		info->pending_cod_change = FALSE;
		handle_pending_uuids(index);
	}
}

static gboolean mgmt_event(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	char buf[MGMT_BUF_SIZE];
	struct mgmt_hdr *hdr = (void *) buf;
	int sk;
	ssize_t ret;
	uint16_t len, opcode, index;

	DBG("cond %d", cond);

	if (cond & G_IO_NVAL)
		return FALSE;

	sk = g_io_channel_unix_get_fd(io);

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		error("Error on management socket");
		return FALSE;
	}

	ret = read(sk, buf, sizeof(buf));
	if (ret < 0) {
		error("Unable to read from management socket: %s (%d)",
						strerror(errno), errno);
		return TRUE;
	}

	DBG("Received %zd bytes from management socket", ret);

	if (ret < MGMT_HDR_SIZE) {
		error("Too small Management packet");
		return TRUE;
	}

	opcode = btohs(bt_get_unaligned(&hdr->opcode));
	len = btohs(bt_get_unaligned(&hdr->len));
	index = btohs(bt_get_unaligned(&hdr->index));

	if (ret != MGMT_HDR_SIZE + len) {
		error("Packet length mismatch. ret %zd len %u", ret, len);
		return TRUE;
	}

	switch (opcode) {
	case MGMT_EV_CMD_COMPLETE:
		mgmt_cmd_complete(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_CMD_STATUS:
		mgmt_cmd_status(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_CONTROLLER_ERROR:
		mgmt_controller_error(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_INDEX_ADDED:
		mgmt_index_added(sk, index);
		break;
	case MGMT_EV_INDEX_REMOVED:
		mgmt_index_removed(sk, index);
		break;
	case MGMT_EV_NEW_SETTINGS:
		mgmt_new_settings(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_CLASS_OF_DEV_CHANGED:
		mgmt_cod_changed(sk, index);
		break;
	case MGMT_EV_NEW_LINK_KEY:
		mgmt_new_link_key(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_DEVICE_CONNECTED:
		mgmt_device_connected(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_DEVICE_DISCONNECTED:
		mgmt_device_disconnected(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_CONNECT_FAILED:
		mgmt_connect_failed(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_PIN_CODE_REQUEST:
		mgmt_pin_code_request(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_USER_CONFIRM_REQUEST:
		mgmt_user_confirm_request(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_AUTH_FAILED:
		mgmt_auth_failed(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_LOCAL_NAME_CHANGED:
		mgmt_local_name_changed(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_DEVICE_FOUND:
		mgmt_device_found(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_DISCOVERING:
		mgmt_discovering(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_DEVICE_BLOCKED:
		mgmt_device_blocked(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_DEVICE_UNBLOCKED:
		mgmt_device_unblocked(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_DEVICE_UNPAIRED:
		mgmt_device_unpaired(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_USER_PASSKEY_REQUEST:
		mgmt_passkey_request(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	case MGMT_EV_NEW_LONG_TERM_KEY:
		mgmt_new_ltk(sk, index, buf + MGMT_HDR_SIZE, len);
		break;
	default:
		error("Unknown Management opcode %u (index %u)", opcode, index);
		break;
	}

	return TRUE;
}

int mgmt_setup(void)
{
	struct mgmt_hdr hdr;
	struct sockaddr_hci addr;
	GIOChannel *io;
	GIOCondition condition;
	int dd, err;

	dd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (dd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	addr.hci_channel = HCI_CHANNEL_CONTROL;

	if (bind(dd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		goto fail;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = htobs(MGMT_OP_READ_VERSION);
	hdr.index = htobs(MGMT_INDEX_NONE);
	if (write(dd, &hdr, sizeof(hdr)) < 0) {
		err = -errno;
		goto fail;
	}

	io = g_io_channel_unix_new(dd);
	condition = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	mgmt_watch = g_io_add_watch(io, condition, mgmt_event, NULL);
	g_io_channel_unref(io);

	mgmt_sock = dd;

	info("Bluetooth Management interface initialized");

	return 0;

fail:
	close(dd);
	return err;
}

void mgmt_cleanup(void)
{
	g_free(controllers);
	controllers = NULL;
	max_index = -1;

	if (mgmt_sock >= 0) {
		close(mgmt_sock);
		mgmt_sock = -1;
	}

	if (mgmt_watch > 0) {
		g_source_remove(mgmt_watch);
		mgmt_watch = 0;
	}
}

int mgmt_start_discovery(int index)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_start_discovery)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_start_discovery *cp = (void *) &buf[sizeof(*hdr)];
	struct controller_info *info = &controllers[index];

	DBG("index %d", index);

	info->discov_type = 0;

	if (mgmt_bredr(info->current_settings))
		hci_set_bit(BDADDR_BREDR, &info->discov_type);

	if (mgmt_low_energy(info->current_settings)) {
		hci_set_bit(BDADDR_LE_PUBLIC, &info->discov_type);
		hci_set_bit(BDADDR_LE_RANDOM, &info->discov_type);
	}

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_START_DISCOVERY);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	cp->type = info->discov_type;

	if (write(mgmt_sock, buf, sizeof(buf)) < 0) {
		int err = -errno;
		error("failed to write to MGMT socket: %s", strerror(err));
		return err;
	}

	return 0;
}

int mgmt_stop_discovery(int index)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_start_discovery)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_start_discovery *cp = (void *) &buf[sizeof(*hdr)];
	struct controller_info *info = &controllers[index];

	DBG("index %d", index);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_STOP_DISCOVERY);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	cp->type = info->discov_type;

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_set_fast_connectable(int index, gboolean enable)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_mode)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_mode *cp = (void *) &buf[sizeof(*hdr)];

	DBG("index %d enable %d", index, enable);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_SET_FAST_CONNECTABLE);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	cp->val = enable;

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_read_clock(int index, bdaddr_t *bdaddr, int which, int timeout,
					uint32_t *clock, uint16_t *accuracy)
{
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("index %d addr %s which %d timeout %d", index, addr, which,
								timeout);

	return -ENOSYS;
}

int mgmt_read_bdaddr(int index, bdaddr_t *bdaddr)
{
	char addr[18];
	struct controller_info *info = &controllers[index];

	ba2str(&info->bdaddr, addr);
	DBG("index %d addr %s", index, addr);

	if (!info->valid)
		return -ENODEV;

	bacpy(bdaddr, &info->bdaddr);

	return 0;
}

int mgmt_block_device(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_block_device)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_block_device *cp;
	size_t buf_len;
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("index %d addr %s", index, addr);

	memset(buf, 0, sizeof(buf));

	hdr->opcode = htobs(MGMT_OP_BLOCK_DEVICE);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	cp = (void *) &buf[sizeof(*hdr)];
	bacpy(&cp->addr.bdaddr, bdaddr);
	cp->addr.type = bdaddr_type;

	buf_len = sizeof(*hdr) + sizeof(*cp);

	if (write(mgmt_sock, buf, buf_len) < 0)
		return -errno;

	return 0;
}

int mgmt_unblock_device(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_unblock_device)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_unblock_device *cp;
	size_t buf_len;
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("index %d addr %s", index, addr);

	memset(buf, 0, sizeof(buf));

	hdr->opcode = htobs(MGMT_OP_UNBLOCK_DEVICE);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	cp = (void *) &buf[sizeof(*hdr)];
	bacpy(&cp->addr.bdaddr, bdaddr);
	cp->addr.type = bdaddr_type;

	buf_len = sizeof(*hdr) + sizeof(*cp);

	if (write(mgmt_sock, buf, buf_len) < 0)
		return -errno;

	return 0;
}

int mgmt_get_conn_list(int index, GSList **conns)
{
	struct controller_info *info = &controllers[index];

	DBG("index %d", index);

	*conns = info->connections;
	info->connections = NULL;

	return 0;
}

int mgmt_disconnect(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_disconnect)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_disconnect *cp = (void *) &buf[sizeof(*hdr)];
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("index %d %s", index, addr);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_DISCONNECT);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	bacpy(&cp->addr.bdaddr, bdaddr);
	cp->addr.type = bdaddr_type;

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		error("write: %s (%d)", strerror(errno), errno);

	return 0;
}

int mgmt_unpair_device(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_unpair_device)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_unpair_device *cp = (void *) &buf[sizeof(*hdr)];
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("index %d addr %s", index, addr);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_UNPAIR_DEVICE);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	bacpy(&cp->addr.bdaddr, bdaddr);
	cp->addr.type = bdaddr_type;
	cp->disconnect = 1;

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_set_did(int index, uint16_t vendor, uint16_t product,
					uint16_t version, uint16_t source)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_set_device_id)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_set_device_id *cp = (void *) &buf[sizeof(*hdr)];

	DBG("index %d source %x vendor %x product %x version %x",
				index, source, vendor, product, version);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_SET_DEVICE_ID);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	cp->source = htobs(source);
	cp->vendor = htobs(vendor);
	cp->product = htobs(product);
	cp->version = htobs(version);

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_load_link_keys(int index, GSList *keys, gboolean debug_keys)
{
	char *buf;
	struct mgmt_hdr *hdr;
	struct mgmt_cp_load_link_keys *cp;
	struct mgmt_link_key_info *key;
	size_t key_count, cp_size;
	GSList *l;
	int err;

	key_count = g_slist_length(keys);

	DBG("index %d keys %zu debug_keys %d", index, key_count, debug_keys);

	cp_size = sizeof(*cp) + (key_count * sizeof(*key));

	buf = g_try_malloc0(sizeof(*hdr) + cp_size);
	if (buf == NULL)
		return -ENOMEM;

	hdr = (void *) buf;
	hdr->opcode = htobs(MGMT_OP_LOAD_LINK_KEYS);
	hdr->len = htobs(cp_size);
	hdr->index = htobs(index);

	cp = (void *) (buf + sizeof(*hdr));
	cp->debug_keys = debug_keys;
	cp->key_count = htobs(key_count);

	for (l = keys, key = cp->keys; l != NULL; l = g_slist_next(l), key++) {
		struct link_key_info *info = l->data;

		bacpy(&key->addr.bdaddr, &info->bdaddr);
		key->addr.type = BDADDR_BREDR;
		key->type = info->type;
		memcpy(key->val, info->key, 16);
		key->pin_len = info->pin_len;
	}

	if (write(mgmt_sock, buf, sizeof(*hdr) + cp_size) < 0)
		err = -errno;
	else
		err = 0;

	g_free(buf);

	return err;
}

int mgmt_set_io_capability(int index, uint8_t io_capability)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_set_io_capability)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_set_io_capability *cp = (void *) &buf[sizeof(*hdr)];

	DBG("hci%d io_capability 0x%02x", index, io_capability);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_SET_IO_CAPABILITY);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	cp->io_capability = io_capability;

	if (write(mgmt_sock, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_create_bonding(int index, bdaddr_t *bdaddr, uint8_t addr_type, uint8_t io_cap)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_pair_device)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_pair_device *cp = (void *) &buf[sizeof(*hdr)];
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d bdaddr %s io_cap 0x%02x", index, addr, io_cap);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_PAIR_DEVICE);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	bacpy(&cp->addr.bdaddr, bdaddr);
	cp->addr.type = addr_type;
	cp->io_cap = io_cap;

	if (write(mgmt_sock, &buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_cancel_bonding(int index, bdaddr_t *bdaddr)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_addr_info)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_addr_info *cp = (void *) &buf[sizeof(*hdr)];
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d bdaddr %s", index, addr);

	memset(buf, 0, sizeof(buf));
	hdr->opcode = htobs(MGMT_OP_CANCEL_PAIR_DEVICE);
	hdr->len = htobs(sizeof(*cp));
	hdr->index = htobs(index);

	bacpy(&cp->bdaddr, bdaddr);

	if (write(mgmt_sock, &buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_read_local_oob_data(int index)
{
	struct mgmt_hdr hdr;

	DBG("hci%d", index);

	hdr.opcode = htobs(MGMT_OP_READ_LOCAL_OOB_DATA);
	hdr.len = 0;
	hdr.index = htobs(index);

	if (write(mgmt_sock, &hdr, sizeof(hdr)) < 0)
		return -errno;

	return 0;
}

int mgmt_add_remote_oob_data(int index, bdaddr_t *bdaddr,
					uint8_t *hash, uint8_t *randomizer)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_add_remote_oob_data)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_add_remote_oob_data *cp = (void *) &buf[sizeof(*hdr)];
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d bdaddr %s", index, addr);

	memset(buf, 0, sizeof(buf));

	hdr->opcode = htobs(MGMT_OP_ADD_REMOTE_OOB_DATA);
	hdr->index = htobs(index);
	hdr->len = htobs(sizeof(*cp));

	bacpy(&cp->addr.bdaddr, bdaddr);
	memcpy(cp->hash, hash, 16);
	memcpy(cp->randomizer, randomizer, 16);

	if (write(mgmt_sock, &buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_remove_remote_oob_data(int index, bdaddr_t *bdaddr)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_remove_remote_oob_data)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_remove_remote_oob_data *cp = (void *) &buf[sizeof(*hdr)];
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d bdaddr %s", index, addr);

	memset(buf, 0, sizeof(buf));

	hdr->opcode = htobs(MGMT_OP_REMOVE_REMOTE_OOB_DATA);
	hdr->index = htobs(index);
	hdr->len = htobs(sizeof(*cp));

	bacpy(&cp->addr.bdaddr, bdaddr);

	if (write(mgmt_sock, &buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_confirm_name(int index, bdaddr_t *bdaddr, uint8_t bdaddr_type,
							gboolean name_known)
{
	char buf[MGMT_HDR_SIZE + sizeof(struct mgmt_cp_confirm_name)];
	struct mgmt_hdr *hdr = (void *) buf;
	struct mgmt_cp_confirm_name *cp = (void *) &buf[sizeof(*hdr)];
	char addr[18];

	ba2str(bdaddr, addr);
	DBG("hci%d bdaddr %s name_known %u", index, addr, name_known);

	memset(buf, 0, sizeof(buf));

	hdr->opcode = htobs(MGMT_OP_CONFIRM_NAME);
	hdr->index = htobs(index);
	hdr->len = htobs(sizeof(*cp));

	bacpy(&cp->addr.bdaddr, bdaddr);
	cp->addr.type = bdaddr_type;
	cp->name_known = name_known;

	if (write(mgmt_sock, &buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int mgmt_load_ltks(int index, GSList *keys)
{
	char *buf;
	struct mgmt_hdr *hdr;
	struct mgmt_cp_load_long_term_keys *cp;
	struct mgmt_ltk_info *key;
	size_t key_count, cp_size;
	GSList *l;
	int err;

	key_count = g_slist_length(keys);

	DBG("index %d keys %zu", index, key_count);

	cp_size = sizeof(*cp) + (key_count * sizeof(*key));

	buf = g_try_malloc0(sizeof(*hdr) + cp_size);
	if (buf == NULL)
		return -ENOMEM;

	hdr = (void *) buf;
	hdr->opcode = htobs(MGMT_OP_LOAD_LONG_TERM_KEYS);
	hdr->len = htobs(cp_size);
	hdr->index = htobs(index);

	cp = (void *) (buf + sizeof(*hdr));
	cp->key_count = htobs(key_count);

	for (l = keys, key = cp->keys; l != NULL; l = g_slist_next(l), key++) {
		struct smp_ltk_info *info = l->data;

		bacpy(&key->addr.bdaddr, &info->bdaddr);
		key->addr.type = info->bdaddr_type;
		memcpy(key->val, info->val, sizeof(info->val));
		memcpy(key->rand, info->rand, sizeof(info->rand));
		memcpy(&key->ediv, &info->ediv, sizeof(key->ediv));
		key->authenticated = info->authenticated;
		key->master = info->master;
		key->enc_size = info->enc_size;
	}

	if (write(mgmt_sock, buf, sizeof(*hdr) + cp_size) < 0)
		err = -errno;
	else
		err = 0;

	g_free(buf);

	return err;
}
