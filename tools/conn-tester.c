/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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
#include <stdlib.h>
#include <unistd.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "monitor/bt.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/hciemu.h"

enum {
	CONNECTING,
	CLOSING,
};

struct test_data {
	const void *test_data;
	uint32_t initial_settings;
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	int unmet_conditions;
	unsigned int timeout_id;
	int sk;
	bdaddr_t bdaddr;
	struct hciemu *hciemu_snd;
	enum hciemu_type hciemu_type_snd;
int state;
};

#define CID 4
#define SVR_BDADDR "aa:bb:cc:dd:ee:ff"

#define test_le(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = malloc(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_snd = 0; \
		user->hciemu_type = HCIEMU_TYPE_LE; \
		user->test_data = data; \
		user->initial_settings = 0x00000000; \
		user->unmet_conditions = 0; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 30, user, free); \
	} while (0)

static gboolean received_hci_event(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	char buf[1 + HCI_EVENT_HDR_SIZE + EVT_CMD_COMPLETE + 1], *ptr;
	evt_cmd_complete *cc;
	hci_event_hdr *hdr;
	uint8_t status;
	gsize len;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL))
		goto failed;

	if (g_io_channel_read_chars(io, (gchar *) buf, sizeof(buf), &len,
						NULL) != G_IO_STATUS_NORMAL)
		goto failed;

	if (len != sizeof(buf))
		goto failed;

	ptr = buf + 1;
	hdr = (void *) ptr;
	if (hdr->evt != EVT_CMD_COMPLETE || hdr->plen != 1)
		goto failed;

	ptr += HCI_EVENT_HDR_SIZE;
	cc = (void *) ptr;
	if (btohs(cc->opcode) != cmd_opcode_pack(OGF_LE_CTL,
						OCF_LE_SET_ADVERTISE_ENABLE))
		goto failed;

	ptr += EVT_CMD_COMPLETE_SIZE;
	status = *ptr;
	if (status != 0)
		goto failed;

	tester_pre_setup_complete();

	return FALSE;

failed:
	tester_pre_setup_failed();
	return FALSE;
}

#if 0
static int hci_send_req_v2(int dd, struct hci_request *r, int to)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	uint16_t opcode = htobs(cmd_opcode_pack(r->ogf, r->ocf));
	struct hci_filter nf, of;
	socklen_t olen;
	hci_event_hdr *hdr;
	int err, try;

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0)
		return -1;

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT,  &nf);
	hci_filter_set_event(EVT_CMD_COMPLETE, &nf);
	hci_filter_set_event(r->event, &nf);
	hci_filter_set_opcode(opcode, &nf);
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
		return -1;

	mgmt->read_watch = g_io_add_watch_full(mgmt->io, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				received_data, mgmt, NULL);

	if (hci_send_cmd(dd, r->ogf, r->ocf, r->clen, r->cparam) < 0)
		goto failed;

failed:
	err = errno;
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	errno = err;
	return -1;

done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	return 0;

}
#endif

static int enable_le_advertising(int hdev)
{
	le_set_advertise_enable_cp adv_cp;
	struct hci_filter nf, of;
	GIOChannel *channel;
	uint16_t opcode;
	socklen_t olen;
	int dd, err;

	dd = hci_open_dev(hdev);
	if (dd < 0) {
		tester_warn("Could not open device");
		return -1;
	}

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0)
		return -1;

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT,  &nf);
	hci_filter_set_event(EVT_CMD_COMPLETE, &nf);
	opcode = htobs(cmd_opcode_pack(OGF_LE_CTL,
						OCF_LE_SET_ADVERTISE_ENABLE));
	hci_filter_set_opcode(opcode, &nf);
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
		return -1;

	channel = g_io_channel_unix_new(dd);
	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	g_io_add_watch_full(channel, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				received_hci_event, NULL, NULL);

	g_io_channel_unref(channel);

	adv_cp.enable = 0x01;
	if (hci_send_cmd(dd, OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE,
						sizeof(adv_cp), &adv_cp) < 0)
		goto failed;

	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

	return 0;

failed:
	err = errno;
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	errno = err;

	return -1;
}

static void powered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller powered on");

	/* FIXME: do not assume index 0 to be the first virtual controller,
	 * instead keep track of controllers added during test setup */
	if (data->mgmt_index == 0)
		tester_pre_setup_complete();
	else if (enable_le_advertising(data->mgmt_index) < 0)
		tester_pre_setup_failed();
}

static void set_le_powered()
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with LE enabled)");

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
			sizeof(param), param, powered_callback, NULL, NULL);
}

static void index_added_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Added callback");
	tester_print("  Index: 0x%04x", index);

	data->mgmt_index = index;

	set_le_powered();
}

static void index_removed_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Removed callback");
	tester_print("  Index: 0x%04x", index);

	if (index != data->mgmt_index)
		return;

	mgmt_unregister_index(data->mgmt, data->mgmt_index);

	mgmt_unref(data->mgmt);
	data->mgmt = NULL;

	tester_post_teardown_complete();
}

static void read_index_list_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Read Index List callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	mgmt_register(data->mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					index_added_callback, NULL, NULL);

	mgmt_register(data->mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					index_removed_callback, NULL, NULL);

	data->hciemu = hciemu_new(data->hciemu_type);
	if (!data->hciemu) {
		tester_warn("Failed to setup HCI emulation");
		tester_pre_setup_failed();
	}
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->mgmt = mgmt_new_default();
	if (!data->mgmt) {
		tester_warn("Failed to setup management interface");
		tester_pre_setup_failed();
		return;
	}

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
					read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;

	if (data->hciemu_snd) {
		hciemu_unref(data->hciemu_snd);
		data->hciemu_snd = NULL;
	}

}

static void test_add_condition(struct test_data *data)
{
	data->unmet_conditions++;

	tester_print("Test condition added, total %d", data->unmet_conditions);
}

static void test_condition_complete(struct test_data *data)
{
	data->unmet_conditions--;

	tester_print("Test condition complete, %d left",
						data->unmet_conditions);

	if (data->unmet_conditions > 0)
		return;

	tester_test_passed();
}

static void setup_connection(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct sockaddr_l2 addr;

	bacpy(&data->bdaddr, BDADDR_ANY);

	/* Create socket */
	data->sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK,
								BTPROTO_L2CAP);
	if (data->sk < 0) {
		tester_print("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_setup_failed();
		return;
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &data->bdaddr);
	if (bind(data->sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		tester_print("Can't bind socket: %s (%d)", strerror(errno),
									errno);
		close(data->sk);
		tester_setup_failed();
	}

	tester_setup_complete();
	return;
}

static gboolean test_timeout(gpointer user_data)
{
	struct test_data *data = user_data;

	data->timeout_id = 0;

	data->state = CLOSING;
	close(data->sk);

	return FALSE;
}

static void close_socket()
{
	struct test_data *data = tester_get_data();

	data->timeout_id = g_timeout_add_seconds(5, test_timeout, data);

	test_add_condition(data);
}

static bool command_hci_callback(uint16_t opcode, const void *param,
					uint8_t length, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("HCI Command 0x%04x length %u", opcode, length);

	if (opcode != BT_HCI_CMD_LE_SET_SCAN_ENABLE)
		return true;

	if (length != sizeof(struct bt_hci_cmd_le_set_scan_enable)) {
		tester_warn("Invalid parameter size for HCI command");
		goto error;
	}

	if (data->state == CONNECTING) {
		static const char expected_hci[] = { 0x01, 0x00 };

		if (memcmp(param, expected_hci, length) != 0) {
			tester_warn("Enable: unexpected HCI cmd parameter");
			goto error;
		}
		close_socket();

	} else {
		static const char expected_hci[] = { 0x00, 0x00 };

		if (memcmp(param, expected_hci, length) != 0) {
			tester_warn("Disable: unexpected HCI cmd parameter");
			goto error;
		}
	}

	test_condition_complete(data);

	return true;

error:
	tester_test_failed();
	return false;
}

static void test_command_connect(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct sockaddr_l2 addr;
	int err;

	/* Connect to remote device */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(SVR_BDADDR, &addr.l2_bdaddr);
	addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;
	addr.l2_cid = htobs(CID);

	tester_print("Registering HCI command callback");
	hciemu_add_master_post_command_hook(data->hciemu, command_hci_callback,
									NULL);
	test_add_condition(data);

	data->state = CONNECTING;

	err = connect(data->sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0 && errno != EINPROGRESS) {
		tester_print("Can't connect: %s (%d)", strerror(errno), errno);
		close(data->sk);
		tester_test_failed();
	}
}



static void setup_second_controller(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->hciemu_type_snd = HCIEMU_TYPE_LE;
	data->hciemu_snd = hciemu_new(data->hciemu_type_snd);
	if (!data->hciemu_snd) {
		tester_warn("Failed to setup HCI emulation");
		tester_setup_failed();
	}

//	tester_setup_complete();
}

static void test_snd_connect(const void *test_data)
{
//	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_le("Connection test 3", NULL, setup_connection,
							test_command_connect);
	test_le("Connection test 1", NULL, setup_second_controller,
							test_snd_connect);

	return tester_run();
}
