/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#include <stdlib.h>

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

static gboolean option_wait_powered = FALSE;

struct test_data {
	const void *test_data;
	uint8_t expected_version;
	uint16_t expected_manufacturer;
	uint32_t expected_supported_settings;
	uint32_t initial_settings;
	struct mgmt *mgmt;
	struct mgmt *mgmt_alt;
	unsigned int mgmt_settings_id;
	unsigned int mgmt_alt_settings_id;
	unsigned int mgmt_alt_ev_id;
	uint8_t mgmt_version;
	uint16_t mgmt_revision;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	struct hciemu *hciemu_second;
	uint16_t mgmt_index_second;
	int unmet_conditions;
};

static void mgmt_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	tester_print("%s%s", prefix, str);
}

static void read_version_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_rp_read_version *rp = param;

	tester_print("Read Version callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	data->mgmt_version = rp->version;
	data->mgmt_revision = btohs(rp->revision);

	tester_print("  Version %u.%u",
				data->mgmt_version, data->mgmt_revision);
}

static void read_commands_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	tester_print("Read Commands callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}
}

static void read_info_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_rp_read_info *rp = param;
	char addr[18];
	uint16_t manufacturer;
	uint32_t supported_settings, current_settings;

	tester_print("Read Info callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	ba2str(&rp->bdaddr, addr);
	manufacturer = btohs(rp->manufacturer);
	supported_settings = btohl(rp->supported_settings);
	current_settings = btohl(rp->current_settings);

	tester_print("  Address: %s", addr);
	tester_print("  Version: 0x%02x", rp->version);
	tester_print("  Manufacturer: 0x%04x", manufacturer);
	tester_print("  Supported settings: 0x%08x", supported_settings);
	tester_print("  Current settings: 0x%08x", current_settings);
	tester_print("  Class: 0x%02x%02x%02x",
			rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);
	tester_print("  Name: %s", rp->name);
	tester_print("  Short name: %s", rp->short_name);

	if (strcmp(hciemu_get_address(data->hciemu), addr)) {
		tester_pre_setup_failed();
		return;
	}

	if (rp->version != data->expected_version) {
		tester_pre_setup_failed();
		return;
	}

	if (manufacturer != data->expected_manufacturer) {
		tester_pre_setup_failed();
		return;
	}

	if (supported_settings != data->expected_supported_settings) {
		tester_pre_setup_failed();
		return;
	}

	if (current_settings != data->initial_settings) {
		tester_pre_setup_failed();
		return;
	}

	if (rp->dev_class[0] != 0x00 || rp->dev_class[1] != 0x00 ||
						rp->dev_class[2] != 0x00) {
		tester_pre_setup_failed();
		return;
	}

	tester_pre_setup_complete();
}

static gboolean received_adv_hci_event(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	char buf[1 + HCI_EVENT_HDR_SIZE + EVT_CMD_COMPLETE_SIZE + 1], *ptr;
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
	if (hdr->evt != EVT_CMD_COMPLETE ||
					hdr->plen != EVT_CMD_COMPLETE_SIZE + 1)
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

	tester_setup_complete();

	return FALSE;

failed:
	tester_setup_failed();

	return FALSE;
}

static int enable_le_advertising(int hdev)
{
	le_set_advertise_enable_cp adv_cp;
	struct hci_filter nf;
	GIOChannel *channel;
	uint16_t opcode;
	int dd;

	dd = hci_open_dev(hdev);
	if (dd < 0) {
		tester_warn("Could not open device");
		return -1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_CMD_COMPLETE, &nf);
	opcode = htobs(cmd_opcode_pack(OGF_LE_CTL,
						OCF_LE_SET_ADVERTISE_ENABLE));
	hci_filter_set_opcode(opcode, &nf);
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		tester_warn("Error setting the socket filter");
		return -1;
	}

	channel = g_io_channel_unix_new(dd);
	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	g_io_add_watch_full(channel, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				received_adv_hci_event, NULL, NULL);

	g_io_channel_unref(channel);

	adv_cp.enable = 0x01;
	if (hci_send_cmd(dd, OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE,
						sizeof(adv_cp), &adv_cp) < 0) {
		tester_warn("Error sending LE ADV Enable command");
		return -1;
	}

	return 0;
}

static void setup_adv_powered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller powered on");

	if (data->hciemu_type == HCIEMU_TYPE_BREDR) {
		tester_setup_complete();
		return;
	}

	if (enable_le_advertising(data->mgmt_index_second) < 0)
		tester_setup_failed();
}

static void second_powered_discoverable()
{
	struct test_data *data = tester_get_data();
	unsigned char con_param[] = { 0x01 };
	unsigned char discov_param[] = { 0x01, 0x00, 0x00 };

	tester_print("Enabling connectable, discoverable and powered (second)");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index_second,
					sizeof(con_param), con_param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_DISCOVERABLE, data->mgmt_index_second,
					sizeof(discov_param), discov_param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index_second,
					sizeof(con_param), con_param,
					setup_adv_powered_callback, NULL, NULL);
}

static void index_added_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Added callback");
	tester_print("  Index: 0x%04x", index);

	if (data->hciemu_second) {
		data->mgmt_index_second = index;
		second_powered_discoverable();
		return;
	}

	data->mgmt_index = index;

	mgmt_send(data->mgmt, MGMT_OP_READ_INFO, data->mgmt_index, 0, NULL,
					read_info_callback, NULL, NULL);
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
	mgmt_unregister_index(data->mgmt_alt, data->mgmt_index);

	mgmt_unref(data->mgmt);
	data->mgmt = NULL;

	mgmt_unref(data->mgmt_alt);
	data->mgmt_alt = NULL;

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

	data->mgmt_alt = mgmt_new_default();
	if (!data->mgmt_alt) {
		tester_warn("Failed to setup alternate management interface");
		tester_pre_setup_failed();

		mgmt_unref(data->mgmt);
		data->mgmt = NULL;
		return;
	}

	if (tester_use_debug()) {
		mgmt_set_debug(data->mgmt, mgmt_debug, "mgmt: ", NULL);
		mgmt_set_debug(data->mgmt_alt, mgmt_debug, "mgmt-alt: ", NULL);
	}

	mgmt_send(data->mgmt, MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, 0, NULL,
					read_version_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_COMMANDS, MGMT_INDEX_NONE, 0, NULL,
					read_commands_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
					read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	if (data->hciemu_second) {
		hciemu_unref(data->hciemu_second);
		data->mgmt_index_second = 0xffff;
		data->hciemu_second = NULL;
	}

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
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

#define test_bredrle(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = malloc(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDRLE; \
		user->hciemu_second = NULL; \
		user->mgmt_index_second = 0xffff; \
		user->test_data = data; \
		user->expected_version = 0x06; \
		user->expected_manufacturer = 0x003f; \
		user->expected_supported_settings = 0x000002ff; \
		user->initial_settings = 0x00000080; \
		user->unmet_conditions = 0; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, free); \
	} while (0)

#define test_bredr(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = malloc(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDR; \
		user->hciemu_second = NULL; \
		user->mgmt_index_second = 0xffff; \
		user->test_data = data; \
		user->expected_version = 0x05; \
		user->expected_manufacturer = 0x003f; \
		user->expected_supported_settings = 0x000000ff; \
		user->initial_settings = 0x00000080; \
		user->unmet_conditions = 0; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, free); \
	} while (0)

#define test_le(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = malloc(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_LE; \
		user->hciemu_second = NULL; \
		user->mgmt_index_second = 0xffff; \
		user->test_data = data; \
		user->expected_version = 0x06; \
		user->expected_manufacturer = 0x003f; \
		user->expected_supported_settings = 0x00000211; \
		user->initial_settings = 0x00000200; \
		user->unmet_conditions = 0; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, free); \
	} while (0)

static void controller_setup(const void *test_data)
{
	tester_test_passed();
}

struct generic_data {
	uint16_t setup_expect_hci_command;
	const void *setup_expect_hci_param;
	uint8_t setup_expect_hci_len;
	uint16_t block_hci_command;
	bool send_index_none;
	uint16_t send_opcode;
	const void *send_param;
	uint16_t send_len;
	uint8_t expect_status;
	const void *expect_param;
	uint16_t expect_len;
	uint32_t expect_settings_set;
	uint32_t expect_settings_unset;
	uint16_t expect_alt_ev;
	const void *expect_alt_ev_param;
	uint16_t expect_alt_ev_len;
	uint16_t expect_hci_command;
	const void *expect_hci_param;
	uint8_t expect_hci_len;
};

static const char dummy_data[] = { 0x00 };

static const struct generic_data invalid_command_test = {
	.send_opcode = 0xffff,
	.expect_status = MGMT_STATUS_UNKNOWN_COMMAND,
};

static const struct generic_data read_version_success_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_VERSION,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_len = 3,
};

static const struct generic_data read_version_invalid_param_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_VERSION,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_version_invalid_index_test = {
	.send_opcode = MGMT_OP_READ_VERSION,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const struct generic_data read_commands_invalid_param_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_COMMANDS,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_commands_invalid_index_test = {
	.send_opcode = MGMT_OP_READ_COMMANDS,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const struct generic_data read_index_list_invalid_param_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_INDEX_LIST,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_index_list_invalid_index_test = {
	.send_opcode = MGMT_OP_READ_INDEX_LIST,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const struct generic_data read_info_invalid_param_test = {
	.send_opcode = MGMT_OP_READ_INFO,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_info_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_INFO,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const char set_powered_on_param[] = { 0x01 };
static const char set_powered_invalid_param[] = { 0x02 };
static const char set_powered_garbage_param[] = { 0x01, 0x00 };
static const char set_powered_settings_param[] = { 0x81, 0x00, 0x00, 0x00 };

static const struct generic_data set_powered_on_success_test = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_settings_param,
	.expect_len = sizeof(set_powered_settings_param),
	.expect_settings_set = MGMT_SETTING_POWERED,
};

static const struct generic_data set_powered_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_powered_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_invalid_param,
	.send_len = sizeof(set_powered_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_powered_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_garbage_param,
	.send_len = sizeof(set_powered_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_powered_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const char set_powered_off_param[] = { 0x00 };
static const char set_powered_off_settings_param[] = { 0x80, 0x00, 0x00, 0x00 };
static const char set_powered_off_class_of_dev[] = { 0x00, 0x00, 0x00 };

static const struct generic_data set_powered_off_success_test = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_off_param,
	.send_len = sizeof(set_powered_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_off_settings_param,
	.expect_len = sizeof(set_powered_off_settings_param),
	.expect_settings_unset = MGMT_SETTING_POWERED,
};

static const struct generic_data set_powered_off_class_test = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_off_param,
	.send_len = sizeof(set_powered_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_off_settings_param,
	.expect_len = sizeof(set_powered_off_settings_param),
	.expect_settings_unset = MGMT_SETTING_POWERED,
	.expect_alt_ev = MGMT_EV_CLASS_OF_DEV_CHANGED,
	.expect_alt_ev_param = set_powered_off_class_of_dev,
	.expect_alt_ev_len = sizeof(set_powered_off_class_of_dev),
};

static const struct generic_data set_powered_off_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_powered_off_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_invalid_param,
	.send_len = sizeof(set_powered_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_powered_off_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_garbage_param,
	.send_len = sizeof(set_powered_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char set_connectable_on_param[] = { 0x01 };
static const char set_connectable_invalid_param[] = { 0x02 };
static const char set_connectable_garbage_param[] = { 0x01, 0x00 };
static const char set_connectable_settings_param_1[] = { 0x82, 0x00, 0x00, 0x00 };
static const char set_connectable_settings_param_2[] = { 0x83, 0x00, 0x00, 0x00 };
static const char set_connectable_scan_enable_param[] = { 0x02 };

static const struct generic_data set_connectable_on_success_test_1 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_settings_param_1,
	.expect_len = sizeof(set_connectable_settings_param_1),
	.expect_settings_set = MGMT_SETTING_CONNECTABLE,
};

static const struct generic_data set_connectable_on_success_test_2 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_settings_param_2,
	.expect_len = sizeof(set_connectable_settings_param_2),
	.expect_settings_set = MGMT_SETTING_CONNECTABLE,
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_connectable_scan_enable_param,
	.expect_hci_len = sizeof(set_connectable_scan_enable_param),
};

static const struct generic_data set_connectable_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_connectable_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_invalid_param,
	.send_len = sizeof(set_connectable_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_connectable_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_garbage_param,
	.send_len = sizeof(set_connectable_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_connectable_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const char set_connectable_off_param[] = { 0x00 };
static const char set_connectable_off_settings_1[] = { 0x80, 0x00, 0x00, 0x00 };
static const char set_connectable_off_settings_2[] = { 0x81, 0x00, 0x00, 0x00 };
static const char set_connectable_off_scan_enable_param[] = { 0x00 };

static const struct generic_data set_connectable_off_success_test_1 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_off_settings_1,
	.expect_len = sizeof(set_connectable_off_settings_1),
	.expect_settings_unset = MGMT_SETTING_CONNECTABLE,
};

static const struct generic_data set_connectable_off_success_test_2 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_off_settings_2,
	.expect_len = sizeof(set_connectable_off_settings_2),
	.expect_settings_unset = MGMT_SETTING_CONNECTABLE,
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_connectable_off_scan_enable_param,
	.expect_hci_len = sizeof(set_connectable_off_scan_enable_param),
};

static const char set_fast_conn_on_param[] = { 0x01 };
static const char set_fast_conn_on_settings_1[] = { 0x87, 0x00, 0x00, 0x00 };

static const struct generic_data set_fast_conn_on_success_test_1 = {
	.send_opcode = MGMT_OP_SET_FAST_CONNECTABLE,
	.send_param = set_fast_conn_on_param,
	.send_len = sizeof(set_fast_conn_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_fast_conn_on_settings_1,
	.expect_len = sizeof(set_fast_conn_on_settings_1),
	.expect_settings_set = MGMT_SETTING_FAST_CONNECTABLE,
};

static const char set_pairable_on_param[] = { 0x01 };
static const char set_pairable_invalid_param[] = { 0x02 };
static const char set_pairable_garbage_param[] = { 0x01, 0x00 };
static const char set_pairable_settings_param[] = { 0x90, 0x00, 0x00, 0x00 };

static const struct generic_data set_pairable_on_success_test = {
	.send_opcode = MGMT_OP_SET_PAIRABLE,
	.send_param = set_pairable_on_param,
	.send_len = sizeof(set_pairable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_pairable_settings_param,
	.expect_len = sizeof(set_pairable_settings_param),
	.expect_settings_set = MGMT_SETTING_PAIRABLE,
};

static const struct generic_data set_pairable_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_PAIRABLE,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_pairable_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_PAIRABLE,
	.send_param = set_pairable_invalid_param,
	.send_len = sizeof(set_pairable_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_pairable_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_PAIRABLE,
	.send_param = set_pairable_garbage_param,
	.send_len = sizeof(set_pairable_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_pairable_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_PAIRABLE,
	.send_param = set_pairable_on_param,
	.send_len = sizeof(set_pairable_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const uint8_t set_discoverable_on_param[] = { 0x01, 0x00, 0x00 };
static const uint8_t set_discoverable_timeout_param[] = { 0x01, 0x0a, 0x00 };
static const uint8_t set_discoverable_invalid_param[] = { 0x02, 0x00, 0x00 };
static const uint8_t set_discoverable_off_param[] = { 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_offtimeout_param[] = { 0x00, 0x01, 0x00 };
static const uint8_t set_discoverable_garbage_param[] = { 0x01, 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_on_settings_param_1[] = { 0x8a, 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_on_settings_param_2[] = { 0x8b, 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_off_settings_param_1[] = { 0x82, 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_off_settings_param_2[] = { 0x83, 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_on_scan_enable_param[] = { 0x03 };
static const uint8_t set_discoverable_off_scan_enable_param[] = { 0x02 };

static const struct generic_data set_discoverable_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_discoverable_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_invalid_param,
	.send_len = sizeof(set_discoverable_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_discoverable_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_garbage_param,
	.send_len = sizeof(set_discoverable_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_discoverable_on_invalid_param_test_4 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_offtimeout_param,
	.send_len = sizeof(set_discoverable_offtimeout_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_discoverable_on_not_powered_test_1 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_timeout_param,
	.send_len = sizeof(set_discoverable_timeout_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
};

static const struct generic_data set_discoverable_on_rejected_test_1 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_discoverable_on_rejected_test_2 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_discoverable_on_rejected_test_3 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_timeout_param,
	.send_len = sizeof(set_discoverable_timeout_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_discoverable_on_success_test_1 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_on_settings_param_1,
	.expect_len = sizeof(set_discoverable_on_settings_param_1),
	.expect_settings_set = MGMT_SETTING_DISCOVERABLE,
};

static const struct generic_data set_discoverable_on_success_test_2 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_on_settings_param_2,
	.expect_len = sizeof(set_discoverable_on_settings_param_2),
	.expect_settings_set = MGMT_SETTING_DISCOVERABLE,
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_discoverable_on_scan_enable_param,
	.expect_hci_len = sizeof(set_discoverable_on_scan_enable_param),
};

static const struct generic_data set_discoverable_off_success_test_1 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_off_param,
	.send_len = sizeof(set_discoverable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_off_settings_param_1,
	.expect_len = sizeof(set_discoverable_off_settings_param_1),
};

static const struct generic_data set_discoverable_off_success_test_2 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_off_param,
	.send_len = sizeof(set_discoverable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_off_settings_param_2,
	.expect_len = sizeof(set_discoverable_off_settings_param_2),
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_discoverable_off_scan_enable_param,
	.expect_hci_len = sizeof(set_discoverable_off_scan_enable_param),
};

static const char set_link_sec_on_param[] = { 0x01 };
static const char set_link_sec_invalid_param[] = { 0x02 };
static const char set_link_sec_garbage_param[] = { 0x01, 0x00 };
static const char set_link_sec_settings_param_1[] = { 0xa0, 0x00, 0x00, 0x00 };
static const char set_link_sec_settings_param_2[] = { 0xa1, 0x00, 0x00, 0x00 };
static const char set_link_sec_auth_enable_param[] = { 0x01 };

static const struct generic_data set_link_sec_on_success_test_1 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_on_param,
	.send_len = sizeof(set_link_sec_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_link_sec_settings_param_1,
	.expect_len = sizeof(set_link_sec_settings_param_1),
	.expect_settings_set = MGMT_SETTING_LINK_SECURITY,
};

static const struct generic_data set_link_sec_on_success_test_2 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_on_param,
	.send_len = sizeof(set_link_sec_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_link_sec_settings_param_2,
	.expect_len = sizeof(set_link_sec_settings_param_2),
	.expect_settings_set = MGMT_SETTING_LINK_SECURITY,
	.expect_hci_command = BT_HCI_CMD_WRITE_AUTH_ENABLE,
	.expect_hci_param = set_link_sec_auth_enable_param,
	.expect_hci_len = sizeof(set_link_sec_auth_enable_param),
};

static const struct generic_data set_link_sec_on_success_test_3 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_link_sec_settings_param_2,
	.expect_len = sizeof(set_link_sec_settings_param_2),
	.expect_settings_set = MGMT_SETTING_LINK_SECURITY,
	.expect_hci_command = BT_HCI_CMD_WRITE_AUTH_ENABLE,
	.expect_hci_param = set_link_sec_auth_enable_param,
	.expect_hci_len = sizeof(set_link_sec_auth_enable_param),
};

static const struct generic_data set_link_sec_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_link_sec_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_invalid_param,
	.send_len = sizeof(set_link_sec_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_link_sec_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_garbage_param,
	.send_len = sizeof(set_link_sec_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_link_sec_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_on_param,
	.send_len = sizeof(set_link_sec_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const char set_link_sec_off_param[] = { 0x00 };
static const char set_link_sec_off_settings_1[] = { 0x80, 0x00, 0x00, 0x00 };
static const char set_link_sec_off_settings_2[] = { 0x81, 0x00, 0x00, 0x00 };
static const char set_link_sec_off_auth_enable_param[] = { 0x00 };

static const struct generic_data set_link_sec_off_success_test_1 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_off_param,
	.send_len = sizeof(set_link_sec_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_link_sec_off_settings_1,
	.expect_len = sizeof(set_link_sec_off_settings_1),
	.expect_settings_unset = MGMT_SETTING_LINK_SECURITY,
};

static const struct generic_data set_link_sec_off_success_test_2 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_off_param,
	.send_len = sizeof(set_link_sec_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_link_sec_off_settings_2,
	.expect_len = sizeof(set_link_sec_off_settings_2),
	.expect_settings_unset = MGMT_SETTING_LINK_SECURITY,
	.expect_hci_command = BT_HCI_CMD_WRITE_AUTH_ENABLE,
	.expect_hci_param = set_link_sec_off_auth_enable_param,
	.expect_hci_len = sizeof(set_link_sec_off_auth_enable_param),
};

static const char set_ssp_on_param[] = { 0x01 };
static const char set_ssp_invalid_param[] = { 0x02 };
static const char set_ssp_garbage_param[] = { 0x01, 0x00 };
static const char set_ssp_settings_param_1[] = { 0xc0, 0x00, 0x00, 0x00 };
static const char set_ssp_settings_param_2[] = { 0xc1, 0x00, 0x00, 0x00 };
static const char set_ssp_on_write_ssp_mode_param[] = { 0x01 };

static const struct generic_data set_ssp_on_success_test_1 = {
	.send_opcode = MGMT_OP_SET_SSP,
	.send_param = set_ssp_on_param,
	.send_len = sizeof(set_ssp_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_ssp_settings_param_1,
	.expect_len = sizeof(set_ssp_settings_param_1),
	.expect_settings_set = MGMT_SETTING_SSP,
};

static const struct generic_data set_ssp_on_success_test_2 = {
	.send_opcode = MGMT_OP_SET_SSP,
	.send_param = set_ssp_on_param,
	.send_len = sizeof(set_ssp_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_ssp_settings_param_2,
	.expect_len = sizeof(set_ssp_settings_param_2),
	.expect_settings_set = MGMT_SETTING_SSP,
	.expect_hci_command = BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE,
	.expect_hci_param = set_ssp_on_write_ssp_mode_param,
	.expect_hci_len = sizeof(set_ssp_on_write_ssp_mode_param),
};

static const struct generic_data set_ssp_on_success_test_3 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_ssp_settings_param_2,
	.expect_len = sizeof(set_ssp_settings_param_2),
	.expect_settings_set = MGMT_SETTING_SSP,
	.expect_hci_command = BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE,
	.expect_hci_param = set_ssp_on_write_ssp_mode_param,
	.expect_hci_len = sizeof(set_ssp_on_write_ssp_mode_param),
};

static const struct generic_data set_ssp_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_SSP,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_ssp_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_SSP,
	.send_param = set_ssp_invalid_param,
	.send_len = sizeof(set_ssp_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_ssp_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_SSP,
	.send_param = set_ssp_garbage_param,
	.send_len = sizeof(set_ssp_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_ssp_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_SSP,
	.send_param = set_ssp_on_param,
	.send_len = sizeof(set_ssp_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const char set_le_on_param[] = { 0x01 };
static const char set_le_invalid_param[] = { 0x02 };
static const char set_le_garbage_param[] = { 0x01, 0x00 };
static const char set_le_settings_param_1[] = { 0x80, 0x02, 0x00, 0x00 };
static const char set_le_settings_param_2[] = { 0x81, 0x02, 0x00, 0x00 };
static const char set_le_on_write_le_host_param[] = { 0x01, 0x01 };

static const struct generic_data set_le_on_success_test_1 = {
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_on_param,
	.send_len = sizeof(set_le_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_le_settings_param_1,
	.expect_len = sizeof(set_le_settings_param_1),
	.expect_settings_set = MGMT_SETTING_LE,
};

static const struct generic_data set_le_on_success_test_2 = {
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_on_param,
	.send_len = sizeof(set_le_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_le_settings_param_2,
	.expect_len = sizeof(set_le_settings_param_2),
	.expect_settings_set = MGMT_SETTING_LE,
	.expect_hci_command = BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED,
	.expect_hci_param = set_le_on_write_le_host_param,
	.expect_hci_len = sizeof(set_le_on_write_le_host_param),
};

static const struct generic_data set_le_on_success_test_3 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_le_settings_param_2,
	.expect_len = sizeof(set_le_settings_param_2),
	.expect_settings_set = MGMT_SETTING_LE,
	.expect_hci_command = BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED,
	.expect_hci_param = set_le_on_write_le_host_param,
	.expect_hci_len = sizeof(set_le_on_write_le_host_param),
};

static const struct generic_data set_le_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_LE,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_le_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_invalid_param,
	.send_len = sizeof(set_le_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_le_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_garbage_param,
	.send_len = sizeof(set_le_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_le_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_on_param,
	.send_len = sizeof(set_le_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const char set_local_name_param[260] = { 'T', 'e', 's', 't', ' ',
						'n', 'a', 'm', 'e' };
static const char write_local_name_hci[248] = { 'T', 'e', 's', 't', ' ',
						'n', 'a', 'm', 'e' };
static const char write_eir_local_name_hci_1[241] = { 0x00,
		0x0a, 0x09, 'T', 'e', 's', 't', ' ', 'n', 'a', 'm', 'e',
		0x02, 0x0a, 0x00, };

static const struct generic_data set_local_name_test_1 = {
	.send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.send_param = set_local_name_param,
	.send_len = sizeof(set_local_name_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_local_name_param,
	.expect_len = sizeof(set_local_name_param),
	.expect_alt_ev = MGMT_EV_LOCAL_NAME_CHANGED,
	.expect_alt_ev_param = set_local_name_param,
	.expect_alt_ev_len = sizeof(set_local_name_param),
};

static const struct generic_data set_local_name_test_2 = {
	.send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.send_param = set_local_name_param,
	.send_len = sizeof(set_local_name_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_local_name_param,
	.expect_len = sizeof(set_local_name_param),
	.expect_hci_command = BT_HCI_CMD_WRITE_LOCAL_NAME,
	.expect_hci_param = write_local_name_hci,
	.expect_hci_len = sizeof(write_local_name_hci),
	.expect_alt_ev = MGMT_EV_LOCAL_NAME_CHANGED,
	.expect_alt_ev_param = set_local_name_param,
	.expect_alt_ev_len = sizeof(set_local_name_param),
};

static const struct generic_data set_local_name_test_3 = {
	.send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.send_param = set_local_name_param,
	.send_len = sizeof(set_local_name_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_local_name_param,
	.expect_len = sizeof(set_local_name_param),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_local_name_hci_1,
	.expect_hci_len = sizeof(write_eir_local_name_hci_1),
	.expect_alt_ev = MGMT_EV_LOCAL_NAME_CHANGED,
	.expect_alt_ev_param = set_local_name_param,
	.expect_alt_ev_len = sizeof(set_local_name_param),
};

static const char start_discovery_invalid_param[] = { 0x00 };
static const char start_discovery_bredr_param[] = { 0x01 };
static const char start_discovery_le_param[] = { 0x06 };
static const char start_discovery_bredrle_param[] = { 0x07 };
static const char start_discovery_valid_hci[] = { 0x01, 0x01 };
static const char start_discovery_evt[] = { 0x07, 0x01 };
static const char start_discovery_le_evt[] = { 0x06, 0x01 };
static const char start_discovery_inq_param[] = { 0x33, 0x8b, 0x9e, 0x08,
									0x00 };
static const char start_device_found_evt[] = { 0x00, 0x00, 0x02, 0x01, 0xaa,
			0x00, 0x00, 0xc4, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00,
			0x04, 0x0d, 0x00, 0x00, 0x00, };
static const char start_le_device_found_evt[] = { 0x00, 0x00, 0x02, 0x01, 0xaa,
			0x00, 0x01, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
			0x02, 0x01, 0x06, 0x02, 0x0a, 0x00, };

static const struct generic_data start_discovery_not_powered_test_1 = {
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_bredr_param,
	.send_len = sizeof(start_discovery_bredr_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
};

static const struct generic_data start_discovery_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_invalid_param,
	.send_len = sizeof(start_discovery_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data start_discovery_not_supported_test_1 = {
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
};

static const struct generic_data start_discovery_valid_param_test_1 = {
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_bredrle_param,
	.send_len = sizeof(start_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_bredrle_param,
	.expect_len = sizeof(start_discovery_bredrle_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_ENABLE,
	.expect_hci_param = start_discovery_valid_hci,
	.expect_hci_len = sizeof(start_discovery_valid_hci),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_discovery_evt,
	.expect_alt_ev_len = sizeof(start_discovery_evt),
};

static const struct generic_data start_discovery_valid_param_test_2 = {
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_le_param,
	.expect_len = sizeof(start_discovery_le_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_ENABLE,
	.expect_hci_param = start_discovery_valid_hci,
	.expect_hci_len = sizeof(start_discovery_valid_hci),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_discovery_le_evt,
	.expect_alt_ev_len = sizeof(start_discovery_le_evt),
};

static const struct generic_data start_discovery_valid_param_test_3 = {
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_bredr_param,
	.send_len = sizeof(start_discovery_bredr_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_bredr_param,
	.expect_len = sizeof(start_discovery_bredr_param),
	.expect_hci_command = BT_HCI_CMD_INQUIRY,
	.expect_hci_param = start_discovery_inq_param,
	.expect_hci_len = sizeof(start_discovery_inq_param),
	.expect_alt_ev = MGMT_EV_DEVICE_FOUND,
	.expect_alt_ev_param = start_device_found_evt,
	.expect_alt_ev_len = sizeof(start_device_found_evt),
};

static const struct generic_data start_discovery_valid_param_test_4 = {
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_le_param,
	.expect_len = sizeof(start_discovery_le_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_ENABLE,
	.expect_hci_param = start_discovery_valid_hci,
	.expect_hci_len = sizeof(start_discovery_valid_hci),
	.expect_alt_ev = MGMT_EV_DEVICE_FOUND,
	.expect_alt_ev_param = start_le_device_found_evt,
	.expect_alt_ev_len = sizeof(start_le_device_found_evt),
};

static const char stop_discovery_bredrle_param[] = { 0x07 };
static const char stop_discovery_bredrle_invalid_param[] = { 0x06 };
static const char stop_discovery_valid_hci[] = { 0x00, 0x00 };
static const char stop_discovery_evt[] = { 0x07, 0x00 };
static const char stop_discovery_bredr_param[] = { 0x01 };
static const char stop_discovery_bredr_discovering[] = { 0x01, 0x00 };
static const char stop_discovery_inq_param[] = { 0x33, 0x8b, 0x9e, 0x08, 0x00 };
static const char stop_device_found_bredr_evt[] = { 0x00, 0x00, 0x02, 0x01,
			0xaa, 0x00, 0x00, 0xc4, 0x03, 0x00, 0x00, 0x00, 0x05,
			0x00, 0x04, 0x0d, 0x00, 0x00, 0x00, };

static const struct generic_data stop_discovery_success_test_1 = {
	.send_opcode = MGMT_OP_STOP_DISCOVERY,
	.send_param = stop_discovery_bredrle_param,
	.send_len = sizeof(stop_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = stop_discovery_bredrle_param,
	.expect_len = sizeof(stop_discovery_bredrle_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_ENABLE,
	.expect_hci_param = stop_discovery_valid_hci,
	.expect_hci_len = sizeof(stop_discovery_valid_hci),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = stop_discovery_evt,
	.expect_alt_ev_len = sizeof(stop_discovery_evt),
};

static const struct generic_data stop_discovery_bredr_success_test_1 = {
	.setup_expect_hci_command = BT_HCI_CMD_INQUIRY,
	.setup_expect_hci_param = stop_discovery_inq_param,
	.setup_expect_hci_len = sizeof(stop_discovery_inq_param),
	.send_opcode = MGMT_OP_STOP_DISCOVERY,
	.send_param = stop_discovery_bredr_param,
	.send_len = sizeof(stop_discovery_bredr_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = stop_discovery_bredr_param,
	.expect_len = sizeof(stop_discovery_bredr_param),
	.expect_hci_command = BT_HCI_CMD_INQUIRY_CANCEL,
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = stop_discovery_bredr_discovering,
	.expect_alt_ev_len = sizeof(stop_discovery_bredr_discovering),
};

static const struct generic_data stop_discovery_bredr_success_test_2 = {
	.setup_expect_hci_command = BT_HCI_CMD_INQUIRY,
	.setup_expect_hci_param = stop_discovery_inq_param,
	.setup_expect_hci_len = sizeof(stop_discovery_inq_param),
	.block_hci_command = BT_HCI_EVT_INQUIRY_COMPLETE,
	.send_opcode = MGMT_OP_STOP_DISCOVERY,
	.send_param = stop_discovery_bredr_param,
	.send_len = sizeof(stop_discovery_bredr_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = stop_discovery_bredr_param,
	.expect_len = sizeof(stop_discovery_bredr_param),
	.expect_hci_command = BT_HCI_CMD_INQUIRY_CANCEL,
	.expect_alt_ev = MGMT_EV_DEVICE_FOUND,
	.expect_alt_ev_param = stop_device_found_bredr_evt,
	.expect_alt_ev_len = sizeof(stop_device_found_bredr_evt),
};

static const struct generic_data stop_discovery_rejected_test_1 = {
	.send_opcode = MGMT_OP_STOP_DISCOVERY,
	.send_param = stop_discovery_bredrle_param,
	.send_len = sizeof(stop_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_REJECTED,
	.expect_param = stop_discovery_bredrle_param,
	.expect_len = sizeof(stop_discovery_bredrle_param),
};

static const struct generic_data stop_discovery_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_STOP_DISCOVERY,
	.send_param = stop_discovery_bredrle_invalid_param,
	.send_len = sizeof(stop_discovery_bredrle_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = stop_discovery_bredrle_invalid_param,
	.expect_len = sizeof(stop_discovery_bredrle_invalid_param),
};

static const char set_dev_class_valid_param[] = { 0x01, 0x0c };
static const char set_dev_class_zero_rsp[] = { 0x00, 0x00, 0x00 };
static const char set_dev_class_valid_rsp[] = { 0x0c, 0x01, 0x00 };
static const char set_dev_class_valid_hci[] = { 0x0c, 0x01, 0x00 };
static const char set_dev_class_invalid_param[] = { 0x01, 0x01 };

static const struct generic_data set_dev_class_valid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_DEV_CLASS,
	.send_param = set_dev_class_valid_param,
	.send_len = sizeof(set_dev_class_valid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
};

static const struct generic_data set_dev_class_valid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_DEV_CLASS,
	.send_param = set_dev_class_valid_param,
	.send_len = sizeof(set_dev_class_valid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_valid_rsp,
	.expect_len = sizeof(set_dev_class_valid_rsp),
	.expect_alt_ev = MGMT_EV_CLASS_OF_DEV_CHANGED,
	.expect_alt_ev_param = set_dev_class_valid_rsp,
	.expect_alt_ev_len = sizeof(set_dev_class_valid_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_CLASS_OF_DEV,
	.expect_hci_param = set_dev_class_valid_hci,
	.expect_hci_len = sizeof(set_dev_class_valid_hci),
};

static const struct generic_data set_dev_class_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_DEV_CLASS,
	.send_param = set_dev_class_invalid_param,
	.send_len = sizeof(set_dev_class_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char add_spp_uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00,
			0x00 };
static const char add_dun_uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x03, 0x11, 0x00, 0x00,
			0x00 };
static const char add_sync_uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x04, 0x11, 0x00, 0x00,
			0x00 };
static const char add_opp_uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x05, 0x11, 0x00, 0x00,
			0x00 };
static const char write_eir_uuid16_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x03, 0x03, 0x01, 0x11 };
static const char write_eir_multi_uuid16_hci_1[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x09, 0x03, 0x01, 0x11, 0x03,
			0x11, 0x04, 0x11, 0x05, 0x11 };
static const char write_eir_multi_uuid16_hci_2[241] = { 0x00,
			0x02, 0x0a, 0x00, 0xeb, 0x02, 0x00, 0x20, 0x01,
			0x20, 0x02, 0x20, 0x03, 0x20, 0x04, 0x20, 0x05,
			0x20, 0x06, 0x20, 0x07, 0x20, 0x08, 0x20, 0x09,
			0x20, 0x0a, 0x20, 0x0b, 0x20, 0x0c, 0x20, 0x0d,
			0x20, 0x0e, 0x20, 0x0f, 0x20, 0x10, 0x20, 0x11,
			0x20, 0x12, 0x20, 0x13, 0x20, 0x14, 0x20, 0x15,
			0x20, 0x16, 0x20, 0x17, 0x20, 0x18, 0x20, 0x19,
			0x20, 0x1a, 0x20, 0x1b, 0x20, 0x1c, 0x20, 0x1d,
			0x20, 0x1e, 0x20, 0x1f, 0x20, 0x20, 0x20, 0x21,
			0x20, 0x22, 0x20, 0x23, 0x20, 0x24, 0x20, 0x25,
			0x20, 0x26, 0x20, 0x27, 0x20, 0x28, 0x20, 0x29,
			0x20, 0x2a, 0x20, 0x2b, 0x20, 0x2c, 0x20, 0x2d,
			0x20, 0x2e, 0x20, 0x2f, 0x20, 0x30, 0x20, 0x31,
			0x20, 0x32, 0x20, 0x33, 0x20, 0x34, 0x20, 0x35,
			0x20, 0x36, 0x20, 0x37, 0x20, 0x38, 0x20, 0x39,
			0x20, 0x3a, 0x20, 0x3b, 0x20, 0x3c, 0x20, 0x3d,
			0x20, 0x3e, 0x20, 0x3f, 0x20, 0x40, 0x20, 0x41,
			0x20, 0x42, 0x20, 0x43, 0x20, 0x44, 0x20, 0x45,
			0x20, 0x46, 0x20, 0x47, 0x20, 0x48, 0x20, 0x49,
			0x20, 0x4a, 0x20, 0x4b, 0x20, 0x4c, 0x20, 0x4d,
			0x20, 0x4e, 0x20, 0x4f, 0x20, 0x50, 0x20, 0x51,
			0x20, 0x52, 0x20, 0x53, 0x20, 0x54, 0x20, 0x55,
			0x20, 0x56, 0x20, 0x57, 0x20, 0x58, 0x20, 0x59,
			0x20, 0x5a, 0x20, 0x5b, 0x20, 0x5c, 0x20, 0x5d,
			0x20, 0x5e, 0x20, 0x5f, 0x20, 0x60, 0x20, 0x61,
			0x20, 0x62, 0x20, 0x63, 0x20, 0x64, 0x20, 0x65,
			0x20, 0x66, 0x20, 0x67, 0x20, 0x68, 0x20, 0x69,
			0x20, 0x6a, 0x20, 0x6b, 0x20, 0x6c, 0x20, 0x6d,
			0x20, 0x6e, 0x20, 0x6f, 0x20, 0x70, 0x20, 0x71,
			0x20, 0x72, 0x20, 0x73, 0x20, 0x74, 0x20, 0x00 };
static const char add_uuid32_param_1[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12,
			0x00 };
static const char add_uuid32_param_2[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0xef, 0xcd, 0xbc, 0x9a,
			0x00 };
static const char add_uuid32_param_3[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0xff, 0xee, 0xdd, 0xcc,
			0x00 };
static const char add_uuid32_param_4[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
			0x00 };
static const char write_eir_uuid32_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x05, 0x05, 0x78, 0x56, 0x34,
			0x12 };
static const char write_eir_uuid32_multi_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x11, 0x05, 0x78, 0x56, 0x34,
			0x12, 0xef, 0xcd, 0xbc, 0x9a, 0xff, 0xee, 0xdd,
			0xcc, 0x11, 0x22, 0x33, 0x44 };
static const char write_eir_uuid32_multi_hci_2[] = { 0x00,
			0x02, 0x0a, 0x00, 0xe9, 0x04, 0xff, 0xff, 0xff,
			0xff, 0xfe, 0xff, 0xff, 0xff, 0xfd, 0xff, 0xff,
			0xff, 0xfc, 0xff, 0xff, 0xff, 0xfb, 0xff, 0xff,
			0xff, 0xfa, 0xff, 0xff, 0xff, 0xf9, 0xff, 0xff,
			0xff, 0xf8, 0xff, 0xff, 0xff, 0xf7, 0xff, 0xff,
			0xff, 0xf6, 0xff, 0xff, 0xff, 0xf5, 0xff, 0xff,
			0xff, 0xf4, 0xff, 0xff, 0xff, 0xf3, 0xff, 0xff,
			0xff, 0xf2, 0xff, 0xff, 0xff, 0xf1, 0xff, 0xff,
			0xff, 0xf0, 0xff, 0xff, 0xff, 0xef, 0xff, 0xff,
			0xff, 0xee, 0xff, 0xff, 0xff, 0xed, 0xff, 0xff,
			0xff, 0xec, 0xff, 0xff, 0xff, 0xeb, 0xff, 0xff,
			0xff, 0xea, 0xff, 0xff, 0xff, 0xe9, 0xff, 0xff,
			0xff, 0xe8, 0xff, 0xff, 0xff, 0xe7, 0xff, 0xff,
			0xff, 0xe6, 0xff, 0xff, 0xff, 0xe5, 0xff, 0xff,
			0xff, 0xe4, 0xff, 0xff, 0xff, 0xe3, 0xff, 0xff,
			0xff, 0xe2, 0xff, 0xff, 0xff, 0xe1, 0xff, 0xff,
			0xff, 0xe0, 0xff, 0xff, 0xff, 0xdf, 0xff, 0xff,
			0xff, 0xde, 0xff, 0xff, 0xff, 0xdd, 0xff, 0xff,
			0xff, 0xdc, 0xff, 0xff, 0xff, 0xdb, 0xff, 0xff,
			0xff, 0xda, 0xff, 0xff, 0xff, 0xd9, 0xff, 0xff,
			0xff, 0xd8, 0xff, 0xff, 0xff, 0xd7, 0xff, 0xff,
			0xff, 0xd6, 0xff, 0xff, 0xff, 0xd5, 0xff, 0xff,
			0xff, 0xd4, 0xff, 0xff, 0xff, 0xd3, 0xff, 0xff,
			0xff, 0xd2, 0xff, 0xff, 0xff, 0xd1, 0xff, 0xff,
			0xff, 0xd0, 0xff, 0xff, 0xff, 0xcf, 0xff, 0xff,
			0xff, 0xce, 0xff, 0xff, 0xff, 0xcd, 0xff, 0xff,
			0xff, 0xcc, 0xff, 0xff, 0xff, 0xcb, 0xff, 0xff,
			0xff, 0xca, 0xff, 0xff, 0xff, 0xc9, 0xff, 0xff,
			0xff, 0xc8, 0xff, 0xff, 0xff, 0xc7, 0xff, 0xff,
			0xff, 0xc6, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 };
static const char add_uuid128_param_1[] = {
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
			0x00 };
static const char add_uuid128_param_2[] = {
			0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
			0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
			0x00 };
static const char write_eir_uuid128_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x11, 0x07, 0x00, 0x11, 0x22,
			0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
			0xbb, 0xcc, 0xdd, 0xee, 0xff };
static const char write_eir_uuid128_multi_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x21, 0x07, 0x00, 0x11, 0x22,
			0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
			0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xff, 0xee, 0xdd,
			0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55,
			0x44, 0x33, 0x22, 0x11 };
static const char write_eir_uuid128_multi_hci_2[] = { 0x00,
			0x02, 0x0a, 0x00, 0xe1, 0x07, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x01, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x02, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x03, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x04, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x05, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x06, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x07, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x08, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x09, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x0a, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x0b, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x0c, 0xff, 0xee, 0xdd,
			0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55,
			0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const char write_eir_uuid_mix_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x05, 0x03, 0x01, 0x11, 0x03,
			0x11, 0x09, 0x05, 0x78, 0x56, 0x34, 0x12, 0xef,
			0xcd, 0xbc, 0x9a, 0x21, 0x07, 0x00, 0x11, 0x22,
			0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
			0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xff, 0xee, 0xdd,
			0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55,
			0x44, 0x33, 0x22, 0x11 };

static const struct generic_data add_uuid16_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_spp_uuid_param,
	.send_len = sizeof(add_spp_uuid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid16_hci,
	.expect_hci_len = sizeof(write_eir_uuid16_hci),
};

static const struct generic_data add_multi_uuid16_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_opp_uuid_param,
	.send_len = sizeof(add_opp_uuid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_multi_uuid16_hci_1,
	.expect_hci_len = sizeof(write_eir_multi_uuid16_hci_1),
};

static const struct generic_data add_multi_uuid16_test_2 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_opp_uuid_param,
	.send_len = sizeof(add_opp_uuid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_multi_uuid16_hci_2,
	.expect_hci_len = sizeof(write_eir_multi_uuid16_hci_2),
};

static const struct generic_data add_uuid32_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid32_param_1,
	.send_len = sizeof(add_uuid32_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid32_hci,
	.expect_hci_len = sizeof(write_eir_uuid32_hci),
};

static const struct generic_data add_uuid32_multi_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid32_param_4,
	.send_len = sizeof(add_uuid32_param_4),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid32_multi_hci,
	.expect_hci_len = sizeof(write_eir_uuid32_multi_hci),
};

static const struct generic_data add_uuid32_multi_test_2 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid32_param_4,
	.send_len = sizeof(add_uuid32_param_4),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid32_multi_hci_2,
	.expect_hci_len = sizeof(write_eir_uuid32_multi_hci_2),
};

static const struct generic_data add_uuid128_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid128_param_1,
	.send_len = sizeof(add_uuid128_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid128_hci,
	.expect_hci_len = sizeof(write_eir_uuid128_hci),
};

static const struct generic_data add_uuid128_multi_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid128_param_2,
	.send_len = sizeof(add_uuid32_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid128_multi_hci,
	.expect_hci_len = sizeof(write_eir_uuid128_multi_hci),
};

static const struct generic_data add_uuid128_multi_test_2 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid128_param_2,
	.send_len = sizeof(add_uuid128_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid128_multi_hci_2,
	.expect_hci_len = sizeof(write_eir_uuid128_multi_hci_2),
};

static const struct generic_data add_uuid_mix_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid128_param_2,
	.send_len = sizeof(add_uuid128_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid_mix_hci,
	.expect_hci_len = sizeof(write_eir_uuid_mix_hci),
};

static const char load_link_keys_valid_param_1[] = { 0x00, 0x00, 0x00 };
static const char load_link_keys_valid_param_2[] = { 0x01, 0x00, 0x00 };
static const char load_link_keys_invalid_param_1[] = { 0x02, 0x00, 0x00 };
static const char load_link_keys_invalid_param_2[] = { 0x00, 0x01, 0x00 };
/* Invalid bdaddr type */
static const char load_link_keys_invalid_param_3[] = { 0x00, 0x01, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* addr */
	0x01,						/* addr type */
	0x00,						/* key type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* value (2/2) */
	0x04,						/* PIN length */
};

static const struct generic_data load_link_keys_success_test_1 = {
	.send_opcode = MGMT_OP_LOAD_LINK_KEYS,
	.send_param = load_link_keys_valid_param_1,
	.send_len = sizeof(load_link_keys_valid_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data load_link_keys_success_test_2 = {
	.send_opcode = MGMT_OP_LOAD_LINK_KEYS,
	.send_param = load_link_keys_valid_param_2,
	.send_len = sizeof(load_link_keys_valid_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data load_link_keys_invalid_params_test_1 = {
	.send_opcode = MGMT_OP_LOAD_LINK_KEYS,
	.send_param = load_link_keys_invalid_param_1,
	.send_len = sizeof(load_link_keys_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data load_link_keys_invalid_params_test_2 = {
	.send_opcode = MGMT_OP_LOAD_LINK_KEYS,
	.send_param = load_link_keys_invalid_param_2,
	.send_len = sizeof(load_link_keys_invalid_param_2),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data load_link_keys_invalid_params_test_3 = {
	.send_opcode = MGMT_OP_LOAD_LINK_KEYS,
	.send_param = load_link_keys_invalid_param_3,
	.send_len = sizeof(load_link_keys_invalid_param_3),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char load_ltks_valid_param_1[] = { 0x00, 0x00 };
/* Invalid key count */
static const char load_ltks_invalid_param_1[] = { 0x01, 0x00 };
/* Invalid addr type */
static const char load_ltks_invalid_param_2[] = {
	0x01, 0x00,					/* count */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x00,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2 */
};
/* Invalid authenticated value */
static const char load_ltks_invalid_param_3[] = {
	0x01, 0x00,					/* count */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x02,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2 */
};
/* Invalid master value */
static const char load_ltks_invalid_param_4[] = {
	0x01, 0x00,					/* count */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authunticated */
	0x02,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2 */
};

static const struct generic_data load_ltks_success_test_1 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_valid_param_1,
	.send_len = sizeof(load_ltks_valid_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data load_ltks_invalid_params_test_1 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_invalid_param_1,
	.send_len = sizeof(load_ltks_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data load_ltks_invalid_params_test_2 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_invalid_param_2,
	.send_len = sizeof(load_ltks_invalid_param_2),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data load_ltks_invalid_params_test_3 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_invalid_param_3,
	.send_len = sizeof(load_ltks_invalid_param_3),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data load_ltks_invalid_params_test_4 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_invalid_param_4,
	.send_len = sizeof(load_ltks_invalid_param_4),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char pair_device_param[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00 };
static const char pair_device_rsp[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00 };
static const char pair_device_invalid_param_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff, 0x00 };
static const char pair_device_invalid_param_rsp_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };

static const struct generic_data pair_device_not_powered_test_1 = {
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_param = pair_device_param,
	.send_len = sizeof(pair_device_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
	.expect_param = pair_device_rsp,
	.expect_len = sizeof(pair_device_rsp),
};

static const struct generic_data pair_device_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_param = pair_device_invalid_param_1,
	.send_len = sizeof(pair_device_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = pair_device_invalid_param_rsp_1,
	.expect_len = sizeof(pair_device_invalid_param_rsp_1),
};

static const char unpair_device_param[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00 };
static const char unpair_device_rsp[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00 };
static const char unpair_device_invalid_param_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff, 0x00 };
static const char unpair_device_invalid_param_rsp_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };
static const char unpair_device_invalid_param_2[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x02 };
static const char unpair_device_invalid_param_rsp_2[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00 };

static const struct generic_data unpair_device_not_powered_test_1 = {
	.send_opcode = MGMT_OP_UNPAIR_DEVICE,
	.send_param = unpair_device_param,
	.send_len = sizeof(unpair_device_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
	.expect_param = unpair_device_rsp,
	.expect_len = sizeof(unpair_device_rsp),
};

static const struct generic_data unpair_device_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_UNPAIR_DEVICE,
	.send_param = unpair_device_invalid_param_1,
	.send_len = sizeof(unpair_device_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = unpair_device_invalid_param_rsp_1,
	.expect_len = sizeof(unpair_device_invalid_param_rsp_1),
};

static const struct generic_data unpair_device_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_UNPAIR_DEVICE,
	.send_param = unpair_device_invalid_param_2,
	.send_len = sizeof(unpair_device_invalid_param_2),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = unpair_device_invalid_param_rsp_2,
	.expect_len = sizeof(unpair_device_invalid_param_rsp_2),
};

static const char disconnect_invalid_param_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };
static const char disconnect_invalid_param_rsp_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };

static const struct generic_data disconnect_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_DISCONNECT,
	.send_param = disconnect_invalid_param_1,
	.send_len = sizeof(disconnect_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = disconnect_invalid_param_rsp_1,
	.expect_len = sizeof(disconnect_invalid_param_rsp_1),
};

static const char block_device_invalid_param_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };
static const char block_device_invalid_param_rsp_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };

static const struct generic_data block_device_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_BLOCK_DEVICE,
	.send_param = block_device_invalid_param_1,
	.send_len = sizeof(block_device_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = block_device_invalid_param_rsp_1,
	.expect_len = sizeof(block_device_invalid_param_rsp_1),
};

static const char unblock_device_invalid_param_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };
static const char unblock_device_invalid_param_rsp_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };

static const struct generic_data unblock_device_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_UNBLOCK_DEVICE,
	.send_param = unblock_device_invalid_param_1,
	.send_len = sizeof(unblock_device_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = unblock_device_invalid_param_rsp_1,
	.expect_len = sizeof(unblock_device_invalid_param_rsp_1),
};

static void powered_delay(void *user_data)
{
	tester_setup_complete();
}

static void setup_powered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller powered on");

	if (option_wait_powered)
		tester_wait(1, powered_delay, NULL);
	else
		tester_setup_complete();
}

static void setup_powered_discoverable(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	unsigned char discov_param[] = { 0x01, 0x00, 0x00 };

	tester_print("Enabling connectable, discoverable and powered");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_DISCOVERABLE, data->mgmt_index,
					sizeof(discov_param), discov_param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_powered_connectable(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Enabling connectable and powered");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_class(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	unsigned char class_param[] = { 0x01, 0x0c };

	tester_print("Setting device class and powering on");

	mgmt_send(data->mgmt, MGMT_OP_SET_DEV_CLASS, data->mgmt_index,
				sizeof(class_param), class_param,
				NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_ssp_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with SSP enabled)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_le_powered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("First Controller powered on");

	if (!data->hciemu_second) {
		if (option_wait_powered)
			tester_wait(1, powered_delay, NULL);
		else
			tester_setup_complete();
		return;
	}
}

static void setup_le_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with LE enabled)");

	data->hciemu_second = hciemu_new(data->hciemu_type);
	if (!data->hciemu_second) {
		tester_warn("Failed to setup second HCI emulation");
		tester_setup_failed();
		return;
	}

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_le_powered_callback, NULL, NULL);
}

static void setup_discovery_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Discovery started");
	tester_setup_complete();
}

static bool setup_command_hci_callback(const void *data, uint16_t len,
								void *user_data)
{
	struct test_data *tdata = tester_get_data();
	const struct generic_data *test = tdata->test_data;
	bool *is_setup = user_data, ret = false;
	

	tester_print("HCI Command 0x%04x length %u (setup)",
					test->setup_expect_hci_command, len);

	if (len != test->setup_expect_hci_len) {
		tester_warn("Invalid parameter size for HCI command (setup)");
		goto fail;
	}

	if (memcmp(data, test->setup_expect_hci_param, len) != 0) {
		tester_warn("Unexpected HCI command parameter value (setup)");
		goto fail;
	}

	if (is_setup && *is_setup)
		tester_setup_complete();
	else {
		test_condition_complete(tdata);
		ret = true;
	}
	goto done;

fail:
	if (is_setup && *is_setup)
		tester_setup_failed();
	else
		tester_test_failed();

done:
	hciemu_del_hook(tdata->hciemu, HCIEMU_HOOK_PRE_EVT,
			test->setup_expect_hci_command);

	return ret;
}

static void setup_start_discovery_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller powered on");

	if (test->setup_expect_hci_command) {
		static bool is_setup = true;

		tester_print("Registering HCI command callback (setup)");
		hciemu_add_hook(data->hciemu, HCIEMU_HOOK_PRE_EVT,
				test->setup_expect_hci_command,
				setup_command_hci_callback,
				&is_setup);
		mgmt_send(data->mgmt, MGMT_OP_START_DISCOVERY, data->mgmt_index,
				test->send_len, test->send_param,
				NULL, NULL, NULL);
	} else {
		unsigned char disc_param[] = { 0x07 };

		mgmt_send(data->mgmt, MGMT_OP_START_DISCOVERY, data->mgmt_index,
					sizeof(disc_param), disc_param,
					setup_discovery_callback, NULL, NULL);
	}

	if (option_wait_powered)
		tester_wait(1, NULL, NULL);
}

static void setup_start_discovery(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with LE enabled)");

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
				sizeof(param), param,
				setup_start_discovery_callback, NULL, NULL);
}

static void setup_ssp_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("SSP enabled");

	tester_setup_complete();
}

static void setup_ssp(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Enabling SSP");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, setup_ssp_callback,
				NULL, NULL);
}

static void setup_le_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Low Energy enabled");

	tester_setup_complete();
}

static void setup_le(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Enabling Low Energy");

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
				sizeof(param), param, setup_le_callback,
				NULL, NULL);
}

static void setup_multi_uuid32(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with 32-bit UUID)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_uuid32_param_1), add_uuid32_param_1,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_uuid32_param_2), add_uuid32_param_2,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_uuid32_param_3), add_uuid32_param_3,
				NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_multi_uuid32_2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	unsigned char uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00 };
	int i;

	tester_print("Powering on controller (with many 32-bit UUIDs)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	for (i = 0; i < 58; i++) {
		uint32_t val = htobl(0xffffffff - i);
		memcpy(&uuid_param[12], &val, sizeof(val));
		mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(uuid_param), uuid_param,
				NULL, NULL, NULL);
	}

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_multi_uuid128(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with 128-bit UUID)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
			sizeof(add_uuid128_param_1), add_uuid128_param_1,
			NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_multi_uuid128_2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	unsigned char uuid_param[] = {
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
			0x00 };
	int i;

	tester_print("Powering on controller (with many 128-bit UUIDs)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	for (i = 0; i < 13; i++) {
		uuid_param[15] = i;
		mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(uuid_param), uuid_param,
				NULL, NULL, NULL);
	}

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_multi_uuid16(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with SPP UUID)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_spp_uuid_param), add_spp_uuid_param,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_dun_uuid_param), add_dun_uuid_param,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
			sizeof(add_sync_uuid_param), add_sync_uuid_param,
			NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_multi_uuid16_2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	unsigned char uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00 };
	int i;

	tester_print("Powering on controller (with many 16-bit UUIDs)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	for (i = 0; i < 117; i++) {
		uint16_t val = htobs(i + 0x2000);
		memcpy(&uuid_param[12], &val, sizeof(val));
		mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(uuid_param), uuid_param,
				NULL, NULL, NULL);
	}

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_uuid_mix(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with mixed UUIDs)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_spp_uuid_param), add_spp_uuid_param,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_uuid32_param_1), add_uuid32_param_1,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
			sizeof(add_uuid128_param_1), add_uuid128_param_1,
			NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_dun_uuid_param), add_dun_uuid_param,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_uuid32_param_2), add_uuid32_param_2,
				NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_connectable_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller connectable on");

	tester_setup_complete();
}

static void setup_connectable(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Setting controller connectable");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
					sizeof(param), param,
					setup_connectable_callback, NULL, NULL);
}

static void setup_connectable_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Setting controller powered and connectable");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
			sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_link_sec_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Link security enabled");

	tester_setup_complete();
}

static void setup_link_sec(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Enabling link security");

	mgmt_send(data->mgmt, MGMT_OP_SET_LINK_SECURITY, data->mgmt_index,
			sizeof(param), param, setup_link_sec_callback,
			NULL, NULL);
}

static void setup_link_sec_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Enabling link security and powering on");

	mgmt_send(data->mgmt, MGMT_OP_SET_LINK_SECURITY, data->mgmt_index,
			sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void command_generic_new_settings(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("New settings event received");

	mgmt_unregister(data->mgmt, data->mgmt_settings_id);

	tester_test_failed();
}

static void command_generic_new_settings_alt(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	uint32_t settings;

	if (length != 4) {
		tester_warn("Invalid parameter size for new settings event");
		tester_test_failed();
		return;
	}

	settings = bt_get_le32(param);

	tester_print("New settings 0x%08x received", settings);

	if (test->expect_settings_unset) {
		if ((settings & test->expect_settings_unset) != 0)
			return;
		goto done;
	}

	if (!test->expect_settings_set)
		return;

	if ((settings & test->expect_settings_set) != test->expect_settings_set)
		return;

done:
	tester_print("Unregistering new settings notification");

	mgmt_unregister(data->mgmt_alt, data->mgmt_alt_settings_id);

	test_condition_complete(data);
}

static void command_generic_event_alt(uint16_t index, uint16_t length,
							const void *param,
							void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	if (length != test->expect_alt_ev_len) {
		tester_warn("Invalid length %s event",
					mgmt_evstr(test->expect_alt_ev));
		tester_test_failed();
		return;
	}

	tester_print("New %s event received", mgmt_evstr(test->expect_alt_ev));

	if (memcmp(param, test->expect_alt_ev_param,
						test->expect_alt_ev_len) != 0)
		return;

	tester_print("Unregistering %s notification",
					mgmt_evstr(test->expect_alt_ev));

	mgmt_unregister(data->mgmt_alt, data->mgmt_alt_ev_id);

	test_condition_complete(data);
}

static void command_generic_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	tester_print("Command 0x%04x finished with status 0x%02x",
						test->send_opcode, status);

	if (status != test->expect_status) {
		tester_test_failed();
		return;
	}

	if (length != test->expect_len) {
		tester_test_failed();
		return;
	}

	if (test->expect_param && test->expect_len > 0 &&
				memcmp(param, test->expect_param, length)) {
		tester_test_failed();
		return;
	}

	test_condition_complete(data);
}

static bool command_hci_callback(uint16_t opcode, const void *param,
					uint8_t length, void *user_data)
{
	struct test_data *data = user_data;
	const struct generic_data *test = data->test_data;

	tester_print("HCI Command 0x%04x length %u", opcode, length);

	if (opcode != test->expect_hci_command)
		return true;

	if (length != test->expect_hci_len) {
		tester_warn("Invalid parameter size for HCI command");
		tester_test_failed();
		return false;
	}

	if (memcmp(param, test->expect_hci_param, length) != 0) {
		tester_warn("Unexpected HCI command parameter value");
		tester_test_failed();
		return false;
	}

	test_condition_complete(data);

	return true;
}

static void setup_test_command_generic(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	unsigned int id;
	uint16_t index;

	index = test->send_index_none ? MGMT_INDEX_NONE : data->mgmt_index;

	if (test->expect_settings_set || test->expect_settings_unset) {
		tester_print("Registering new settings notification");

		id = mgmt_register(data->mgmt, MGMT_EV_NEW_SETTINGS, index,
				command_generic_new_settings, NULL, NULL);
		data->mgmt_settings_id = id;

		id = mgmt_register(data->mgmt_alt, MGMT_EV_NEW_SETTINGS, index,
				command_generic_new_settings_alt, NULL, NULL);
		data->mgmt_alt_settings_id = id;
		test_add_condition(data);
	}

	if (test->expect_alt_ev) {
		tester_print("Registering %s notification",
					mgmt_evstr(test->expect_alt_ev));
		id = mgmt_register(data->mgmt_alt, test->expect_alt_ev, index,
					command_generic_event_alt, NULL, NULL);
		data->mgmt_alt_ev_id = id;
		test_add_condition(data);
	}

	if (test->expect_hci_command) {
		tester_print("Registering HCI command callback");
		hciemu_add_master_post_command_hook(data->hciemu,
						command_hci_callback, data);
		test_add_condition(data);
	}
}

static void test_command_generic(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	uint16_t index;

	index = test->send_index_none ? MGMT_INDEX_NONE : data->mgmt_index;

	setup_test_command_generic(test_data);

	tester_print("Sending command 0x%04x", test->send_opcode);

	mgmt_send(data->mgmt, test->send_opcode, index,
					test->send_len, test->send_param,
					command_generic_callback, NULL, NULL);
	test_add_condition(data);
}

static bool stop_command_hci_callback(const void *data, uint16_t len,
								void *user_data)
{
	struct test_data *tdata = tester_get_data();
	const struct generic_data *test = tdata->test_data;

	tester_print("Interrupt HCI Command 0x%04x length %u",
						test->block_hci_command, len);

	test_condition_complete(tdata);

	hciemu_del_hook(tdata->hciemu, HCIEMU_HOOK_POST_EVT,
						test->block_hci_command);

	return false;
}

static void start_discovery_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	if (status != MGMT_STATUS_SUCCESS) {
		tester_warn("Error starting discovery");
		tester_test_failed();
		return;
	}

	tester_print("Discovery started");

	tester_print("Sending command 0x%04x", test->send_opcode);
	mgmt_send(data->mgmt, test->send_opcode, data->mgmt_index,
					test->send_len, test->send_param,
					command_generic_callback, NULL, NULL);
	test_add_condition(data);
}

static void hook_stop_hci_command(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	if (test->block_hci_command) {
		tester_print("Registering hook to stop HCI command 0x%04x",
						test->block_hci_command);
		hciemu_add_hook(data->hciemu, HCIEMU_HOOK_POST_EVT,
				test->block_hci_command,
				stop_command_hci_callback,
				NULL);
		test_add_condition(data);
	}
}

static void test_command_start_discovery(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	uint16_t index;

	index = test->send_index_none ? MGMT_INDEX_NONE : data->mgmt_index;

	setup_test_command_generic(test_data);

	tester_print("Registering HCI command callback (second)");
	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_PRE_EVT,
			test->setup_expect_hci_command,
			setup_command_hci_callback,
			NULL);
	test_add_condition(data);

	hook_stop_hci_command(test_data);

	mgmt_send(data->mgmt, MGMT_OP_START_DISCOVERY, index, test->send_len,
			test->send_param, start_discovery_callback, NULL, NULL);
}

static GOptionEntry options[] = {
	{ "wait-powered", 'P', 0, G_OPTION_ARG_NONE, &option_wait_powered,
					"Add a delay after powering on" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);
	g_option_context_set_ignore_unknown_options(context, TRUE);

	if (g_option_context_parse(context, &argc, &argv, &error) == FALSE) {
		if (error != NULL) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	tester_init(&argc, &argv);

	test_bredrle("Controller setup", NULL, NULL, controller_setup);
	test_bredr("Controller setup (BR/EDR-only)", NULL, NULL,
							controller_setup);
	test_le("Controller setup (LE-only)", NULL, NULL, controller_setup);
	test_bredrle("Invalid command", &invalid_command_test,
					NULL, test_command_generic);

	test_bredrle("Read version - Success", &read_version_success_test,
					NULL, test_command_generic);
	test_bredrle("Read version - Invalid parameters",
					&read_version_invalid_param_test,
					NULL, test_command_generic);
	test_bredrle("Read version - Invalid index",
					&read_version_invalid_index_test,
					NULL, test_command_generic);
	test_bredrle("Read commands - Invalid parameters",
					&read_commands_invalid_param_test,
					NULL, test_command_generic);
	test_bredrle("Read commands - Invalid index",
					&read_commands_invalid_index_test,
					NULL, test_command_generic);
	test_bredrle("Read index list - Invalid parameters",
					&read_index_list_invalid_param_test,
					NULL, test_command_generic);
	test_bredrle("Read index list - Invalid index",
					&read_index_list_invalid_index_test,
					NULL, test_command_generic);
	test_bredrle("Read info - Invalid parameters",
					&read_info_invalid_param_test,
					NULL, test_command_generic);
	test_bredrle("Read info - Invalid index",
					&read_info_invalid_index_test,
					NULL, test_command_generic);

	test_bredrle("Set powered on - Success",
					&set_powered_on_success_test,
					NULL, test_command_generic);
	test_bredrle("Set powered on - Invalid parameters 1",
					&set_powered_on_invalid_param_test_1,
					NULL, test_command_generic);
	test_bredrle("Set powered on - Invalid parameters 2",
					&set_powered_on_invalid_param_test_2,
					NULL, test_command_generic);
	test_bredrle("Set powered on - Invalid parameters 3",
					&set_powered_on_invalid_param_test_3,
					NULL, test_command_generic);
	test_bredrle("Set powered on - Invalid index",
					&set_powered_on_invalid_index_test,
					NULL, test_command_generic);

	test_bredrle("Set powered off - Success",
					&set_powered_off_success_test,
					setup_powered, test_command_generic);
	test_bredrle("Set powered off - Class of Device",
					&set_powered_off_class_test,
					setup_class, test_command_generic);
	test_bredrle("Set powered off - Invalid parameters 1",
					&set_powered_off_invalid_param_test_1,
					setup_powered, test_command_generic);
	test_bredrle("Set powered off - Invalid parameters 2",
					&set_powered_off_invalid_param_test_2,
					setup_powered, test_command_generic);
	test_bredrle("Set powered off - Invalid parameters 3",
					&set_powered_off_invalid_param_test_3,
					setup_powered, test_command_generic);

	test_bredrle("Set connectable on - Success 1",
					&set_connectable_on_success_test_1,
					NULL, test_command_generic);
	test_bredrle("Set connectable on - Success 2",
					&set_connectable_on_success_test_2,
					setup_powered, test_command_generic);
	test_bredrle("Set connectable on - Invalid parameters 1",
					&set_connectable_on_invalid_param_test_1,
					NULL, test_command_generic);
	test_bredrle("Set connectable on - Invalid parameters 2",
					&set_connectable_on_invalid_param_test_2,
					NULL, test_command_generic);
	test_bredrle("Set connectable on - Invalid parameters 3",
					&set_connectable_on_invalid_param_test_3,
					NULL, test_command_generic);
	test_bredrle("Set connectable on - Invalid index",
					&set_connectable_on_invalid_index_test,
					NULL, test_command_generic);

	test_bredrle("Set connectable off - Success 1",
				&set_connectable_off_success_test_1,
				setup_connectable, test_command_generic);
	test_bredrle("Set connectable off - Success 2",
					&set_connectable_off_success_test_2,
					setup_connectable_powered,
					test_command_generic);

	test_bredrle("Set fast connectable on - Success 1",
			&set_fast_conn_on_success_test_1,
			setup_powered_connectable, test_command_generic);

	test_bredrle("Set pairable on - Success",
					&set_pairable_on_success_test,
					NULL, test_command_generic);
	test_bredrle("Set pairable on - Invalid parameters 1",
					&set_pairable_on_invalid_param_test_1,
					NULL, test_command_generic);
	test_bredrle("Set pairable on - Invalid parameters 2",
					&set_pairable_on_invalid_param_test_2,
					NULL, test_command_generic);
	test_bredrle("Set pairable on - Invalid parameters 3",
					&set_pairable_on_invalid_param_test_3,
					NULL, test_command_generic);
	test_bredrle("Set pairable on - Invalid index",
					&set_pairable_on_invalid_index_test,
					NULL, test_command_generic);

	test_bredrle("Set discoverable on - Invalid parameters 1",
				&set_discoverable_on_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Invalid parameters 2",
				&set_discoverable_on_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Invalid parameters 3",
				&set_discoverable_on_invalid_param_test_3,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Invalid parameters 4",
				&set_discoverable_on_invalid_param_test_4,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Not powered 1",
				&set_discoverable_on_not_powered_test_1,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Not powered 1",
				&set_discoverable_on_not_powered_test_1,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Not powered 2",
				&set_discoverable_on_not_powered_test_1,
				setup_connectable, test_command_generic);
	test_bredrle("Set discoverable on - Rejected 1",
				&set_discoverable_on_rejected_test_1,
				setup_powered, test_command_generic);
	test_bredrle("Set discoverable on - Rejected 2",
				&set_discoverable_on_rejected_test_2,
				setup_powered, test_command_generic);
	test_bredrle("Set discoverable on - Rejected 3",
				&set_discoverable_on_rejected_test_3,
				setup_powered, test_command_generic);
	test_bredrle("Set discoverable on - Success 1",
				&set_discoverable_on_success_test_1,
				setup_connectable, test_command_generic);
	test_bredrle("Set discoverable on - Success 2",
				&set_discoverable_on_success_test_2,
				setup_powered_connectable, test_command_generic);
	test_bredrle("Set discoverable off - Success 1",
				&set_discoverable_off_success_test_1,
				setup_connectable, test_command_generic);
	test_bredrle("Set discoverable off - Success 2",
				&set_discoverable_off_success_test_2,
				setup_powered_discoverable,
				test_command_generic);

	test_bredrle("Set link security on - Success 1",
					&set_link_sec_on_success_test_1,
					NULL, test_command_generic);
	test_bredrle("Set link security on - Success 2",
					&set_link_sec_on_success_test_2,
					setup_powered, test_command_generic);
	test_bredrle("Set link security on - Success 3",
					&set_link_sec_on_success_test_3,
					setup_link_sec, test_command_generic);
	test_bredrle("Set link security on - Invalid parameters 1",
					&set_link_sec_on_invalid_param_test_1,
					NULL, test_command_generic);
	test_bredrle("Set link security on - Invalid parameters 2",
					&set_link_sec_on_invalid_param_test_2,
					NULL, test_command_generic);
	test_bredrle("Set link security on - Invalid parameters 3",
					&set_link_sec_on_invalid_param_test_3,
					NULL, test_command_generic);
	test_bredrle("Set link security on - Invalid index",
					&set_link_sec_on_invalid_index_test,
					NULL, test_command_generic);

	test_bredrle("Set link security off - Success 1",
					&set_link_sec_off_success_test_1,
					setup_link_sec, test_command_generic);
	test_bredrle("Set link security off - Success 2",
					&set_link_sec_off_success_test_2,
					setup_link_sec_powered,
					test_command_generic);

	test_bredrle("Set SSP on - Success 1", &set_ssp_on_success_test_1,
						NULL, test_command_generic);
	test_bredrle("Set SSP on - Success 2", &set_ssp_on_success_test_2,
					setup_powered, test_command_generic);
	test_bredrle("Set SSP on - Success 3", &set_ssp_on_success_test_3,
					setup_ssp, test_command_generic);
	test_bredrle("Set SSP on - Invalid parameters 1",
					&set_ssp_on_invalid_param_test_1,
					NULL, test_command_generic);
	test_bredrle("Set SSP on - Invalid parameters 2",
					&set_ssp_on_invalid_param_test_2,
					NULL, test_command_generic);
	test_bredrle("Set SSP on - Invalid parameters 3",
					&set_ssp_on_invalid_param_test_3,
					NULL, test_command_generic);
	test_bredrle("Set SSP on - Invalid index",
					&set_ssp_on_invalid_index_test,
					NULL, test_command_generic);

	test_bredrle("Set Low Energy on - Success 1",
			&set_le_on_success_test_1, NULL, test_command_generic);
	test_bredrle("Set Low Energy on - Success 2",
					&set_le_on_success_test_2,
					setup_powered, test_command_generic);
	test_bredrle("Set Low Energy on - Success 3",
					&set_le_on_success_test_3,
					setup_le, test_command_generic);
	test_bredrle("Set Low Energy on - Invalid parameters 1",
					&set_le_on_invalid_param_test_1,
					NULL, test_command_generic);
	test_bredrle("Set Low Energy on - Invalid parameters 2",
					&set_le_on_invalid_param_test_2,
					NULL, test_command_generic);
	test_bredrle("Set Low Energy on - Invalid parameters 3",
					&set_le_on_invalid_param_test_3,
					NULL, test_command_generic);
	test_bredrle("Set Low Energy on - Invalid index",
					&set_le_on_invalid_index_test,
					NULL, test_command_generic);

	test_bredr("Set Local Name - Success 1", &set_local_name_test_1,
						NULL, test_command_generic);
	test_bredr("Set Local Name - Success 2", &set_local_name_test_2,
					setup_powered, test_command_generic);
	test_bredr("Set Local Name - Success 3", &set_local_name_test_3,
				setup_ssp_powered, test_command_generic);

	test_bredrle("Start Discovery - Not powered 1",
				&start_discovery_not_powered_test_1,
				NULL, test_command_generic);
	test_bredrle("Start Discovery - Invalid parameters 1",
				&start_discovery_invalid_param_test_1,
				setup_powered, test_command_generic);
	test_bredrle("Start Discovery - Not supported 1",
				&start_discovery_not_supported_test_1,
				setup_powered, test_command_generic);
	test_bredrle("Start Discovery - Success 1",
				&start_discovery_valid_param_test_1,
				setup_le_powered, test_command_generic);
	test_le("Start Discovery - Success 2",
				&start_discovery_valid_param_test_2,
				setup_powered, test_command_generic);
	test_bredr("Start Discovery (Device Found) - Success 3",
				&start_discovery_valid_param_test_3,
				setup_le_powered, test_command_generic);
	test_le("Start Discovery (Device Found) - Success 4",
				&start_discovery_valid_param_test_4,
				setup_le_powered, test_command_generic);

	test_bredrle("Stop Discovery - Success 1",
				&stop_discovery_success_test_1,
				setup_start_discovery, test_command_generic);
	test_bredr("Stop Discovery - BR/EDR (Inquiry) Success 1",
				&stop_discovery_bredr_success_test_1,
				setup_start_discovery, test_command_generic);
	test_bredr("Stop Discovery (Device Found) - Success 2",
				&stop_discovery_bredr_success_test_2,
				setup_le_powered, test_command_start_discovery);
	test_bredrle("Stop Discovery - Rejected 1",
				&stop_discovery_rejected_test_1,
				setup_le_powered, test_command_generic);
	test_bredrle("Stop Discovery - Invalid parameters 1",
				&stop_discovery_invalid_param_test_1,
				setup_start_discovery, test_command_generic);

	test_bredrle("Set Device Class - Success 1",
				&set_dev_class_valid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set Device Class - Success 2",
				&set_dev_class_valid_param_test_2,
				setup_powered, test_command_generic);
	test_bredrle("Set Device Class - Invalid parameters 1",
				&set_dev_class_invalid_param_test_1,
				NULL, test_command_generic);

	test_bredrle("Add UUID - UUID-16 1", &add_uuid16_test_1,
				setup_ssp_powered, test_command_generic);
	test_bredrle("Add UUID - UUID-16 multiple 1", &add_multi_uuid16_test_1,
				setup_multi_uuid16, test_command_generic);
	test_bredrle("Add UUID - UUID-16 partial 1", &add_multi_uuid16_test_2,
				setup_multi_uuid16_2, test_command_generic);
	test_bredrle("Add UUID - UUID-32 1", &add_uuid32_test_1,
				setup_ssp_powered, test_command_generic);
	test_bredrle("Add UUID - UUID-32 multiple 1", &add_uuid32_multi_test_1,
				setup_multi_uuid32, test_command_generic);
	test_bredrle("Add UUID - UUID-32 partial 1", &add_uuid32_multi_test_2,
				setup_multi_uuid32_2, test_command_generic);
	test_bredrle("Add UUID - UUID-128 1", &add_uuid128_test_1,
				setup_ssp_powered, test_command_generic);
	test_bredrle("Add UUID - UUID-128 multiple 1",
				&add_uuid128_multi_test_1, setup_multi_uuid128,
				test_command_generic);
	test_bredrle("Add UUID - UUID-128 partial 1", &add_uuid128_multi_test_2,
				setup_multi_uuid128_2, test_command_generic);
	test_bredrle("Add UUID - UUID mix", &add_uuid_mix_test_1,
				setup_uuid_mix, test_command_generic);

	test_bredrle("Load Link Keys - Empty List Success 1",
			&load_link_keys_success_test_1, NULL,
			test_command_generic);
	test_bredrle("Load Link Keys - Empty List Success 2",
			&load_link_keys_success_test_2, NULL,
			test_command_generic);
	test_bredrle("Load Link Keys - Invalid Parameters 1",
			&load_link_keys_invalid_params_test_1, NULL,
			test_command_generic);
	test_bredrle("Load Link Keys - Invalid Parameters 2",
			&load_link_keys_invalid_params_test_2, NULL,
			test_command_generic);
	test_bredrle("Load Link Keys - Invalid Parameters 3",
			&load_link_keys_invalid_params_test_3, NULL,
			test_command_generic);

	test_bredrle("Load Long Term Keys - Success 1",
			&load_ltks_success_test_1, NULL, test_command_generic);
	test_bredrle("Load Long Term Keys - Invalid Parameters 1",
			&load_ltks_invalid_params_test_1, NULL,
			test_command_generic);
	test_bredrle("Load Long Term Keys - Invalid Parameters 2",
			&load_ltks_invalid_params_test_2, NULL,
			test_command_generic);
	test_bredrle("Load Long Term Keys - Invalid Parameters 3",
			&load_ltks_invalid_params_test_3, NULL,
			test_command_generic);
	test_bredrle("Load Long Term Keys - Invalid Parameters 4",
			&load_ltks_invalid_params_test_4, NULL,
			test_command_generic);

	test_bredrle("Pair Device - Not Powered 1",
			&pair_device_not_powered_test_1, NULL,
			test_command_generic);
	test_bredrle("Pair Device - Invalid Parameters 1",
			&pair_device_invalid_param_test_1, NULL,
			test_command_generic);

	test_bredrle("Unpair Device - Not Powered 1",
			&unpair_device_not_powered_test_1, NULL,
			test_command_generic);
	test_bredrle("Unpair Device - Invalid Parameters 1",
			&unpair_device_invalid_param_test_1, NULL,
			test_command_generic);
	test_bredrle("Unpair Device - Invalid Parameters 2",
			&unpair_device_invalid_param_test_2, NULL,
			test_command_generic);

	test_bredrle("Disconnect - Invalid Parameters 1",
			&disconnect_invalid_param_test_1, NULL,
			test_command_generic);

	test_bredrle("Block Device - Invalid Parameters 1",
			&block_device_invalid_param_test_1, NULL,
			test_command_generic);

	test_bredrle("Unblock Device - Invalid Parameters 1",
			&unblock_device_invalid_param_test_1, NULL,
			test_command_generic);

	return tester_run();
}
