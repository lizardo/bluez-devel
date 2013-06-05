/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdbool.h>
#include <stdint.h>

struct hciemu;

enum hciemu_type {
	HCIEMU_TYPE_BREDRLE,
	HCIEMU_TYPE_BREDR,
	HCIEMU_TYPE_LE,
};

struct hciemu *hciemu_new(enum hciemu_type type);

struct hciemu *hciemu_ref(struct hciemu *hciemu);
void hciemu_unref(struct hciemu *hciemu);

void hciemu_l2cap_cmd(struct hciemu *hciemu, uint16_t handle, uint8_t code,
				uint8_t ident, const void *data, uint16_t len);

void hciemu_client_connect(struct hciemu *hciemu, const uint8_t *bdaddr);

typedef void (*hciemu_new_conn_cb) (uint16_t handle, void *user_data);

void hciemu_set_new_conn_cb(struct hciemu *hciemu, hciemu_new_conn_cb cb,
							void *user_data);

typedef void (*hciemu_scan_enable_cb)(uint8_t status, void *user_data);

void hciemu_client_scan_enable(struct hciemu *hciemu, uint8_t scan,
				hciemu_scan_enable_cb cb, void *user_data);

void hciemu_client_set_server_psm(struct hciemu *hciemu, uint16_t psm);

const char *hciemu_get_address(struct hciemu *hciemu);

const uint8_t *hciemu_get_master_bdaddr(struct hciemu *hciemu);
const uint8_t *hciemu_get_client_bdaddr(struct hciemu *hciemu);

typedef bool (*hciemu_command_func_t)(uint16_t opcode, const void *data,
						uint8_t len, void *user_data);

bool hciemu_add_master_post_command_hook(struct hciemu *hciemu,
			hciemu_command_func_t function, void *user_data);
