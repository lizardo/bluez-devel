/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
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

struct att_notif_ind;

typedef void (*att_confirm_cb) (struct att_notif_ind *notif_ind,
				struct btd_device *device, void *user_data);

struct att_notif_ind *att_create_notif_ind(struct btd_adapter *adapter,
							uint16_t value_handle,
							uint16_t ccc_handle);
void att_destroy_notif_inds(struct btd_adapter *adapter);
int att_send_notification(struct att_notif_ind *notif_ind, const uint8_t *value,
								size_t len);
int att_send_indication(struct att_notif_ind *notif_ind, const uint8_t *value,
				size_t len, att_confirm_cb cb, void *user_data);
