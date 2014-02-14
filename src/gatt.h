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

struct btd_attribute;

void gatt_init(void);

void gatt_cleanup(void);

/*
 * Read operation result callback. Called from the service implementation
 * informing the core (ATT layer) the result of read operation.
 * @err:	error in -errno format.
 * @value:	value of the attribute read.
 * @len:	length of value.
 * @user_data:	user_data passed in btd_attr_read_t callback.
 */
typedef void (*btd_attr_read_result_t) (int err, uint8_t *value, size_t len,
							void *user_data);
/*
 * Service implementation callback passed to core (ATT layer). It manages read
 * operations received from remote devices.
 * @attr:	reference of the attribute to be read.
 * @result:	callback called from the service implementation informing the
 *		value of attribute read.
 * @user_data:	user_data passed in btd_attr_read_result_t callback.
 */
typedef void (*btd_attr_read_t) (struct btd_attribute *attr,
						btd_attr_read_result_t result,
						void *user_data);

/*
 * Write operation result callback. Called from the service implementation
 * informing the core (ATT layer) the result of the write operation. It is used
 * to manage Write Request operations.
 * @err:	error in -errno format.
 * @user_data:	user_data passed in btd_attr_write_t callback.
 */
typedef void (*btd_attr_write_result_t) (int err, void *user_data);
/*
 * Service implementation callback passed to core (ATT layer). It manages write
 * operations received from remote devices.
 * @attr:	reference of the attribute to be changed.
 * @value:	new attribute value.
 * @len:	length of value.
 * @result:	callback called from the service implementation informing the
 *		result of the write operation.
 * @user_data:	user_data passed in btd_attr_write_result_t callback.
 */
typedef void (*btd_attr_write_t) (struct btd_attribute *attr,
					const uint8_t *value, size_t len,
					btd_attr_write_result_t result,
					void *user_data);

/*
 * Callback called on each attribute from the local database when using
 * btd_gatt_database_for_each().
 * @attr:	attribute for the current iteration.
 * @handle:	attribute handle.
 * @type:	attribute type UUID.
 * @read_cb:	read callback associated with this attribute.
 * @write_cb:	write callback associated with this attribute.
 * @value_len:	attribute value length (for static attributes).
 * @value:	attribute value (for static attributes).
 * @user_data:	user_data provided by btd_gatt_database_for_each() caller.
 */
typedef void (*btd_attr_func_t) (struct btd_attribute *attr, uint16_t handle,
				bt_uuid_t *type, btd_attr_read_t read_cb,
				btd_attr_write_t write_cb, uint16_t value_len,
				uint8_t *value, void *user_data);

/* btd_gatt_add_service - Add a service declaration to local attribute database.
 * @uuid:	Service UUID.
 *
 * Returns a reference to service declaration attribute. In case of error,
 * NULL is returned.
 */
struct btd_attribute *btd_gatt_add_service(const bt_uuid_t *uuid);

/* btd_gatt_remove_service - Remove a service (along with all its
 * characteristics) from the local attribute database.
 * @service:	Service declaration attribute.
 */
void btd_gatt_remove_service(struct btd_attribute *service);

/*
 * btd_gatt_add_char - Add a characteristic (declaration and value attributes)
 * to local attribute database.
 * @uuid:	Characteristic UUID (16-bits or 128-bits).
 * @properties:	Characteristic properties. See Core SPEC 4.1 page 2183.
 * @read_cb:	Callback used to provide the characteristic value.
 * @write_cb:	Callback called to notify the implementation that a new value
 *              is available.
 *
 * Returns a reference to characteristic value attribute. In case of error,
 * NULL is returned.
 */
struct btd_attribute *btd_gatt_add_char(const bt_uuid_t *uuid,
						uint8_t properties,
						btd_attr_read_t read_cb,
						btd_attr_write_t write_cb);

/* btd_gatt_database_for_each - Iterate over each attribute on the local
 * attribute database.
 * @func:	Callback called for each attribute on the database.
 * @user_data:	Data to be passed to the callback function.
 */
void btd_gatt_database_for_each(btd_attr_func_t func, void *user_data);

/* btd_gatt_database_notify_update - Set callbacks for notifying callers when
 * an attribute is added or removed from the database.
 * @attr_added:		Callback called when attribute is added to the database.
 * @attr_removed:	Callback called when attribute is removed from database.
 * @user_data:		Data to be passed to the callback functions.
 */
void btd_gatt_database_notify_update(btd_attr_func_t attr_added,
						btd_attr_func_t attr_removed,
						void *user_data);

/* btd_gatt_get_svc_range - Get start and end attribute handles for the first
 * service matching given UUID.
 * @uuid:	Service UUID.
 */
void btd_gatt_get_svc_range(bt_uuid_t *uuid, uint16_t *start, uint16_t *end);
