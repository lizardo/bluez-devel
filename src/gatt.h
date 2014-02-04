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
 * Callbacks from this type are called once the value from the attribute is
 * ready to be read.
 * @err:	error in errno format.
 * @value:	pointer to value
 * @len:	length of value
 * @user_data:	user_data passed in btd_attr_read_t callback
 */
typedef void (*btd_attr_read_result_t) (int err, uint8_t *value, size_t len,
							void *user_data);
typedef void (*btd_attr_read_t) (struct btd_device *device,
						struct btd_attribute *attr,
						btd_attr_read_result_t result,
						void *user_data);
/*
 * Callbacks from this type are called once the value from the attribute was
 * written.
 * @err:	error in errno format.
 * @user_data:	user_data passed in btd_attr_write_t callback
 */
typedef void (*btd_attr_write_result_t) (int err, void *user_data);
typedef void (*btd_attr_write_t) (struct btd_device *device,
					struct btd_attribute *attr,
					const uint8_t *value, size_t len,
					btd_attr_write_result_t result,
					void *user_data);

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
struct btd_attribute *btd_gatt_add_char(bt_uuid_t *uuid, uint8_t properties,
						btd_attr_read_t read_cb,
						btd_attr_write_t write_cb);

/* btd_gatt_add_char_desc - Add a characteristic descriptor to local attribute
 * database.
 * @uuid:	Characteristic Descriptor UUID (16-bits or 128-bits).
 * @read_cb:	Callback that should be called once the characteristic
 *		descriptor attribute is read.
 * @write_cb:	Callback that should be called once the characteristic
 *		descriptor attribute is written.
 *
 * Returns a reference to characteristic descriptor attribute. In case of
 * error, NULL is returned.
 */
struct btd_attribute *btd_gatt_add_char_desc(bt_uuid_t *uuid,
						btd_attr_read_t read_cb,
						btd_attr_write_t write_cb);

/* btd_gatt_read_attribute - Read the value of an attribute.
 * @attr:	Attribute to be read.
 * @result:	Callback function to be called with the result.
 * @user_data:	Data to be passed to the result callback function.
 */
void btd_gatt_read_attribute(struct btd_attribute *attr,
					btd_attr_read_result_t result,
					void *user_data);

/* btd_gatt_write_attribute - Write the value of an attribute.
 * @attr:	Attribute to be written.
 * @value:	Value to be written.
 * @len:	Length of the value.
 * @result:	Callback function to be called with the result.
 * @user_data:	Data to be passed to the result callback function.
 */
void btd_gatt_write_attribute(struct btd_attribute *attr,
				uint8_t *value, size_t len,
				btd_attr_write_result_t result,
				void *user_data);

/* btd_gatt_database_for_each - Iterate over each attribute on the local
 * attribute database.
 * @func:	Callback called for each attribute on the database.
 * @user_data:	Data to be passed to the callback function.
 */
typedef void (*btd_attr_func_t) (struct btd_attribute *attr, uint16_t handle,
				bt_uuid_t *type, btd_attr_read_t read_cb,
				btd_attr_write_t write_cb, uint16_t value_len,
				uint8_t *value, void *user_data);
void btd_gatt_database_for_each(btd_attr_func_t func, void *user_data);
