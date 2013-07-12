/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

struct btd_attribute;

typedef void (*btd_attr_read_result_t) (int err, uint8_t *value, size_t len,
					void *user_data);
typedef void (*btd_attr_read_t) (struct btd_device *device,
					btd_attr_read_result_t result,
					void *user_data);

typedef void (*btd_attr_write_result_t) (int err, void *user_data);
typedef void (*btd_attr_write_t) (struct btd_device *device, uint8_t *value,
					size_t len, uint16_t offset,
					btd_attr_write_result_t result,
					void *user_data);

typedef void (*btd_attr_value_t) (uint8_t *value, size_t len, void *user_data);

void btd_gatt_service_manager_init(void);

void btd_gatt_service_manager_cleanup(void);

void gatt_discover_attributes(struct btd_device *device);

/* btd_gatt_add_service - Add a service declaration to local attribute database.
 * @uuid:	Service UUID.
 * @primary:	Set to 'true' if this is a primary services. Otherwise, it will
 *		be declared as a secondary service.
 *
 *
 * Returns a reference to service declaration attribute. In case of error,
 * NULL is returned.
 */
struct btd_attribute *btd_gatt_add_service(bt_uuid_t *uuid, bool primary);

/* btd_gatt_remove_service - Remove a service (along with all its
 * characteristics) from the local attribute database.
 * @service:	Service declaration attribute.
 */
void btd_gatt_remove_service(struct btd_attribute *service);

/* btd_gatt_add_char- Add a characteristic (declaration and value attributes)
 * to local attribute database.
 * @uuid:	Characteristic UUID.
 * @properties:	Characteristic properties.
 * @read_cb:	Callback that should be called once the characteristic value
 *		attribute is read.
 * @write_cb:	Callback that should be called once the characteristic value
 *		attribute is written.
 *
 * Returns a reference to characteristic value attribute. In case of error,
 * NULL is returned.
 */
struct btd_attribute *btd_gatt_add_char(bt_uuid_t *uuid, uint8_t properties,
					btd_attr_read_t read_cb,
					btd_attr_write_t write_cb);

/* btd_gatt_add_char_desc - Add a characteristic descriptor to local attribute
 * database.
 * @uuid:	Characteristic UUID.
 * @read_cb:	Callback that should be called once the characteristic
 *		descriptor attribute is read.
 * @write_cb:	Callback that should be called once the characteristic
 *		descriptor attribute is written.
 */
void btd_gatt_add_char_desc(bt_uuid_t *uuid, btd_attr_read_t read_cb,
				btd_attr_write_t write_cb);

/* btd_gatt_get_services - Get a list with all services whose UUID matches the
 * searched one.
 * @database:	List of attributes where the services will be searched.
 * @service:	Service UUID.
 *
 * Returns a list with all services' attributes. If there is no services,
 * NULL is returned.
 */
GSList *btd_gatt_get_services(GList *database, bt_uuid_t *service);

/* btd_gatt_get_chars_decl - Get a list with all characteristics of the
 * specified type in the specified service.
 * @database:	List of attributes where the characteristics will be searched.
 * @service:	Service declaration.
 * @type:	Characteristic type.
 *
 * Returns a list with all characteristics' attributes. If there is no
 * characteristic, NULL is returned.
 */
GSList *btd_gatt_get_chars_decl(GList *database, struct btd_attribute *service,
				bt_uuid_t *type);

/* btd_gatt_get_char_desc - Get the specified descriptor of the specified
 * characteristic.
 * @database:	List of attributes where the descriptor will be searched.
 * @chr:	Characteristic declaration.
 * @type:	Descriptor type.
 *
 * Returns the characteristic descriptor declaration attribute. If there
 * is no such descriptor, NULL is returned.
 */
struct btd_attribute *btd_gatt_get_char_desc(GList *database,
						struct btd_attribute *chr,
						bt_uuid_t *type);

/* btd_gatt_get_char_value - Get the characteristic value declaration of a
 * characteristic.
 * @database:	List of attributes where the descriptor will be searched.
 * @chr:	Characteristic declaration.
 *
 * Returns the characteristic value declaration attribute. If there is no
 * such attribute, NULL is returned.
 */
struct btd_attribute *btd_gatt_get_char_value(GList *database,
						struct btd_attribute *chr);

/* btd_gatt_read_attribute - Read the value of an attribute.
 * @attr:	Attribute to be read.
 * @result:	Callback function to be called with the result.
 * @user_data:	Data to be passed to the result callback function.
 */
void btd_gatt_read_attribute(struct btd_device *device,
					struct btd_attribute *attr,
					btd_attr_read_result_t result,
					void *user_data);

/* btd_gatt_write_attribute - Write the value of an attribute.
 * @attr:	Attribute to be written.
 * @value:	Value to be written.
 * @len:	Length of the value.
 * @offset:	Offset of the value.
 * @result:	Callback function to be called with the result.
 * @user_data:	Data to be passed to the result callback function.
 */
void btd_gatt_write_attribute(struct btd_device *device,
				struct btd_attribute *attr,
				uint8_t *value, size_t len, uint16_t offset,
				btd_attr_write_result_t result,
				void *user_data);

/* btd_gatt_add_notifier - Add a notifier to an attribute.
 * @attr:	Target attribute.
 * @value_cb:	Callback function to be called when notify.
 * @user_data:	Data to be passed to the value_cb callback function.
 */
unsigned int btd_gatt_add_notifier(struct btd_attribute *attr,
						btd_attr_value_t value_cb,
						void *user_data);

/* btd_gatt_remove_notifier - Remove a notifier from an attribute.
 * @attr:	Target attribute.
 * @id:		Notifier ID.
 */
void btd_gatt_remove_notifier(struct btd_attribute *attr, unsigned int id);
