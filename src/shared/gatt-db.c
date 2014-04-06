/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Instituto Nokia de Tecnologia - INdT
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

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "lib/uuid.h"
#include "src/shared/gatt-db.h"

struct gatt_db *gatt_db_new(void)
{
	/* TODO */
	return NULL;
}

void gatt_db_destroy(struct gatt_db *db)
{
	/* TODO */
}

uint16_t gatt_db_new_service(struct gatt_db *db, const bt_uuid_t *uuid,
							unsigned int num_attrs)
{
	/* TODO */
	return 0x0000;
}

uint16_t gatt_db_new_characteristic(struct gatt_db *db, uint16_t service_handle,
					const bt_uuid_t *uuid,
					uint8_t properties,
					gatt_db_read_func_t read_cb,
					gatt_db_write_func_t write_cb)
{
	/* TODO */
	return 0x0000;
}

uint16_t gatt_db_new_descriptor(struct gatt_db *db, uint16_t char_handle,
					const bt_uuid_t *uuid,
					gatt_db_read_func_t read_cb,
					gatt_db_write_func_t write_cb)
{
	/* TODO */
	return 0x0000;
}

bool gatt_db_start_service(struct gatt_db *db, uint16_t service_handle)
{
	/* TODO */
	return false;
}

bool gatt_db_stop_service(struct gatt_db *db, uint16_t service_handle)
{
	/* TODO */
	return false;
}

bool gatt_db_remove_service(struct gatt_db *db, uint16_t service_handle)
{
	/* TODO */
	return false;
}