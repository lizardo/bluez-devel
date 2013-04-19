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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>

#include "plugin.h"
#include "lib/uuid.h"

/* Attribute access permissions (modes) */
typedef enum {
	ATT_PERM_READ,		/* read-only */
	ATT_PERM_WRITE,		/* write-only */
	ATT_PERM_RDWR,		/* read-write */
} access_mode_t;

struct gatt_characteristic {
	bt_uuid_t uuid;
	uint8_t properties;
	uint16_t ext_properties;	/* extended properties */

	access_mode_t access_modes;	/* access modes for attribute */
	access_mode_t authentication;	/* modes requiring authentication */
	access_mode_t authorization;	/* modes requiring authorization */
	access_mode_t encryption;	/* modes requiring encryption */

	GSList *descriptors;	/* profile specific descriptors */
};

static int gatt_external_init(void)
{
	return 0;
}

static void gatt_external_exit(void)
{
}

BLUETOOTH_PLUGIN_DEFINE(gatt_external, VERSION,
					BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
					gatt_external_init, gatt_external_exit)
