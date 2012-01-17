/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Nokia Corporation
 *  Copyright (C) 2012  Marcel Holtmann <marcel@holtmann.org>
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

#include "adapter.h"
#include "log.h"
#include "manager.h"
#include "server.h"

static int time_server_probe(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("path %s", path);

	return time_server_register(adapter);
}

static void time_server_remove(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("path %s", path);
}

struct btd_adapter_driver time_server_driver = {
	.name = "gatt-time-server",
	.probe = time_server_probe,
	.remove = time_server_remove,
};

int time_manager_init(void)
{
	if (time_server_init() < 0) {
		error("Could not initialize GATT Time server");
		return -EIO;
	}

	btd_register_adapter_driver(&time_server_driver);

	return 0;
}

void time_manager_exit(void)
{
	btd_unregister_adapter_driver(&time_server_driver);

	time_server_exit();
}
