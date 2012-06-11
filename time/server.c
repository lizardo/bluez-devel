/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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
#include <time.h>
#include <errno.h>
#include <bluetooth/uuid.h>
#include <adapter.h>

#include "gattrib.h"
#include "att.h"
#include "gatt.h"
#include "att-database.h"
#include "attrib-server.h"
#include "gatt-service.h"
#include "log.h"
#include "server.h"

#define CURRENT_TIME_SVC_UUID		0x1805
#define REF_TIME_UPDATE_SVC_UUID	0x1806

#define LOCAL_TIME_INFO_CHR_UUID	0x2A0F
#define TIME_UPDATE_CTRL_CHR_UUID	0x2A16
#define TIME_UPDATE_STAT_CHR_UUID	0x2A17
#define CT_TIME_CHR_UUID		0x2A2B

static int encode_current_time(uint8_t value[10])
{
	struct timespec tp;
	struct tm tm;

	if (clock_gettime(CLOCK_REALTIME, &tp) == -1) {
		int err = -errno;

		error("clock_gettime: %s", strerror(-err));
		return err;
	}

	if (localtime_r(&tp.tv_sec, &tm) == NULL) {
		error("localtime_r() failed");
		/* localtime_r() does not set errno */
		return -EINVAL;
	}

	att_put_u16(1900 + tm.tm_year, &value[0]); /* Year */
	value[2] = tm.tm_mon + 1; /* Month */
	value[3] = tm.tm_mday; /* Day */
	value[4] = tm.tm_hour; /* Hours */
	value[5] = tm.tm_min; /* Minutes */
	value[6] = tm.tm_sec; /* Seconds */
	value[7] = tm.tm_wday == 0 ? 7 : tm.tm_wday; /* Day of Week */
	/* From Time Profile spec: "The number of 1/256 fractions of a second."
	 * In 1s there are 256 fractions, in 1ns there are 256/10^9 fractions.
	 * To avoid integer overflow, we use the equivalent 1/3906250 ratio. */
	value[8] = tp.tv_nsec / 3906250; /* Fractions256 */
	value[9] = 0x00; /* Adjust Reason */

	return 0;
}

static uint8_t current_time_read(struct attribute *a,
				 struct btd_device *device, gpointer user_data)
{
	struct btd_adapter *adapter = user_data;
	uint8_t value[10];

	if (encode_current_time(value) < 0)
		return ATT_ECODE_IO;

	attrib_db_update(adapter, a->handle, NULL, value, sizeof(value), NULL);

	return 0;
}

static uint8_t local_time_info_read(struct attribute *a,
				struct btd_device *device, gpointer user_data)
{
	struct btd_adapter *adapter = user_data;
	uint8_t value[2];

	DBG("a=%p", a);

	tzset();

	/* FIXME: POSIX "daylight" variable only indicates whether there is DST
	 * for the local time or not. The offset is unknown. */
	value[0] = daylight ? 0xff : 0x00;

	/* Convert POSIX "timezone" (seconds West of GMT) to Time Profile
	 * format (offset from UTC in number of 15 minutes increments). */
	value[1] = (uint8_t) (-1 * timezone / (60 * 15));

	attrib_db_update(adapter, a->handle, NULL, value, sizeof(value), NULL);

	return 0;
}

static gboolean register_current_time_service(struct btd_adapter *adapter)
{
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, CURRENT_TIME_SVC_UUID);

	/* Current Time service */
	return gatt_service_add(adapter, GATT_PRIM_SVC_UUID, &uuid,
				/* CT Time characteristic */
				GATT_OPT_CHR_UUID, CT_TIME_CHR_UUID,
				GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ |
							ATT_CHAR_PROPER_NOTIFY,
				GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
						current_time_read, adapter,

				/* Local Time Information characteristic */
				GATT_OPT_CHR_UUID, LOCAL_TIME_INFO_CHR_UUID,
				GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ,
				GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
						local_time_info_read, adapter,

				GATT_OPT_INVALID);
}

static uint8_t time_update_control(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	DBG("handle 0x%04x", a->handle);

	if (a->len != 1) {
		DBG("Invalid control point value size: %d", a->len);
		return 0;
	}

	return time_provider_control(a->data[0]);
}

static uint8_t time_update_status(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	struct btd_adapter *adapter = user_data;
	uint8_t value[2];

	DBG("handle 0x%04x", a->handle);

	time_provider_status(&value[0], &value[1]);

	attrib_db_update(adapter, a->handle, NULL, value, sizeof(value), NULL);

	return 0;
}

static gboolean register_ref_time_update_service(struct btd_adapter *adapter)
{
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, REF_TIME_UPDATE_SVC_UUID);

	/* Reference Time Update service */
	return gatt_service_add(adapter, GATT_PRIM_SVC_UUID, &uuid,
				/* Time Update control point */
				GATT_OPT_CHR_UUID, TIME_UPDATE_CTRL_CHR_UUID,
				GATT_OPT_CHR_PROPS,
					ATT_CHAR_PROPER_WRITE_WITHOUT_RESP,
				GATT_OPT_CHR_VALUE_CB, ATTRIB_WRITE,
						time_update_control, adapter,

				/* Time Update status */
				GATT_OPT_CHR_UUID, TIME_UPDATE_STAT_CHR_UUID,
				GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ,
				GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
						time_update_status, adapter,

				GATT_OPT_INVALID);
}

int time_server_register(struct btd_adapter *adapter)
{
	if (!register_current_time_service(adapter)) {
		error("Current Time Service could not be registered");
		return -EIO;
	}

	if (!register_ref_time_update_service(adapter)) {
		error("Reference Time Update Service could not be registered");
		return -EIO;
	}

	return 0;
}

int time_server_init(void)
{
	if (time_provider_init() < 0)
		return -1;

	return 0;
}

void time_server_exit(void)
{
	time_provider_exit();
}
