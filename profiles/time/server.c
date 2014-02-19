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

#include "src/adapter.h"
#include "src/device.h"
#include "src/plugin.h"

#include "lib/uuid.h"
#include "attrib/gattrib.h"
#include "attrib/att.h"
#include "attrib/gatt.h"
#include "src/gatt.h"
#include "src/log.h"

#define CURRENT_TIME_SVC_UUID		0x1805
#define REF_TIME_UPDATE_SVC_UUID	0x1806

#define LOCAL_TIME_INFO_CHR_UUID	0x2A0F
#define TIME_UPDATE_CTRL_CHR_UUID	0x2A16
#define TIME_UPDATE_STAT_CHR_UUID	0x2A17
#define CT_TIME_CHR_UUID		0x2A2B

enum {
	UPDATE_RESULT_SUCCESSFUL = 0,
	UPDATE_RESULT_CANCELED = 1,
	UPDATE_RESULT_NO_CONN = 2,
	UPDATE_RESULT_ERROR = 3,
	UPDATE_RESULT_TIMEOUT = 4,
	UPDATE_RESULT_NOT_ATTEMPTED = 5,
};

enum {
	UPDATE_STATE_IDLE = 0,
	UPDATE_STATE_PENDING = 1,
};

enum {
	GET_REFERENCE_UPDATE = 1,
	CANCEL_REFERENCE_UPDATE = 2,
};

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

static void current_time_read(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{
	uint8_t value[10];
	int err;

	err = encode_current_time(value);
	if (err < 0) {
		result(-err, NULL, 0, user_data);
		return;
	}

	result(0, value, sizeof(value), user_data);
}

static void local_time_info_read(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{
	uint8_t value[2];

	tzset();

	/* Convert POSIX "timezone" (seconds West of GMT) to Time Profile
	 * format (offset from UTC in number of 15 minutes increments). */
	value[0] = (uint8_t) (-1 * timezone / (60 * 15));

	/* FIXME: POSIX "daylight" variable only indicates whether there
	 * is DST for the local time or not. The offset is unknown. */
	value[1] = daylight ? 0xff : 0x00;

	result(0, value, sizeof(value), user_data);
}

static void register_current_time_service(void)
{
	struct btd_attribute *attr;
	bt_uuid_t uuid;

	/* Current Time service */
	bt_uuid16_create(&uuid, CURRENT_TIME_SVC_UUID);
	attr = btd_gatt_add_service(&uuid);
	if (!attr)
		return;

	/* CT Time characteristic */
	bt_uuid16_create(&uuid, CT_TIME_CHR_UUID);
	if (!btd_gatt_add_char(&uuid, GATT_CHR_PROP_READ | GATT_CHR_PROP_NOTIFY,
						current_time_read, NULL)) {
		btd_gatt_remove_service(attr);
		return;
	}

	/* Local Time Information characteristic */
	bt_uuid16_create(&uuid, LOCAL_TIME_INFO_CHR_UUID);
	if (!btd_gatt_add_char(&uuid, GATT_CHR_PROP_READ, local_time_info_read,
									NULL)) {
		btd_gatt_remove_service(attr);
		return;
	}
}

static void time_update_control(struct btd_device *device,
				struct btd_attribute *attr,
				const uint8_t *value, size_t len,
				btd_attr_write_result_t result, void *user_data)
{
	int err = 0;

	if (len != 1) {
		DBG("Invalid control point value size: %zu", len);
		err = EINVAL;
		goto done;
	}

	switch (value[0]) {
	case GET_REFERENCE_UPDATE:
		DBG("Get Reference Update");
		break;
	case CANCEL_REFERENCE_UPDATE:
		DBG("Cancel Reference Update");
		break;
	default:
		DBG("Unknown command: 0x%02x", value[0]);
		err = EINVAL;
	}

done:
	result(err, user_data);
}

static void time_update_status(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{
	uint8_t value[2];

	value[0] = UPDATE_STATE_IDLE;
	value[1] = UPDATE_RESULT_SUCCESSFUL;

	result(0, value, sizeof(value), user_data);
}

static void register_ref_time_update_service(void)
{
	struct btd_attribute *attr;
	bt_uuid_t uuid;

	/* Reference Time Update service */
	bt_uuid16_create(&uuid, REF_TIME_UPDATE_SVC_UUID);
	attr = btd_gatt_add_service(&uuid);
	if (!attr)
		return;

	/* Time Update control point */
	bt_uuid16_create(&uuid, TIME_UPDATE_CTRL_CHR_UUID);
	if (!btd_gatt_add_char(&uuid, GATT_CHR_PROP_WRITE_WITHOUT_RESP,
						NULL, time_update_control)) {
		btd_gatt_remove_service(attr);
		return;
	}

	/* Time Update status */
	bt_uuid16_create(&uuid, TIME_UPDATE_STAT_CHR_UUID);
	if (!btd_gatt_add_char(&uuid, GATT_CHR_PROP_READ, time_update_status,
									NULL)) {
		btd_gatt_remove_service(attr);
		return;
	}
}

static int time_init(void)
{
	register_current_time_service();
	register_ref_time_update_service();

	return 0;
}

static void time_exit(void)
{
}

BLUETOOTH_PLUGIN_DEFINE(time, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			time_init, time_exit)
