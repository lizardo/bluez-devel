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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>

#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "log.h"
#include "notify.h"

/* Some systems lack this flag on <sys/timerfd.h> */
#ifndef TFD_TIMER_CANCEL_ON_SET
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

static GIOChannel *rtc_watch_io = NULL;

static gboolean timer_event_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	uint64_t nexp;
	ssize_t len;
	int fd;

	if (cond & (G_IO_ERR | G_IO_NVAL))
		goto failed;

	fd = g_io_channel_unix_get_fd(io);
	len = read(fd, &nexp, sizeof(nexp));
	if (len == -1 && errno == ECANCELED) {
		struct timespec now;

		if (clock_gettime(CLOCK_REALTIME, &now) == -1) {
			error("Could not read RTC: %s (%d)", strerror(errno),
									errno);
			goto failed;
		}

		/* FIXME: notify new time */
		DBG("Time changed to: %s", ctime(&now.tv_sec));
	} else if (len != sizeof(nexp)) {
		error("Could not read from timer object: %s (%d)",
							strerror(errno), errno);
		goto failed;
	} else
		DBG("Number of timer expirations: %" PRId64, nexp);

	return TRUE;

failed:
	g_io_channel_unref(rtc_watch_io);
	rtc_watch_io = NULL;

	return FALSE;
}

int monitor_rtc_init(void)
{
	struct itimerspec new_value;
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_NVAL;
	int fd;

	fd = timerfd_create(CLOCK_REALTIME, 0);
	if (fd == -1) {
		int err = -errno;

		error("Could not create timer object: %s (%d)", strerror(-err),
									-err);

		return err;
	}

	memset(&new_value, 0, sizeof(new_value));

	if (timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
						&new_value, NULL) == -1) {
		int err = -errno;

		error("Could not arm timer object: %s (%d)", strerror(-err),
									-err);
		close(fd);

		return err;
	}

	rtc_watch_io = g_io_channel_unix_new(fd);
	g_io_channel_set_encoding(rtc_watch_io, NULL, NULL);
	g_io_channel_set_close_on_unref(rtc_watch_io, TRUE);
	g_io_add_watch(rtc_watch_io, cond, timer_event_cb, NULL);

	return 0;
}

void monitor_rtc_exit(void)
{
	g_io_channel_unref(rtc_watch_io);
	rtc_watch_io = NULL;
}
