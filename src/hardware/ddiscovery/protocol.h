/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2023 Marc Font Freixa <marc@bz17.dev>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBSIGROK_HARDWARE_DDISCOVERY_PROTOCOL_H
#define LIBSIGROK_HARDWARE_DDISCOVERY_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "ddiscovery"

#define  DDISCOVERY_STATE_READY        0
#define  DDISCOVERY_STATE_CONFIG       4
#define  DDISCOVERY_STATE_PREFILL      5
#define  DDISCOVERY_STATE_ARMED        1
#define  DDISCOVERY_STATE_WAIT         7
#define  DDISCOVERY_STATE_TRIGGERED    3
#define  DDISCOVERY_STATE_RUNNING      3
#define  DDISCOVERY_STATE_DONE         2

struct dev_context {
	struct ftdi_context *ftdic;
    uint8_t  status;                    /* Device status */

	uint8_t  *data_buf;                 /* Data buffer pointer */
	uint32_t data_buf_size;
 
    uint8_t  bytes_per_sample;          /* Number of bytes per sample (depends on channels configured) */
	uint32_t samples_recorded;          /* Number of samples recorded in the device*/
	uint32_t samples_recorded_overflow; /* Flag to know that device have reached the limits of samples counter */ 
	uint32_t samples_available;         /* Number of samples available in the device memory */
	uint32_t samples_pre_trigger;       /* Number of samples in pre trigger */
	uint32_t samples_post_trigger;      /* Number of samples post trigger   */
	uint32_t read_samples_threshold;    /* Read samples threshold */
	gboolean triggers_en;               /* Triggers enabled */

	uint32_t trigger_start_offset;      /* Offset where pre-trigger start */
	uint32_t pending_bytes_to_read;     /* Number of pending bytes to read */
	uint32_t bytes_read;                /* Number of bytes read */

	uint64_t limit_samples;             /* Limit of samples */
    uint64_t cur_samplerate;            /* Sample rate */
    uint64_t capture_ratio;             /* Pre trigger post trigger ratio */

    uint32_t  num_channels;             /* Number of channels used to capture */
};

SR_PRIV int ddiscovery_init(const struct sr_dev_inst *sdi);
SR_PRIV int ddiscovery_prepare(const struct sr_dev_inst *sdi);
SR_PRIV int ddiscovery_start(const struct sr_dev_inst *sdi);
SR_PRIV int ddiscovery_stop(const struct sr_dev_inst *sdi);
SR_PRIV int ddiscovery_read_data(int fd, int revents, void *cb_data);

#endif
