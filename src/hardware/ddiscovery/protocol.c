/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2017 Jan Luebbe <jluebbe@lasnet.de>
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

#include <config.h>
#include <string.h>
#include "protocol.h"

#include "frames.c"

#define CONFIG_USE_8_CH  0
#define CONFIG_USE_16_CH 1
#define CONFIG_USE_32_CH 2

#define DATA_BUF_SIZE               (16u * 1024u * 1024u)
#define FPGA_CLOCK                  SR_MHZ(800u)
#define FRAME_STATUS_RESPONSE_SIZE  24u
//#define DEBUG_FRAMES

static inline int ddiscovery_write(struct ftdi_context *ftdi, const uint8_t *buf, int size) {
#ifdef DEBUG_FRAMES
    int i;
    printf("-> ");
    for (i=0; i < size; i ++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
#endif
    return ftdi_write_data(ftdi, buf, size);
}

static inline int ddiscovery_read(struct ftdi_context *ftdi, uint8_t *buf, int size) {
    int r;
    r = ftdi_read_data(ftdi, buf, size);
#ifdef DEBUG_FRAMES
    printf("<- ");
    if (r > 0) {
        int i;
        for (i=0; i < r; i ++) {
            printf("%02x ", buf[i]);
        }
    }
    printf("\n");
#endif
    return r;
}


SR_PRIV int ddiscovery_init(const struct sr_dev_inst *sdi)
{
    (void) sdi;
	return SR_OK;
}

static int ddiscovery_session_triggers_config(struct sr_trigger *trigger, uint32_t *low_mask, uint32_t *high_mask, uint32_t *rising_edge_mask, uint32_t *falling_edge_mask)
{
    struct sr_trigger_stage *stage;
    struct sr_trigger_match *match;
    GSList *l, *m;

    *low_mask = 0;
    *high_mask = 0;
    *rising_edge_mask = 0;
    *falling_edge_mask = 0;

    if (!trigger->stages) {
        return SR_ERR;
    }

    for (l = trigger->stages; l; l = l->next) {
        stage = l->data;
        if (!stage->matches) {
            return SR_ERR;
        }
        for (m = stage->matches; m; m = m->next) {
            match = m->data;
            if (!match->channel) {
                return SR_ERR;
            }
            if (!match->match) {
                return SR_ERR;
            }
            switch (match->match) {
                case SR_TRIGGER_ZERO:
                    *low_mask |= 1 << match->channel->index;
                    break;
                case SR_TRIGGER_ONE:
                    *high_mask |= 1 << match->channel->index;
                    break;
                case SR_TRIGGER_RISING:
                    *rising_edge_mask |= 1 << match->channel->index;
                    break;
                case SR_TRIGGER_FALLING:
                    *falling_edge_mask |= 1 << match->channel->index;
                    break;
                case SR_TRIGGER_EDGE:
                    *rising_edge_mask |= 1 << match->channel->index;
                    *falling_edge_mask |= 1 << match->channel->index;
                    break;
                default:
                    break;
            }
        }
    }

    return SR_OK;
}

SR_PRIV int ddiscovery_prepare(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;

    uint32_t low_mask = 0;
    uint32_t high_mask = 0;
    uint32_t rising_edge_mask = 0;
    uint32_t falling_edge_mask = 0;
    struct sr_trigger *trigger;

    devc->status = 0xFF;
    devc->bytes_read = 0;
	devc->samples_available = 0;
	devc->samples_recorded = 0;
	devc->samples_recorded_overflow = FALSE;
    devc->trigger_start_offset = 0;
    devc->pending_bytes_to_read = devc->limit_samples * devc->bytes_per_sample;
    devc->samples_pre_trigger = (devc->limit_samples * devc->capture_ratio) / 100;
    devc->samples_post_trigger = devc->limit_samples - devc->samples_pre_trigger; 

    /* Read threshold depeding on cur_samplerate */
    devc->read_samples_threshold = MIN(DATA_BUF_SIZE, devc->cur_samplerate / 2);

	devc->data_buf = g_malloc0(DATA_BUF_SIZE);
	devc->data_buf_size = DATA_BUF_SIZE; 

    ftdi_set_bitmode(devc->ftdic, 0xff, 0x40);
    ftdi_set_latency_timer(devc->ftdic, 2);
    ftdi_setflowctrl(devc->ftdic, 0x0);
    ftdi_usb_purge_buffers(devc->ftdic);

    ddiscovery_write(devc->ftdic, frame_init_1, sizeof(frame_init_1));
    ddiscovery_write(devc->ftdic, frame_init_2, sizeof(frame_init_2));
    ddiscovery_write(devc->ftdic, frame_init_3, sizeof(frame_init_3));
    ddiscovery_write(devc->ftdic, frame_init_4, sizeof(frame_init_4));

    /* 
     Digital discovery clock frequency 800000000 MHz

     div = (FPGA_CLOCK / cur_samplerate) - 8

     | MHz    | Divider  | Value          |
     |--------|----------|----------------|
     | 800    |     1    |  0xfffffff9    |
     | 400    |     2    |  0xfffffffa    |
     | 200    |     4    |  0xfffffffc    |
     | 100    |     8    |  0x00          |
     |  50    |    16    |  0x08          |
     |  25    |    32    |  0x18          |
     |  20    |    40    |  0x20          |
     |  12.5  |    64    |  0x38          |
     |  10    |    80    |  0x48          |
     |   8    |   100    |  0x5c          |
     |   5    |   160    |  0x98          |
     |   2    |   400    |  0x0188        |
     |   1    |   800    |  0x0318        |
     */
    int32_t div = (FPGA_CLOCK / devc->cur_samplerate) - 8;

    ddiscovery_write(devc->ftdic, frame_init_2, sizeof(frame_init_2));
    ddiscovery_write(devc->ftdic, frame_big, sizeof(frame_big));
    ddiscovery_write(devc->ftdic, frame_start, sizeof(frame_start));
    ddiscovery_write(devc->ftdic, frame_capture_config, sizeof(frame_capture_config));
    ddiscovery_write(devc->ftdic, frame_pattern_genertor_config, sizeof(frame_pattern_genertor_config));

    frame_capture_config_change_record_mode();
    if (devc->num_channels == 8) {
        frame_capture_config_change_num_channels(CONFIG_USE_8_CH);
    } else if (devc->num_channels == 16) {
        frame_capture_config_change_num_channels(CONFIG_USE_16_CH);
    } else {
        frame_capture_config_change_num_channels(CONFIG_USE_32_CH);
    }
    frame_capture_config_change_divider(div);

    /* Prepare HW trigger */
    devc->triggers_en = FALSE;
    if ((trigger = sr_session_trigger_get(sdi->session))) {
        ddiscovery_session_triggers_config(trigger, &low_mask, &high_mask, &rising_edge_mask, &falling_edge_mask);
        devc->triggers_en = TRUE;
    }

    frame_capture_config_change_bytes_samples(devc->pending_bytes_to_read - 1);
    frame_capture_config_change_pre_trigger_post_trigger(devc->triggers_en ? devc->samples_pre_trigger: 0, 
                                                         devc->triggers_en ? devc->samples_post_trigger: devc->limit_samples);
    frame_capture_config_change_trigger_mode(low_mask, high_mask, rising_edge_mask, falling_edge_mask);
    if (devc->triggers_en) {
        frame_capture_config_change_bytes_samples(0xFFFFFFFF);
    }

    ddiscovery_write(devc->ftdic, frame_capture_config, sizeof(frame_capture_config));

	return SR_OK;
}

SR_PRIV int ddiscovery_start(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;

    frame_capture_config_change_start_record(frame_capture_config);
    ddiscovery_write(devc->ftdic, frame_capture_config, sizeof(frame_capture_config));
    ftdi_usb_purge_buffers(devc->ftdic);

	return SR_OK;
}

SR_PRIV int ddiscovery_stop(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;

    ddiscovery_write(devc->ftdic, frame_stop, sizeof(frame_stop));
    ftdi_set_bitmode(devc->ftdic, 0x0, 0x0);

	return SR_OK;
}

SR_PRIV int ddiscovery_read_data(int fd, int revents, void *cb_data) 
{
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	struct sr_datafeed_packet packet;
	struct sr_datafeed_logic logic;

	(void)fd;
	(void)revents;

    int32_t r = 0;
    uint8_t status_response[FRAME_STATUS_RESPONSE_SIZE];
    uint8_t status;
    uint32_t samples_recorded = 0;
    uint32_t t_samples = 0;
    gboolean force_last_samples_read = FALSE;

	if (!(sdi = cb_data))
		return TRUE;
	if (!(devc = sdi->priv))
		return TRUE;
	if (!(revents == G_IO_IN || revents == 0))
		return TRUE;
	if (!devc->ftdic)
		return TRUE;

	packet.type = SR_DF_LOGIC;
	packet.payload = &logic;

    /* Read the status of device to check how many samples can we read */
    ddiscovery_write(devc->ftdic, frame_status, sizeof(frame_status));
    while (r != FRAME_STATUS_RESPONSE_SIZE) {
        r += ddiscovery_read(devc->ftdic, &status_response[r], FRAME_STATUS_RESPONSE_SIZE-r);
    }

    status = status_response[0] & 0xF;
    if (status == DDISCOVERY_STATE_PREFILL || status == DDISCOVERY_STATE_RUNNING || status == DDISCOVERY_STATE_ARMED) {
        samples_recorded = (status_response[10] << 24) | 
            (status_response[9]  << 16) | 
            (status_response[8]  <<  8) | 
            status_response[7];
        t_samples = (status_response[4] << 24) |
            (status_response[3]  << 16) |
            (status_response[2]  <<  8) |
            status_response[1];

        samples_recorded /= (8 * devc->bytes_per_sample);

        if (samples_recorded < devc->samples_recorded) {
            devc->samples_recorded_overflow = TRUE;
            devc->samples_recorded = samples_recorded; 
            return TRUE;
        }

        devc->samples_available += samples_recorded - devc->samples_recorded;
        devc->samples_recorded = samples_recorded; 
    } else if (status == DDISCOVERY_STATE_DONE) {
        force_last_samples_read = TRUE;
    }
    if (devc->status != status) {
        devc->status = status;

        if (devc->triggers_en && status == DDISCOVERY_STATE_RUNNING) {
            devc->samples_available = devc->samples_pre_trigger;
            //TODO control samples overflow ????
            devc->trigger_start_offset = (samples_recorded - (devc->samples_post_trigger - t_samples) - devc->samples_pre_trigger) * devc->bytes_per_sample;
        }
    }

    /* Read Samples or skip if no samples available */
    if (devc->samples_available < devc->read_samples_threshold && force_last_samples_read == FALSE) {
        return TRUE;
    }

    /* If sample rate is higher than 200 then we have to read all samples at the end. Otherwise the device fails... */
    if (devc->cur_samplerate >= SR_MHZ(200) && devc->status != DDISCOVERY_STATE_DONE) {
        return TRUE;
    }

    if (devc->triggers_en && (status == DDISCOVERY_STATE_ARMED || devc->status == DDISCOVERY_STATE_PREFILL)) {
        return TRUE;
    }

    /* If counter samples overflow we need to mask the offset */
    uint32_t offset = devc->bytes_read + devc->trigger_start_offset;
    if (devc->samples_recorded_overflow) {
        //TODO check again if is really necessary 
        offset = offset & 0xFFFFFFF;
    }

    /* Read the samples */
    uint32_t to_read = devc->samples_available * devc->bytes_per_sample;
    if (to_read == 0) { /* We have to read the pending bytes */
        to_read = devc->pending_bytes_to_read;
    }

    to_read = MIN(to_read, devc->data_buf_size); /* Limit of bytes to read */

    /* Offset to read and number of bytes to read */
    frame_status_record_change_offset_to(offset, to_read - 1);
    ddiscovery_write(devc->ftdic, frame_status_record, sizeof(frame_status_record));

    while (to_read > 0) {
        r = ddiscovery_read(devc->ftdic, devc->data_buf, to_read);
        to_read -= r;
        logic.length = r;
        logic.unitsize = devc->bytes_per_sample;
        logic.data = devc->data_buf;
        devc->bytes_read += r;
        devc->pending_bytes_to_read -= r; 
        sr_session_send(sdi, &packet);

        if (devc->pending_bytes_to_read == 0) {
            sr_dev_acquisition_stop(sdi);
        }
    }

    devc->samples_available = 0;

    return TRUE;
}



