/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2023 Marc Font Freixa <marc@bz17.dev>
 *
 * Some parts has been extracted and adapted from openocd project xilinx_bit.c
 * Copyright (C) 2006 by Dominic Rath                                    
 * Dominic.Rath@gmx.de                                                   
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
 *
 */

#include "fpga.h"
#include "protocol.h"


#define DDISCOVERY_PART_NAME "6slx25csg324" 
#define DDISCOVERY_LOAD_CHUNK_SIZE 8192u
#define DDISCOVERY_FPGA_DEVICE_ID  0x24004093 
#define DDISCOVERY_FPGA_DEVICE_ID_0 (DDISCOVERY_FPGA_DEVICE_ID & 0xff) 
#define DDISCOVERY_FPGA_DEVICE_ID_1 ((DDISCOVERY_FPGA_DEVICE_ID >> 8)  & 0xff) 
#define DDISCOVERY_FPGA_DEVICE_ID_2 ((DDISCOVERY_FPGA_DEVICE_ID >> 16) & 0xff) 
#define DDISCOVERY_FPGA_DEVICE_ID_3 ((DDISCOVERY_FPGA_DEVICE_ID >> 24) & 0xff) 

struct xilinx_bit_file {
    uint8_t unknown_header[13];
    uint8_t *source_file;
    uint8_t *part_name;
    uint8_t *date;
    uint8_t *time;
    uint32_t length;
    uint8_t *data;
};

static inline uint8_t reverse_byte(uint8_t b) 
{
    uint8_t r = 0;
    for (int i=0; i < 8; i++) {
        r = (r << 1) | (b & 0x01);
        b >>= 1;
    }
    return r;
}

static inline uint32_t be_to_h_u32(const uint8_t *buf)
{
    return (uint32_t)((uint32_t)buf[3] | (uint32_t)buf[2] << 8 | (uint32_t)buf[1] << 16 | (uint32_t)buf[0] << 24);
}

static inline uint16_t be_to_h_u16(const uint8_t *buf)
{
    return (uint16_t)((uint16_t)buf[1] | (uint16_t)buf[0] << 8);
}

static void xilinx_free_bit_file(struct xilinx_bit_file *bit_file)
{
    if (bit_file->source_file)
    	free(bit_file->source_file);
    if (bit_file->part_name)
    	free(bit_file->part_name);
    if (bit_file->date)
	    free(bit_file->date);
    if (bit_file->time)
	    free(bit_file->time);
    if (bit_file->data)
	    free(bit_file->data);
}

static int xilinx_read_section(struct sr_context *ctx, struct sr_resource *fw, int length_size, char section,
	uint32_t *buffer_length, uint8_t **buffer)
{
	uint8_t length_buffer[4];
	int length;
	char section_char;
	int read_count;

	if ((length_size != 2) && (length_size != 4)) {
		return -1;
	}

	read_count = sr_resource_read(ctx, fw, &section_char, 1);
	if (read_count != 1)
		return -1;

	if (section_char != section)
		return -1;

	read_count = sr_resource_read(ctx, fw, length_buffer, length_size);
	if (read_count != length_size)
		return -1;

	if (length_size == 4)
		length = be_to_h_u32(length_buffer);
	else	/* (length_size == 2) */
		length = be_to_h_u16(length_buffer);

	if (buffer_length)
		*buffer_length = length;

	*buffer = malloc(length);

	read_count = sr_resource_read(ctx, fw, *buffer, length);
	if (read_count != length) {
		return -1;
    }

	return 0;
}

static int xilinx_read_bit_file(struct sr_context *ctx, const char *filename, struct xilinx_bit_file *bit_file)
{
    struct sr_resource fw;
    int read_count;

	if (!filename || !bit_file)
		return -1;

    if (sr_resource_open(ctx, &fw, SR_RESOURCE_FIRMWARE, filename) != SR_OK) {
        sr_err("FPGA bitstream not found\n");
        return -1;
    }

	bit_file->source_file = NULL;
	bit_file->part_name = NULL;
	bit_file->date = NULL;
	bit_file->time = NULL;
	bit_file->data = NULL;

	read_count = sr_resource_read(ctx, &fw, bit_file->unknown_header, 13);
	if (read_count != 13) {
        sr_resource_close(ctx, &fw);
		return -1;
	}

	if (xilinx_read_section(ctx, &fw, 2, 'a', NULL, &bit_file->source_file) != 0) {
		xilinx_free_bit_file(bit_file);
        sr_resource_close(ctx, &fw);
		return -1;
	}

	if (xilinx_read_section(ctx, &fw, 2, 'b', NULL, &bit_file->part_name) != 0) {
		xilinx_free_bit_file(bit_file);
        sr_resource_close(ctx, &fw);
		return -1;
	}

	if (xilinx_read_section(ctx, &fw, 2, 'c', NULL, &bit_file->date) != 0) {
		xilinx_free_bit_file(bit_file);
        sr_resource_close(ctx, &fw);
		return -1;
	}

	if (xilinx_read_section(ctx, &fw, 2, 'd', NULL, &bit_file->time) != 0) {
		xilinx_free_bit_file(bit_file);
        sr_resource_close(ctx, &fw);
		return -1;
	}

	if (xilinx_read_section(ctx, &fw, 4, 'e', &bit_file->length, &bit_file->data) != 0) {
		xilinx_free_bit_file(bit_file);
        sr_resource_close(ctx, &fw);
		return -1;
	}

    sr_resource_close(ctx, &fw);

	return 0;
}


static int ddiscovery_sync_mpsee(struct ftdi_context *ftdi) 
{
    uint8_t tx_buf[1];
    uint8_t rx_buf[2];

    tx_buf[0] = 0xAA;
    ftdi_write_data(ftdi, tx_buf, 1);
    gboolean mpsse_synced = FALSE;
    int retries = 1000;
    while (!mpsse_synced && retries > 0) {
        ftdi_read_data(ftdi, rx_buf, 2);
        if ((rx_buf[0] == 0xFA) && (rx_buf[1] == 0xAA)) {
            mpsse_synced = TRUE;
        }
        retries--;
    }
    return mpsse_synced;
}

static int ddiscovery_check_fpga_idcode(struct ftdi_context *ftdi) 
{
    uint8_t idcode[4];

    uint8_t jtag_mpsee_idcode_1[] = {0x8b,0x86,0x00,0x00};
    uint8_t jtag_mpsee_idcode_2[] = {0x80,0x08,0x0b,0x82,0x80,0x80};
    uint8_t jtag_mpsee_idcode_3[] = {0x4b,0x05,0xbf,0x4b,0x03,0x82,0x39,0x03,0x00,0xff,0xff,0xff,0xff,0x87};

    ftdi_write_data(ftdi, jtag_mpsee_idcode_1, sizeof(jtag_mpsee_idcode_1));
    ftdi_write_data(ftdi, jtag_mpsee_idcode_2, sizeof(jtag_mpsee_idcode_2));
    ftdi_write_data(ftdi, jtag_mpsee_idcode_3, sizeof(jtag_mpsee_idcode_3));
    ftdi_read_data(ftdi, idcode, 4);

    /* 0x93 0x40 0x00 0x24 => expected DeviceId 0x24004093 */
    if (!(idcode[0] == DDISCOVERY_FPGA_DEVICE_ID_0 && idcode[1] == DDISCOVERY_FPGA_DEVICE_ID_1 && 
        idcode[2] == DDISCOVERY_FPGA_DEVICE_ID_2 && idcode[3] == DDISCOVERY_FPGA_DEVICE_ID_3)) {
        sr_err("Expected fpga device id 0x%08x returned 0x%02x%02x%02x%02x\n", 
                DDISCOVERY_FPGA_DEVICE_ID, idcode[3], idcode[2], idcode[1], idcode[0]);
        return -1;
    }
    return 0;
}

SR_PRIV int ddiscovery_load_fpga(const struct sr_dev_inst *sdi, char *filename)
{
    struct dev_context *devc;
    struct drv_context *drvc;
    struct ftdi_context *ftdi;
    struct xilinx_bit_file bit_file = {};

    devc = sdi->priv;
    ftdi = devc->ftdic;
    drvc = sdi->driver->context;

    int ret = xilinx_read_bit_file(drvc->sr_ctx, filename, &bit_file);
    if (ret < 0 || strcmp((char *) bit_file.part_name, DDISCOVERY_PART_NAME)) {
        xilinx_free_bit_file(&bit_file);
        return -1;
    } 

    /* Configure ftdi to work as mpsse */
    ftdi_set_latency_timer(ftdi, 16);
    ftdi_usb_purge_buffers(ftdi);
    ftdi_set_bitmode(ftdi, 0x00, 0x00);
    ftdi_set_bitmode(ftdi, 0x00, 0x02);

    if (ddiscovery_sync_mpsee(ftdi) == FALSE) {
        sr_err("Error in synchronizing the MPSSE\n");
        xilinx_free_bit_file(&bit_file);
        return -1;
    }

    if (ddiscovery_check_fpga_idcode(ftdi) < 0) {
        xilinx_free_bit_file(&bit_file);
        return -1;
    }

    /* Extracted from waveform load fpga secuence using wireshark */
    /* Frames before load bitstream */
    uint8_t jtag_mpsee_frame_1[] = {0x8a,0x97,0x8d,0x86,0x02,0x00,0x87};
    uint8_t jtag_mpsee_frame_2[] = {0x80,0x08,0x0b,0x82,0x80,0x80,0x87};
    uint8_t jtag_mpsee_frame_3[] = {0x4b,0x00,0x01,0x4b,0x00,0x01,0x4b,0x00,0x01,0x4b,0x00,0x01,0x4b,0x00,0x01,0x4b,0x00,0x00,0x4b,0x00,0x01,0x87};
    uint8_t jtag_mpsee_frame_4[] = {0x4b,0x00,0x01,0x4b,0x00,0x00,0x4b,0x00,0x00,0x87};
    uint8_t jtag_mpsee_frame_5[] = {0x1b,0x04,0x05,0x87};
    uint8_t jtag_mpsee_frame_6[] = {0x4b,0x00,0x01,0x87};
    uint8_t jtag_mpsee_frame_7[] = {0x4b,0x00,0x01,0x4b,0x00,0x01,0x87};
    uint8_t jtag_mpsee_frame_8[] = {0x4b,0x00,0x00,0x4b,0x00,0x00,0x87};
    uint8_t jtag_mpsee_frame_9[] = {0x19,0x03,0x00,0x00,0x00,0x00,0x00,0x87};
    /* Frames after load bitstream */
    uint8_t jtag_mpsee_frame_10[] = {0x4b,0x00,0x01,0x87};
    uint8_t jtag_mpsee_frame_11[] = {0x4b,0x00,0x01,0x4b,0x00,0x01,0x87};
    uint8_t jtag_mpsee_frame_12[] = {0x4b,0x00,0x01,0x4b,0x00,0x00,0x4b,0x00,0x00,0x87};
    uint8_t jtag_mpsee_frame_13[] = {0x1b,0x04,0x0c,0x87};
    uint8_t jtag_mpsee_frame_14[] = {0x4b,0x00,0x01,0x87};
    uint8_t jtag_mpsee_frame_15[] = {0x4b,0x00,0x01,0x4b,0x00,0x01,0x87};
    uint8_t jtag_mpsee_frame_16[] = {0x4b,0x00,0x00,0x4b,0x00,0x01,0x4b,0x00,0x01,0x4b,0x00,0x00,0x87};
    uint8_t jtag_mpsee_frame_17[] = {0x19,0x03,0x00,0x00,0x00,0x00,0x00,0x87};
    uint8_t jtag_mpsee_frame_18[] = {0x4b,0x00,0x01,0x4b,0x00,0x01,0x4b,0x00,0x01,0x4b,0x00,0x01,0x87};
    uint8_t jtag_mpsee_frame_19[] = {0x80,0x08,0x00,0x82,0x00,0x00,0x87};

    ftdi_write_data(ftdi, jtag_mpsee_frame_1, sizeof(jtag_mpsee_frame_1));
    ftdi_write_data(ftdi, jtag_mpsee_frame_2, sizeof(jtag_mpsee_frame_2));
    ftdi_write_data(ftdi, jtag_mpsee_frame_3, sizeof(jtag_mpsee_frame_3));
    ftdi_write_data(ftdi, jtag_mpsee_frame_4, sizeof(jtag_mpsee_frame_4));
    ftdi_write_data(ftdi, jtag_mpsee_frame_5, sizeof(jtag_mpsee_frame_5));
    ftdi_write_data(ftdi, jtag_mpsee_frame_6, sizeof(jtag_mpsee_frame_6));
    ftdi_write_data(ftdi, jtag_mpsee_frame_7, sizeof(jtag_mpsee_frame_7));
    ftdi_write_data(ftdi, jtag_mpsee_frame_8, sizeof(jtag_mpsee_frame_8));
    ftdi_write_data(ftdi, jtag_mpsee_frame_9, sizeof(jtag_mpsee_frame_9));

    uint8_t *buffer = malloc(DDISCOVERY_LOAD_CHUNK_SIZE + 3);
    if (buffer != NULL) {
        /* Load bitstream  by chunks */
        uint32_t loaded = 0;
        uint32_t length = bit_file.length - 1;
        while (loaded < length) {
            uint32_t load_size = DDISCOVERY_LOAD_CHUNK_SIZE;
            if (load_size + loaded > length) {
                load_size = length - loaded;
            }
            buffer[0] = 0x19;
            buffer[1] = (load_size - 1) & 0xFF;
            buffer[2] = ((load_size - 1) >> 8) & 0xFF;
            for (uint32_t j = 0; j < load_size; j++) {
                buffer[3+j] = reverse_byte(bit_file.data[loaded+j]);
            }
            ftdi_write_data(ftdi, buffer, 3 + load_size);                             
            loaded += load_size;
        }

        ftdi_write_data(ftdi, jtag_mpsee_frame_10, sizeof(jtag_mpsee_frame_10));
        ftdi_write_data(ftdi, jtag_mpsee_frame_11, sizeof(jtag_mpsee_frame_11));
        ftdi_write_data(ftdi, jtag_mpsee_frame_12, sizeof(jtag_mpsee_frame_12));
        ftdi_write_data(ftdi, jtag_mpsee_frame_13, sizeof(jtag_mpsee_frame_13));
        ftdi_write_data(ftdi, jtag_mpsee_frame_14, sizeof(jtag_mpsee_frame_14));
        ftdi_write_data(ftdi, jtag_mpsee_frame_15, sizeof(jtag_mpsee_frame_15));
        ftdi_write_data(ftdi, jtag_mpsee_frame_16, sizeof(jtag_mpsee_frame_16));
        ftdi_write_data(ftdi, jtag_mpsee_frame_17, sizeof(jtag_mpsee_frame_17));
        ftdi_write_data(ftdi, jtag_mpsee_frame_18, sizeof(jtag_mpsee_frame_18));
        ftdi_write_data(ftdi, jtag_mpsee_frame_19, sizeof(jtag_mpsee_frame_19));

        ftdi_set_bitmode(ftdi, 0x00, 0x00);

        free(buffer);
    }

    xilinx_free_bit_file(&bit_file);

    return 0;
}
