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

#include <config.h>
#include <glib.h>
#include <string.h>

#include "protocol.h"
#include "fpga.h"

#define MAX_SAMPLES_8CH  256000000u
#define MAX_SAMPLES_16CH 128000000u
#define MAX_SAMPLES_32CH 64000000u

#define EEPROM_MODEL_NAME_ADDR 0x28
#define EEPROM_MODEL_NAME_SIZE 12

/* USB strings and eeprom defines */
#define USB_STR_MAXLEN 128

#define FPGA_BITSTREAM "ddiscovery-dcfg-04-02-01.bit"

static const char digilent_manufacturer[] = "Digilent";
static const char digilent_description[] = "Digilent USB Device";
static const char digilent_eeprom_model_ddiscovery[] = "@@DDiscovery";

static const char digilent_model_8[]  = "DDiscovery  8Ch (800MHz)";
static const char digilent_model_16[] = "DDiscovery 16Ch (400MHz)";
static const char digilent_model_32[] = "DDiscovery 32Ch (200MHz)";

static const uint32_t scanopts[] = {
};

static const uint32_t drvopts[] = {
	SR_CONF_LOGIC_ANALYZER,
};

static const uint32_t devopts[] = {
	SR_CONF_SAMPLERATE    | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_TRIGGER_MATCH | SR_CONF_LIST,
	SR_CONF_CAPTURE_RATIO | SR_CONF_GET | SR_CONF_SET,
};

static const int32_t trigger_matches[] = {
	SR_TRIGGER_ZERO,
	SR_TRIGGER_ONE,
	SR_TRIGGER_RISING,
	SR_TRIGGER_FALLING,
	SR_TRIGGER_EDGE,
};

static const char *channel_names_8[] = {
	"DIN0", "DIN1", "DIN2", "DIN3", "DIN4", "DIN5", "DIN6", "DIN7"
};

static const char *channel_names_16[] = {
	"DIN0", "DIN1", "DIN2",  "DIN3",  "DIN4",  "DIN5",  "DIN6",  "DIN7",
	"DIN8", "DIN9", "DIN10", "DIN11", "DIN12", "DIN13", "DIN14", "DIN15"
};

static const char *channel_names_32[] = {
	"DIN0",  "DIN1",  "DIN2",  "DIN3",  "DIN4",  "DIN5",  "DIN6",  "DIN7",
	"DIN8",  "DIN9",  "DIN10", "DIN11", "DIN12", "DIN13", "DIN14", "DIN15",
	"DIN16", "DIN17", "DIN18", "DIN19", "DIN20", "DIN21", "DIN22", "DIN23",
	"DIO24", "DIO25", "DIO26", "DIO27", "DIO28", "DIO29", "DIO30", "DIO31"
};

static const uint64_t samplerates_8[] = {
	SR_MHZ(1),
	SR_MHZ(2),
	SR_MHZ(4),
	SR_MHZ(5),
	SR_MHZ(8),
	SR_MHZ(10),
	SR_MHZ(16),
	SR_MHZ(20),
	SR_MHZ(25),
	SR_MHZ(40),
	SR_MHZ(50),
	SR_MHZ(80),
	SR_MHZ(100),
	SR_MHZ(200),
	SR_MHZ(400),
	SR_MHZ(800), 
};

static const uint64_t samplerates_16[] = {
	SR_MHZ(1),
	SR_MHZ(2),
	SR_MHZ(4),
	SR_MHZ(5),
	SR_MHZ(8),
	SR_MHZ(10),
	SR_MHZ(16),
	SR_MHZ(20),
	SR_MHZ(25),
	SR_MHZ(40),
	SR_MHZ(50),
	SR_MHZ(80),
	SR_MHZ(100),
	SR_MHZ(200),
	SR_MHZ(400),
};

static const uint64_t samplerates_32[] = {
	SR_MHZ(1),
	SR_MHZ(2),
	SR_MHZ(4),
	SR_MHZ(5),
	SR_MHZ(8),
	SR_MHZ(10),
	SR_MHZ(16),
	SR_MHZ(20),
	SR_MHZ(25),
	SR_MHZ(40),
	SR_MHZ(50),
	SR_MHZ(80),
	SR_MHZ(100),
	SR_MHZ(200),
};

static int scan_eeprom(struct ftdi_context *ftdic, gboolean *is_ddiscovery)
{
    int f;
    int value;
    int size;
    unsigned char buf[256];

    *is_ddiscovery = FALSE;

    f = ftdi_read_eeprom(ftdic);
    if (f < 0) {
        sr_err("ftdi_read_eeprom: %d (%s)\n", f, ftdi_get_error_string(ftdic));
        return -1;
    }

    ftdi_get_eeprom_value(ftdic, CHIP_SIZE, & value);
    if (value <0) {
        return -1;
    }
    if (ftdic->type == TYPE_R)
        size = 0xa0;
    else
        size = value;
    ftdi_get_eeprom_buf(ftdic, buf, size);
    if (0 == memcmp(&buf[EEPROM_MODEL_NAME_ADDR], digilent_eeprom_model_ddiscovery, EEPROM_MODEL_NAME_SIZE)) {
        *is_ddiscovery = TRUE;
    }

    return 0;
}

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
    struct ftdi_context *ftdic;
    struct ftdi_device_list *devlist, *curdev;
	GSList *devices;
    int ret;
    gboolean is_ddiscovery;
    int i = 0;

    (void) options;

    devices = NULL;

	ftdic = ftdi_new();
	if (!ftdic) {
		sr_err("Failed to initialize libftdi.");
		return NULL;
	}

    if ((ret = ftdi_usb_find_all(ftdic, &devlist, 0, 0)) < 0) {
        sr_err("ftdi_usb_find_all failed: %d (%s)\n", ret, ftdi_get_error_string(ftdic));
        return NULL;
    } 

    for (curdev = devlist; curdev != NULL; i++) {
        char manufacturer[USB_STR_MAXLEN];
        char description[USB_STR_MAXLEN];
        char serial_num[USB_STR_MAXLEN];

        if ((ret = ftdi_usb_get_strings(ftdic, curdev->dev, manufacturer, sizeof(manufacturer), description, sizeof(description), serial_num, sizeof(serial_num))) < 0) {
            sr_err("ftdi_usb_get_strings failed: %d (%s)\n", ret, ftdi_get_error_string(ftdic));
            curdev = curdev->next;
            continue;
        }

        if (!strcmp(manufacturer, digilent_manufacturer) && !strcmp(description, digilent_description)) {
            int f;

            f = ftdi_usb_open_dev(ftdic, curdev->dev);
            if (f < 0) {
                sr_err("Unable to open device %d: (%s)",
                        i, ftdi_get_error_string(ftdic));
                curdev = curdev->next;
                continue;
            }
            scan_eeprom(ftdic, &is_ddiscovery);
            ftdi_usb_close(ftdic);

            if (is_ddiscovery) {
                struct sr_dev_inst *sdi;
                struct dev_context *devc;

                /* Add device with 8 channels */
                sdi = g_malloc0(sizeof(struct sr_dev_inst));
                devc = g_malloc0(sizeof(struct dev_context));
                sdi->status = SR_ST_INACTIVE;
                sdi->vendor = g_strdup(digilent_manufacturer);
                sdi->model = g_strdup(digilent_model_8);
                sdi->serial_num = g_strdup(serial_num);
                sdi->priv = devc; 
                sdi->connection_id = g_strdup_printf("d:%u/%u",
                        libusb_get_bus_number(curdev->dev), libusb_get_device_address(curdev->dev));
                for (unsigned int j = 0; j < ARRAY_SIZE(channel_names_8); j++) {
                    sr_channel_new(sdi, j, SR_CHANNEL_LOGIC, TRUE, channel_names_8[j]);
                }
                devices = g_slist_append(devices, sdi);

                /* Add devices with 16 channels */
                sdi = g_malloc0(sizeof(struct sr_dev_inst));
                devc = g_malloc0(sizeof(struct dev_context));
                sdi->status = SR_ST_INACTIVE;
                sdi->vendor = g_strdup(digilent_manufacturer);
                sdi->model = g_strdup(digilent_model_16);
                sdi->serial_num = g_strdup(serial_num);
                sdi->priv = devc; 
                sdi->connection_id = g_strdup_printf("d:%u/%u",
                        libusb_get_bus_number(curdev->dev), libusb_get_device_address(curdev->dev));
                for (unsigned int j = 0; j < ARRAY_SIZE(channel_names_16); j++) {
                    sr_channel_new(sdi, j, SR_CHANNEL_LOGIC, TRUE, channel_names_16[j]);
                }
                devices = g_slist_append(devices, sdi);

                /* Add devices with 32 channels */
                sdi = g_malloc0(sizeof(struct sr_dev_inst));
                devc = g_malloc0(sizeof(struct dev_context));
                sdi->status = SR_ST_INACTIVE;
                sdi->vendor = g_strdup(digilent_manufacturer);
                sdi->model = g_strdup(digilent_model_32);
                sdi->serial_num = g_strdup(serial_num);
                sdi->priv = devc; 
                sdi->connection_id = g_strdup_printf("d:%u/%u",
                        libusb_get_bus_number(curdev->dev), libusb_get_device_address(curdev->dev));
                for (unsigned int j = 0; j < ARRAY_SIZE(channel_names_32); j++) {
                    sr_channel_new(sdi, j, SR_CHANNEL_LOGIC, TRUE, channel_names_32[j]);
                }
                //TODO not supported yet, strange behavior in some channels...
                //devices = g_slist_append(devices, sdi);
            }

        } 

        curdev = curdev->next;
    }

	ftdi_free(ftdic);

	return std_scan_complete(di, devices);
}

static void init_model(struct sr_dev_inst *sdi) 
{
	struct dev_context *devc;

	devc = sdi->priv;

    if (!strcmp(sdi->model, digilent_model_8)) {
        devc->num_channels = 8;
        devc->bytes_per_sample = 1;
    } else if (!strcmp(sdi->model, digilent_model_16)) {
        devc->num_channels = 16;
        devc->bytes_per_sample = 2;
    } else { /* digilent_model_32 */
        devc->num_channels = 32;
        devc->bytes_per_sample = 4;
    }
}

static int dev_open(struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	int ret = SR_OK;

	devc = sdi->priv;


    init_model(sdi);
    devc->limit_samples = 10000000;
    devc->cur_samplerate = SR_MHZ(10);
    devc->capture_ratio = 10;

	devc->ftdic = ftdi_new();
	if (!devc->ftdic)
		return SR_ERR;

	ret = ftdi_usb_open_string(devc->ftdic, sdi->connection_id);
	if (ret < 0) {
		/* Log errors, except for -3 ("device not found"). */
		if (ret != -3)
			sr_err("Failed to open device (%d): %s", ret,
			       ftdi_get_error_string(devc->ftdic));
		goto err_ftdi_free;
	}


	ret = ftdi_usb_purge_buffers(devc->ftdic);
	if (ret < 0) {
		sr_err("Failed to purge FTDI RX/TX buffers (%d): %s.",
		       ret, ftdi_get_error_string(devc->ftdic));
		goto err_dev_open_close_ftdic;
	}

    if (ddiscovery_load_fpga(sdi, FPGA_BITSTREAM) < 0) {
		goto err_dev_open_close_ftdic;
    }

	return SR_OK;

err_dev_open_close_ftdic:
	ftdi_usb_close(devc->ftdic);

err_ftdi_free:
	ftdi_free(devc->ftdic);

	return SR_ERR;
}


static int dev_close(struct sr_dev_inst *sdi)
{
	struct dev_context *devc;

	devc = sdi->priv;

	if (!devc->ftdic)
		return SR_ERR_BUG;

	ftdi_usb_close(devc->ftdic);
	ftdi_free(devc->ftdic);
	devc->ftdic = NULL;

	return SR_OK;
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct sr_usb_dev_inst *usb;
	struct dev_context *devc;

	(void)cg;

	switch (key) {
	case SR_CONF_CONN:
		if (!sdi || !sdi->conn)
			return SR_ERR_ARG;
		usb = sdi->conn;
		*data = g_variant_new_printf("%d.%d", usb->bus, usb->address);
		break;
	case SR_CONF_SAMPLERATE:
		if (!sdi)
			return SR_ERR;
		devc = sdi->priv;
		*data = g_variant_new_uint64(devc->cur_samplerate);
		break;
	case SR_CONF_LIMIT_SAMPLES:
		if (!sdi)
			return SR_ERR;
		devc = sdi->priv;
		*data = g_variant_new_uint64(devc->limit_samples);
		break;
	case SR_CONF_CAPTURE_RATIO:
		if (!sdi)
			return SR_ERR;
		devc = sdi->priv;
		*data = g_variant_new_uint64(devc->capture_ratio);
		break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc;
    uint64_t value;

	(void)cg;

	devc = sdi->priv;

	switch (key) {
	case SR_CONF_LIMIT_SAMPLES:
		value = g_variant_get_uint64(data);
		devc->limit_samples = value; 
		break;
	case SR_CONF_SAMPLERATE:
		value = g_variant_get_uint64(data);
		devc->cur_samplerate = value;
		break;
	case SR_CONF_CAPTURE_RATIO:
		devc->capture_ratio = g_variant_get_uint64(data);
		break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
    struct dev_context *devc;

	switch (key) {
	case SR_CONF_SCAN_OPTIONS:
	case SR_CONF_DEVICE_OPTIONS:
		return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts, devopts);
    case SR_CONF_TRIGGER_MATCH:
        *data = std_gvar_array_i32(ARRAY_AND_SIZE(trigger_matches));
        break;
	case SR_CONF_SAMPLERATE:
        if (!sdi)
            return SR_ERR_ARG;
        devc = sdi->priv;
        if (devc->num_channels == 8) {
            *data = std_gvar_samplerates(ARRAY_AND_SIZE(samplerates_8));
        } else if (devc->num_channels == 16) {
            *data = std_gvar_samplerates(ARRAY_AND_SIZE(samplerates_16));
        } else {
            *data = std_gvar_samplerates(ARRAY_AND_SIZE(samplerates_32));
        }
		break;
    case SR_CONF_LIMIT_SAMPLES:
        if (!sdi)
            return SR_ERR_ARG;
        devc = sdi->priv;
        if (devc->num_channels == 8) {
            *data = std_gvar_tuple_u64(1000, MAX_SAMPLES_8CH);
        } else if (devc->num_channels == 16) {
            *data = std_gvar_tuple_u64(1000, MAX_SAMPLES_16CH);
        } else {
            *data = std_gvar_tuple_u64(1000, MAX_SAMPLES_32CH);
        }
        break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	unsigned int ret;

	ret = ddiscovery_prepare(sdi);
	if (ret != SR_OK)
		return ret;

	std_session_send_df_header(sdi);


	ddiscovery_start(sdi);
	if (ret != SR_OK)
		return ret;

	/* Hook up a dummy handler to read data from the device. */
	sr_session_source_add(sdi->session, -1, G_IO_IN, 0,
			      ddiscovery_read_data, (void *)sdi);


	return SR_OK;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	ddiscovery_stop(sdi);

    sr_session_source_remove(sdi->session, -1);

    std_session_send_df_end(sdi);

	return SR_OK;
}

static struct sr_dev_driver ddiscovery_driver_info = {
	.name = "DDiscovery",
	.longname = "Digilent Digital Discovery",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	.scan = scan,
	.dev_list = std_dev_list,
	.dev_clear = std_dev_clear,
	.config_get = config_get,
	.config_set = config_set,
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};
SR_REGISTER_DEV_DRIVER(ddiscovery_driver_info);
