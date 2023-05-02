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

static uint8_t frame_init_1[] = {0x00,0x00,0x00,0x10,0x17,0x00,0x00,0x80};
static uint8_t frame_init_2[] = {0x00,0x00,0x00,0xa0,0x00,0x00,0x00,0x00,0xac};
static uint8_t frame_init_3[] = {0x00,0x00,0x00,0xa0,0x03,0x00,0x00,0x00,0xac,0x53,0x00,0x00};
static uint8_t frame_init_4[] = {0x00,0x00,0x00,0xa0,0x03,0x00,0x00,0x80};

static uint8_t frame_big[] = {
    0x00,0x00,0x00,0xb0,0x9b,0x0a,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x99,0xaa,0x66,0x55,0xa1,0x30,0x07,0x00,
    0x00,0x20,0xa1,0x31,0x88,0x04,0xc2,0x31,0x00,0x04,0x93,0x40,0x41,0x31,0x00,0x3d,
    0x61,0x31,0x26,0x07,0x22,0x30,0x22,0x04,0x16,0x00,0xa1,0x30,0x01,0x00,0x60,0x50,
    0x00,0x00,0x82,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1f,0x44,
    0x85,0xf4,0xe9,0x14,0x00,0x80,0x1f,0x44,0x85,0xf4,0xe9,0x14,0x00,0x80,0x1f,0x44,
    0x85,0xf4,0xe9,0x14,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x05,0x00,0x6e,0x3e,0x22,0x30,0x00,0x20,
    0x00,0x00,0x60,0x50,0x00,0x00,0x89,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,
    0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x07,0x00,0x00,0x24,0x00,0x0b,0x00,
    0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,
    0x01,0x07,0x00,0x00,0x24,0x00,0x0b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80,0x00,0x00,0x36,0x00,0x0e,0x00,
    0x01,0x80,0x00,0x00,0x36,0x00,0x0e,0x00,0x01,0x07,0x00,0x00,0x24,0x00,0x0b,0x00,
    0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,0x01,0x80,0x00,0x00,0x36,0x00,0x0e,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x07,0x00,0x00,0x24,0x00,0x0b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,0x01,0x80,0x00,0x00,0x36,0x00,0x0e,0x00,
    0x01,0x07,0x00,0x00,0x24,0x00,0x0b,0x00,0x01,0x07,0x00,0x00,0x24,0x00,0x0b,0x00,
    0x01,0x07,0x00,0x00,0x24,0x00,0x0b,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x80,0x82,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x87,0x00,0x00,0x36,0x00,0x0e,0x00,
    0x01,0x07,0x00,0x00,0x24,0x00,0x0b,0x00,0x01,0x07,0x00,0x00,0x24,0x00,0x0b,0x00,
    0x01,0x87,0x66,0x00,0x2d,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,
    0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x07,0x00,0x00,0x24,0x00,0x0b,0x00,
    0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x87,0x00,0x00,0x36,0x00,0x0e,0x00,0x01,0x87,0x00,0x00,0x36,0x00,0x0e,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x87,0x00,0x00,0x36,0x00,0x0e,0x00,
    0x01,0x87,0x00,0x00,0x36,0x00,0x0e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,0x01,0x87,0x00,0x00,0x36,0x00,0x0e,0x00,
    0x01,0x87,0x00,0x00,0x36,0x00,0x0e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,
    0x01,0x80,0x66,0x00,0x2d,0x00,0x08,0x00,0x01,0x87,0x00,0x00,0x36,0x00,0x0e,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x40,0x44,0x00,0x24,0x00,0x0b,0x00,0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x40,0x44,0x00,0x24,0x00,0x0b,0x00,0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,0x00,0x86,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x03,0x86,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,0x00,0x86,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x03,0x86,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x85,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
    0x00,0x00,0x00,0x00,0x00,0x45,0x00,0x00,0x00,0x00,0x00,0x24,0x00,0x00,0x00,0x00,
    0x00,0x8b,0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0x00,0x40,0x18,0x00,0x2f,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,
    0x01,0x80,0xbb,0x40,0x36,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x40,0x44,0x00,0x24,0x00,0x0b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x08,
    0x00,0x00,0x00,0x00,0x00,0x41,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,
    0x00,0x68,0x00,0x00,0x00,0x00,0x80,0x06,0x00,0x00,0x00,0x00,0x00,0x2a,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x01,0x84,0x66,0x40,0x35,0x00,0x03,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
    0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x23,0x00,0x00,0x00,0x00,
    0x80,0x80,0x00,0x00,0x00,0x00,0x80,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x01,0x80,0x66,0x40,0x2d,0x00,0x0f,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x84,0x66,0x40,0x2d,0x00,0x0f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x00,0x5e,0xdc,0xa1,0x30,
    0x03,0x00,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x02,0x30,0x0a,0x00,0xbf,0xb8,
    0xa1,0x30,0x0d,0x00,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,
    0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,0x00,0x20,
    0x00,0x20,0x00,0x20,
};

static uint8_t frame_start[] = {
    0x00,0x00,0x00,0x10,0x17,0x00,0x00,0x00,0x01,0x22,0x00,0x00,0x00,0x00,0x2f,0x00,
    0x00,0x00,0x00,0x00,0x00,0x62,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

static uint8_t frame_capture_config[] = {
    0x00,0x00,0x00,0x30,0x53,0x00,0x00,0x00,0x01,0x01,0xf9,0xff,0xff,0xff,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x00,0x80,0x40,0xfe,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xfe,0xff,0xff,0xff,0x00,0x00,0x00,0x05 
};

static uint8_t frame_pattern_genertor_config[] = {
    0x00,0x00,0x00,0x40,0x23,0x02,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x02,0xff,0xff,
    0xff,0xff,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x02,0x02,0x00,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x02,0x06,0x00,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0e,0x00,0x00,0x00,0x02,0x0e,0x00,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1e,0x00,0x00,0x00,0x02,0x1e,0x00,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3e,0x00,0x00,0x00,0x02,0x3e,0x00,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7e,0x00,0x00,0x00,0x02,0x7e,0x00,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x00,0x00,0x00,0x02,0xfe,0x00,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x01,0x00,0x00,0x02,0xfe,0x01,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x03,0x00,0x00,0x02,0xfe,0x03,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x07,0x00,0x00,0x02,0xfe,0x07,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x0f,0x00,0x00,0x02,0xfe,0x0f,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x1f,0x00,0x00,0x02,0xfe,0x1f,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x3f,0x00,0x00,0x02,0xfe,0x3f,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x7f,0x00,0x00,0x02,0xfe,0x7f,
    0x00,0x00,0x00,0x00,0xe7,0x03,0xe7,0x03,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0xfd,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01                   
};

static uint8_t frame_status[] = {0x00,0x00,0x00,0x30,0x17,0x00,0x00,0x80};
static uint8_t frame_status_record[] = {0x00,0x00,0x00,0x80,0x00,0x00,0x00,0x80};

static uint8_t frame_stop[] = {
    0x00,0x00,0x00,0x10,0x17,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x00,0x00,0xff,0x03, 
    0x00,0x00,0x00,0x00,0x00,0x62,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};


static void frame_capture_config_change_divider(int32_t div) {
    frame_capture_config[13] = (div >> 24) & 0xff;
    frame_capture_config[12] = (div >> 16) & 0xff;
    frame_capture_config[11] = (div >> 8) & 0xff;
    frame_capture_config[10] = div & 0xff;
}

static void frame_capture_config_change_pre_trigger_post_trigger(uint32_t pre, uint32_t post) {
    frame_capture_config[25] = (post >> 24) & 0xff;
    frame_capture_config[24] = (post >> 16) & 0xff;
    frame_capture_config[23] = (post >> 8) & 0xff;
    frame_capture_config[22] = post & 0xff;

    frame_capture_config[19] = (pre >> 24) & 0xff;
    frame_capture_config[18] = (pre >> 16) & 0xff;
    frame_capture_config[17] = (pre >> 8) & 0xff;
    frame_capture_config[16] = pre & 0xff;
}


static void frame_capture_config_change_bytes_samples(int32_t bytes) {
    frame_capture_config[31] = (bytes >> 24) & 0xff;
    frame_capture_config[30] = (bytes >> 16) & 0xff;
    frame_capture_config[29] = (bytes >> 8) & 0xff;
    frame_capture_config[28] = bytes & 0xff;
}

static void frame_capture_config_change_record_mode() {
    frame_capture_config[sizeof(frame_capture_config)-1] = 0x05;
}

static void frame_capture_config_change_num_channels(int value) {
    /* 8ch = 0 | 16ch = 1 | 32ch = 2*/
    frame_capture_config[9] = value;
}

static void frame_capture_config_change_start_record() {
    frame_capture_config[sizeof(frame_capture_config)-1] = 0x07;
}

static void frame_status_record_change_offset_to(uint32_t offset, uint32_t to) {
    frame_status_record[0] = offset & 0xff;
    frame_status_record[1] = (offset  >> 8) & 0xff;
    frame_status_record[2] = (offset  >> 16) & 0xff;
    frame_status_record[3] = 0x80 | ((offset  >> 24) & 0x0f);

    frame_status_record[4] = to & 0xff;
    frame_status_record[5] = (to >> 8) & 0xff;
    frame_status_record[6] = (to >> 16) & 0xff;
    frame_status_record[7] = 0x80 | ((to >> 24) & 0x0f);
}

static void frame_capture_config_change_trigger_mode(uint32_t low_mask, uint32_t high_mask, uint32_t rising_edge_mask, uint32_t falling_edge_mask) {
    if (rising_edge_mask || falling_edge_mask || low_mask || high_mask) {
        frame_capture_config[14] = 0x42; /* DetectorDigitalIn */
    } else {
        frame_capture_config[14] = 0x00; /* No trigger*/
    }
    frame_capture_config[51] = (rising_edge_mask >> 24) & 0xff;
    frame_capture_config[50] = (rising_edge_mask >> 16) & 0xff;
    frame_capture_config[49] = (rising_edge_mask >> 8) & 0xff;
    frame_capture_config[48] = rising_edge_mask & 0xff;

    frame_capture_config[55] = (falling_edge_mask >> 24) & 0xff;
    frame_capture_config[54] = (falling_edge_mask >> 16) & 0xff;
    frame_capture_config[53] = (falling_edge_mask >> 8) & 0xff;
    frame_capture_config[52] = falling_edge_mask & 0xff;

    frame_capture_config[59] = (low_mask >> 24) & 0xff;
    frame_capture_config[58] = (low_mask >> 16) & 0xff;
    frame_capture_config[57] = (low_mask >> 8) & 0xff;
    frame_capture_config[56] = low_mask & 0xff;

    frame_capture_config[63] = (high_mask >> 24) & 0xff;
    frame_capture_config[62] = (high_mask >> 16) & 0xff;
    frame_capture_config[61] = (high_mask >> 8) & 0xff;
    frame_capture_config[60] = high_mask & 0xff;
}


