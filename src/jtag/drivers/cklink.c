// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * T-Head CK-Link JTAG adapter driver
 *
 * Supports the CK-Link Lite V2 wire protocol used by T-Head's original
 * probes and by Bouffalo Lab BL616/BL702 CK-Link clones (for example
 * the built-in debugger on the BL618 eval board).
 *
 * Host-side communication goes over USB bulk endpoints with a framed
 * command protocol reverse-engineered from T-Head's DebugServer.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jtag/adapter.h>
#include <jtag/interface.h>
#include <jtag/commands.h>
#include <helper/binarybuffer.h>
#include <helper/bits.h>
#include <helper/time_support.h>
#include "libusb_helper.h"

/* USB identification */
#define CKLINK_VID_BOUFFALO		0x42bf
#define CKLINK_VID_THEAD		0x32bf
#define CKLINK_PID_LITE_V2		0xb210

#define CKLINK_USB_INTERFACE		0
#define CKLINK_EP_OUT			0x02
#define CKLINK_EP_IN			0x81
#define CKLINK_USB_TIMEOUT_MS		1000
#define CKLINK_USB_BUF_SIZE		2048

/* Wire-protocol framing bytes */
#define CKLINK_FRAME_START		0x68
#define CKLINK_FRAME_END		0x16

/* Response frame layout: start + status + payload + checksum + end */
#define CKLINK_FRAME_OVERHEAD		4
#define CKLINK_RESP_PAYLOAD_OFFSET	2

/* Opcodes */
#define CKLINK_OP_SELFREG_WRITE		0x06
#define CKLINK_OP_SELFREG_READ		0x87
#define CKLINK_OP_JTAG_BATCH		0x88

/* Self-register indices */
#define CKLINK_SR_CSR			0	/* clock divider + CDI mode */
#define CKLINK_SR_MTCR_WAIT		1	/* target-comm wait cycles */
#define CKLINK_SR_JTAG_CONFIG		8	/* JTAG config word */
#define CKLINK_SELFREG_BYTES		4

/*
 * Initial self-register values captured from a working DebugServer
 * session and replayed verbatim. sr0's byte 3 controls the CDI mode:
 * 0x60 selects 5-wire JTAG, 0x61 would select 2-wire cJTAG.
 */
#define CKLINK_SR0_INIT_CLK_BYTE	0x17
#define CKLINK_SR0_INIT_MODE_BYTE	0x60
#define CKLINK_SR1_INIT_VALUE		0x000003e8
#define CKLINK_SR8_INIT_VALUE		0x00622250

/*
 * Per-scan protocol limits. The JTAG batch opcode stores the IR and DR
 * bit-counts in single bytes, so individual scans cannot exceed 255 bits.
 */
#define CKLINK_MAX_SCAN_BITS		255
#define CKLINK_MAX_SCAN_BYTES		32	/* DIV_ROUND_UP(255, 8) */

/* TAP reset via a 5-cycle TMS=1 sequence */
#define CKLINK_TAP_RESET_BITS		5
#define CKLINK_TAP_RESET_TMS_PATTERN	0x1f

/*
 * When a DR scan arrives without a prior IR scan to pair with, we send an
 * IDCODE-instruction placeholder IR scan so the chip reads back its IDCODE
 * via the DR shift. Assumes a 5-bit IR with IDCODE encoded as 0x01, which
 * matches all the BL61x/BL70x/BL702L cores this driver targets.
 */
#define CKLINK_PLACEHOLDER_IR_BITS	5
#define CKLINK_PLACEHOLDER_IR_VALUE	0x01

struct cklink {
	struct libusb_device_handle *usb_dev;
	uint8_t tx_buf[CKLINK_USB_BUF_SIZE];
	uint8_t rx_buf[CKLINK_USB_BUF_SIZE];
	/* Cached IR scan to combine with the next DR scan */
	uint8_t ir_value[CKLINK_MAX_SCAN_BYTES];
	unsigned int ir_bits;
};

static struct cklink *cklink_handle;

/**
 * Send a framed command from @p tx_buf and optionally wait for a reply.
 * When @p rxlen is NULL, the call is fire-and-forget (no bulk IN).
 */
static int cklink_usb_xfer(struct cklink *ck, int txlen, int *rxlen)
{
	int actual = 0;
	int ret = jtag_libusb_bulk_write(ck->usb_dev, CKLINK_EP_OUT,
					 (char *)ck->tx_buf, txlen,
					 CKLINK_USB_TIMEOUT_MS, &actual);
	if (ret != ERROR_OK || actual != txlen) {
		LOG_ERROR("CK-Link bulk write failed (ret=%d, actual=%d/%d)",
			  ret, actual, txlen);
		return ERROR_FAIL;
	}

	if (!rxlen)
		return ERROR_OK;

	ret = jtag_libusb_bulk_read(ck->usb_dev, CKLINK_EP_IN,
				    (char *)ck->rx_buf, CKLINK_USB_BUF_SIZE,
				    CKLINK_USB_TIMEOUT_MS, &actual);
	if (ret != ERROR_OK || actual < CKLINK_FRAME_OVERHEAD) {
		LOG_ERROR("CK-Link bulk read failed (ret=%d, actual=%d)",
			  ret, actual);
		return ERROR_FAIL;
	}
	if (ck->rx_buf[0] != CKLINK_FRAME_START) {
		LOG_ERROR("CK-Link bad response start byte 0x%02x",
			  ck->rx_buf[0]);
		return ERROR_FAIL;
	}
	/*
	 * Non-zero status bytes are tolerated here: OpenOCD's initial
	 * chain-detection scans can legitimately elicit error statuses
	 * that callers need to see rather than us bail on.
	 */
	*rxlen = actual;
	return ERROR_OK;
}

/** Write the frame header and return the next free index. */
static int cklink_frame_start(struct cklink *ck, uint8_t opcode)
{
	ck->tx_buf[0] = CKLINK_FRAME_START;
	ck->tx_buf[1] = opcode;
	return 2;
}

/** Append the checksum + end marker and return the total frame length. */
static int cklink_frame_end(struct cklink *ck, int pos)
{
	unsigned int checksum = 0;
	for (int i = 0; i < pos; i++)
		checksum += ck->tx_buf[i];
	ck->tx_buf[pos++] = (uint8_t)(checksum & 0xff);
	ck->tx_buf[pos++] = CKLINK_FRAME_END;
	return pos;
}

/** Write a 4-byte self-register. Fire-and-forget on the wire. */
static int cklink_selfreg_write(struct cklink *ck, uint8_t reg,
				const uint8_t *value)
{
	int pos = cklink_frame_start(ck, CKLINK_OP_SELFREG_WRITE);
	ck->tx_buf[pos++] = reg;
	memcpy(&ck->tx_buf[pos], value, CKLINK_SELFREG_BYTES);
	pos += CKLINK_SELFREG_BYTES;
	pos = cklink_frame_end(ck, pos);
	return cklink_usb_xfer(ck, pos, NULL);
}

/** Read a 4-byte self-register into @p value. */
static int cklink_selfreg_read(struct cklink *ck, uint8_t reg, uint8_t *value)
{
	int pos = cklink_frame_start(ck, CKLINK_OP_SELFREG_READ);
	ck->tx_buf[pos++] = reg;
	pos = cklink_frame_end(ck, pos);

	int rxlen = 0;
	int ret = cklink_usb_xfer(ck, pos, &rxlen);
	if (ret != ERROR_OK)
		return ret;

	const int expected = CKLINK_FRAME_OVERHEAD + CKLINK_SELFREG_BYTES;
	if (rxlen < expected) {
		LOG_ERROR("CK-Link selfreg read response too short (%d < %d)",
			  rxlen, expected);
		return ERROR_FAIL;
	}
	memcpy(value, &ck->rx_buf[CKLINK_RESP_PAYLOAD_OFFSET],
	       CKLINK_SELFREG_BYTES);
	return ERROR_OK;
}

/** Pack a 32-bit value as little-endian bytes for self-register I/O. */
static void cklink_selfreg_pack_u32(uint8_t *dst, uint32_t value)
{
	dst[0] = (uint8_t)(value & 0xff);
	dst[1] = (uint8_t)((value >> 8) & 0xff);
	dst[2] = (uint8_t)((value >> 16) & 0xff);
	dst[3] = (uint8_t)((value >> 24) & 0xff);
}

/**
 * Send a single-entry JTAG batch scan and copy the captured DR bits into
 * @p dr_tdo. A @p dr_tdo of NULL discards the capture. Scans longer than
 * CKLINK_MAX_SCAN_BITS are clamped: OpenOCD's chain-detection sometimes
 * asks for very long bypass shifts and the fallback path handles a short
 * response gracefully.
 */
static int cklink_jtag_scan(struct cklink *ck,
			    unsigned int ir_bits, const uint8_t *ir_tdi,
			    unsigned int dr_bits, const uint8_t *dr_tdi,
			    uint8_t *dr_tdo)
{
	if (ir_bits > CKLINK_MAX_SCAN_BITS)
		ir_bits = CKLINK_MAX_SCAN_BITS;
	if (dr_bits > CKLINK_MAX_SCAN_BITS)
		dr_bits = CKLINK_MAX_SCAN_BITS;

	const unsigned int ir_bytes = DIV_ROUND_UP(ir_bits, 8);
	const unsigned int dr_bytes = DIV_ROUND_UP(dr_bits, 8);

	int pos = cklink_frame_start(ck, CKLINK_OP_JTAG_BATCH);
	ck->tx_buf[pos++] = 0;		/* (entry count - 1), here 1 entry */
	ck->tx_buf[pos++] = (uint8_t)ir_bits;
	if (ir_tdi)
		memcpy(&ck->tx_buf[pos], ir_tdi, ir_bytes);
	else
		memset(&ck->tx_buf[pos], 0, ir_bytes);
	pos += ir_bytes;
	ck->tx_buf[pos++] = (uint8_t)dr_bits;
	if (dr_tdi)
		memcpy(&ck->tx_buf[pos], dr_tdi, dr_bytes);
	else
		memset(&ck->tx_buf[pos], 0, dr_bytes);
	pos += dr_bytes;
	pos = cklink_frame_end(ck, pos);

	int rxlen = 0;
	int ret = cklink_usb_xfer(ck, pos, &rxlen);
	if (ret != ERROR_OK)
		return ret;

	/*
	 * Response layout:
	 *   start(1) + status(1) + ir_tdo(ir_bytes) + dr_echo(1)
	 *     + dr_tdo(dr_bytes) + checksum(1) + end(1)
	 */
	const unsigned int expected =
		CKLINK_FRAME_OVERHEAD + ir_bytes + 1 + dr_bytes;
	if ((unsigned int)rxlen < expected) {
		if (dr_tdo)
			memset(dr_tdo, 0, dr_bytes);
		return ERROR_OK;
	}

	const unsigned int dr_tdo_offset =
		CKLINK_RESP_PAYLOAD_OFFSET + ir_bytes + 1;
	if (dr_tdo)
		memcpy(dr_tdo, &ck->rx_buf[dr_tdo_offset], dr_bytes);

	return ERROR_OK;
}

/**
 * Shift @p num_bits idle cycles, chunked to fit the protocol's 255-bit
 * per-scan limit. Used for RUNTEST, STABLECLOCKS and TMS commands.
 */
static int cklink_idle_cycles(unsigned int num_bits)
{
	static const uint8_t zeros[CKLINK_MAX_SCAN_BYTES] = { 0 };

	while (num_bits > 0) {
		unsigned int chunk = num_bits > CKLINK_MAX_SCAN_BITS
			? CKLINK_MAX_SCAN_BITS : num_bits;
		int ret = cklink_jtag_scan(cklink_handle, 0, NULL,
					   chunk, zeros, NULL);
		if (ret != ERROR_OK)
			return ret;
		num_bits -= chunk;
	}
	return ERROR_OK;
}

static int cklink_execute_scan(struct jtag_command *cmd)
{
	struct scan_command *scan = cmd->cmd.scan;
	struct cklink *ck = cklink_handle;

	unsigned int total_bits = 0;
	for (unsigned int i = 0; i < scan->num_fields; i++)
		total_bits += scan->fields[i].num_bits;

	if (total_bits == 0)
		return ERROR_OK;

	const unsigned int total_bytes = DIV_ROUND_UP(total_bits, 8);
	uint8_t *tdi_buf = calloc(1, total_bytes);
	uint8_t *tdo_buf = calloc(1, total_bytes);
	if (!tdi_buf || !tdo_buf) {
		LOG_ERROR("CK-Link: out of memory for scan buffers");
		free(tdi_buf);
		free(tdo_buf);
		return ERROR_FAIL;
	}

	unsigned int bit_offset = 0;
	for (unsigned int i = 0; i < scan->num_fields; i++) {
		struct scan_field *field = &scan->fields[i];
		if (field->out_value)
			buf_set_buf(field->out_value, 0, tdi_buf,
				    bit_offset, field->num_bits);
		bit_offset += field->num_bits;
	}

	if (scan->ir_scan) {
		/*
		 * Cache the IR scan. The CK-Link JTAG batch requires each
		 * entry to contain both an IR and a DR phase, so we defer
		 * this IR until the next DR scan arrives.
		 */
		if (total_bytes <= sizeof(ck->ir_value)) {
			memcpy(ck->ir_value, tdi_buf, total_bytes);
			ck->ir_bits = total_bits;
		}
		free(tdi_buf);
		free(tdo_buf);
		return ERROR_OK;
	}

	/*
	 * When no IR has been cached yet, send an IDCODE placeholder so the
	 * chip latches IDCODE before the DR shift. This matches the implicit
	 * post-reset IR state and lets OpenOCD's chain detection work.
	 */
	const uint8_t placeholder_ir = CKLINK_PLACEHOLDER_IR_VALUE;
	const unsigned int ir_bits = ck->ir_bits ? ck->ir_bits
			: CKLINK_PLACEHOLDER_IR_BITS;
	const uint8_t *ir_value = ck->ir_bits ? ck->ir_value : &placeholder_ir;

	int ret = cklink_jtag_scan(ck, ir_bits, ir_value,
				   total_bits, tdi_buf, tdo_buf);
	if (ret != ERROR_OK) {
		free(tdi_buf);
		free(tdo_buf);
		return ret;
	}

	bit_offset = 0;
	for (unsigned int i = 0; i < scan->num_fields; i++) {
		struct scan_field *field = &scan->fields[i];
		if (field->in_value)
			buf_set_buf(tdo_buf, bit_offset,
				    field->in_value, 0, field->num_bits);
		bit_offset += field->num_bits;
	}

	free(tdi_buf);
	free(tdo_buf);
	return ERROR_OK;
}

static int cklink_execute_tlr_reset(void)
{
	/*
	 * The wire protocol does not expose a TMS-only sequence opcode, so
	 * we cannot drive TMS=1 for 5 cycles to walk the TAP state machine
	 * into Test-Logic-Reset. Shifting an IR scan with all-ones (the
	 * obvious workaround) only sets the IR to BYPASS and leaves the
	 * state machine in Run-Test/Idle, which is not equivalent.
	 *
	 * The CK-Link Lite is a 5-wire probe and asserts hardware TRST on
	 * init, so we are already in TLR after cklink_init(). Any later
	 * TLR_RESET request from OpenOCD is treated as a state-tracking
	 * no-op: invalidate the cached IR (since hardware TRST would have
	 * loaded IDCODE) and let the next IR scan repopulate it.
	 */
	struct cklink *ck = cklink_handle;

	ck->ir_bits = 0;
	memset(ck->ir_value, 0, sizeof(ck->ir_value));
	tap_set_state(TAP_RESET);
	return ERROR_OK;
}

static int cklink_execute_runtest(struct jtag_command *cmd)
{
	return cklink_idle_cycles(cmd->cmd.runtest->num_cycles);
}

static int cklink_execute_stableclocks(struct jtag_command *cmd)
{
	return cklink_idle_cycles(cmd->cmd.stableclocks->num_cycles);
}

static int cklink_execute_tms(struct jtag_command *cmd)
{
	return cklink_idle_cycles(cmd->cmd.tms->num_bits);
}

static int cklink_execute_reset(struct jtag_command *cmd)
{
	/* Only TRST is meaningful here: we have no separate SRST control. */
	if (cmd->cmd.reset->trst)
		return cklink_execute_tlr_reset();
	return ERROR_OK;
}

static int cklink_execute_queue(struct jtag_command *cmd_queue)
{
	for (struct jtag_command *cmd = cmd_queue; cmd; cmd = cmd->next) {
		int ret;

		switch (cmd->type) {
		case JTAG_SCAN:
			ret = cklink_execute_scan(cmd);
			break;
		case JTAG_TLR_RESET:
			ret = cklink_execute_tlr_reset();
			break;
		case JTAG_RUNTEST:
			ret = cklink_execute_runtest(cmd);
			break;
		case JTAG_RESET:
			ret = cklink_execute_reset(cmd);
			break;
		case JTAG_PATHMOVE:
			/* Not implemented: fall back to a TAP reset. */
			ret = cklink_execute_tlr_reset();
			break;
		case JTAG_STABLECLOCKS:
			ret = cklink_execute_stableclocks(cmd);
			break;
		case JTAG_TMS:
			ret = cklink_execute_tms(cmd);
			break;
		case JTAG_SLEEP:
			jtag_sleep(cmd->cmd.sleep->us);
			ret = ERROR_OK;
			break;
		default:
			LOG_ERROR("CK-Link: unsupported JTAG command %d",
				  cmd->type);
			return ERROR_FAIL;
		}
		if (ret != ERROR_OK)
			return ret;
	}
	return ERROR_OK;
}

static int cklink_probe_init(struct cklink *ck)
{
	uint8_t sr0[CKLINK_SELFREG_BYTES] = { 0 };
	uint8_t sr1[CKLINK_SELFREG_BYTES];
	uint8_t sr8[CKLINK_SELFREG_BYTES];

	sr0[0] = CKLINK_SR0_INIT_CLK_BYTE;
	sr0[3] = CKLINK_SR0_INIT_MODE_BYTE;
	cklink_selfreg_pack_u32(sr1, CKLINK_SR1_INIT_VALUE);
	cklink_selfreg_pack_u32(sr8, CKLINK_SR8_INIT_VALUE);

	int ret = cklink_selfreg_write(ck, CKLINK_SR_CSR, sr0);
	if (ret != ERROR_OK)
		return ret;
	ret = cklink_selfreg_write(ck, CKLINK_SR_MTCR_WAIT, sr1);
	if (ret != ERROR_OK)
		return ret;
	ret = cklink_selfreg_write(ck, CKLINK_SR_JTAG_CONFIG, sr8);
	if (ret != ERROR_OK)
		return ret;

	uint8_t readback[CKLINK_SELFREG_BYTES];
	ret = cklink_selfreg_read(ck, CKLINK_SR_CSR, readback);
	if (ret != ERROR_OK)
		return ret;

	if (readback[3] != CKLINK_SR0_INIT_MODE_BYTE) {
		LOG_WARNING("CK-Link: sr0 mode byte is 0x%02x, expected 0x%02x (5-wire JTAG)",
			    readback[3], CKLINK_SR0_INIT_MODE_BYTE);
	}
	return ERROR_OK;
}

static int cklink_init(void)
{
	struct cklink *ck = calloc(1, sizeof(*ck));
	if (!ck) {
		LOG_ERROR("CK-Link: out of memory");
		return ERROR_JTAG_INIT_FAILED;
	}

	const uint16_t vids[] = {
		CKLINK_VID_BOUFFALO,
		CKLINK_VID_THEAD,
		0
	};
	const uint16_t pids[] = {
		CKLINK_PID_LITE_V2,
		CKLINK_PID_LITE_V2,
		0
	};

	if (jtag_libusb_open(vids, pids, NULL, &ck->usb_dev, NULL) != ERROR_OK) {
		LOG_ERROR("CK-Link probe not found");
		free(ck);
		return ERROR_JTAG_INIT_FAILED;
	}

	int claim = libusb_claim_interface(ck->usb_dev, CKLINK_USB_INTERFACE);
	if (claim != 0) {
		LOG_ERROR("CK-Link: failed to claim interface %d: %s",
			  CKLINK_USB_INTERFACE, libusb_error_name(claim));
		jtag_libusb_close(ck->usb_dev);
		free(ck);
		return ERROR_JTAG_INIT_FAILED;
	}

	if (cklink_probe_init(ck) != ERROR_OK) {
		LOG_ERROR("CK-Link: probe initialization failed");
		libusb_release_interface(ck->usb_dev, CKLINK_USB_INTERFACE);
		jtag_libusb_close(ck->usb_dev);
		free(ck);
		return ERROR_JTAG_INIT_FAILED;
	}

	cklink_handle = ck;
	tap_set_state(TAP_RESET);
	LOG_INFO("CK-Link Lite V2 initialized (5-wire JTAG)");
	return ERROR_OK;
}

static int cklink_quit(void)
{
	if (!cklink_handle)
		return ERROR_OK;

	libusb_release_interface(cklink_handle->usb_dev,
				 CKLINK_USB_INTERFACE);
	jtag_libusb_close(cklink_handle->usb_dev);
	free(cklink_handle);
	cklink_handle = NULL;
	return ERROR_OK;
}

static int cklink_speed(int speed)
{
	/*
	 * The probe uses a fixed clock divider programmed at init time.
	 * Accept any requested speed silently so OpenOCD target scripts
	 * that call "adapter speed" do not fail.
	 */
	return ERROR_OK;
}

static int cklink_khz(int khz, int *jtag_speed)
{
	if (khz == 0) {
		LOG_ERROR("CK-Link: adaptive clocking (RTCK) is not supported");
		return ERROR_FAIL;
	}
	*jtag_speed = khz;
	return ERROR_OK;
}

static int cklink_speed_div(int speed, int *khz)
{
	*khz = speed;
	return ERROR_OK;
}

static struct jtag_interface cklink_jtag_interface = {
	.execute_queue = cklink_execute_queue,
};

struct adapter_driver cklink_adapter_driver = {
	.name			= "cklink",
	.transport_ids		= TRANSPORT_JTAG,
	.transport_preferred_id	= TRANSPORT_JTAG,

	.init			= cklink_init,
	.quit			= cklink_quit,
	.speed			= cklink_speed,
	.khz			= cklink_khz,
	.speed_div		= cklink_speed_div,

	.jtag_ops		= &cklink_jtag_interface,
};
