/*\
 *  Copyright (C) International Business Machines  Corp., 2005
 *  Author(s): Anthony Liguori <aliguori@us.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
\*/

#include <stdio.h>
#include <stdarg.h>

#include "dump.h"

#define str(a) # a
#define error(a, ...) do { \
 _error("%s:%s():L%d: " a, __FILE__, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
  exit(1); \
} while (0)
#define warn(a, ...) do { \
 _error("%s:%s():L%d: " a, __FILE__, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#define debug(a, ...) do { \
 _error(a, ## __VA_ARGS__);\
} while (0)

void _error(const char *fmt, ...);

#define debug_begin(a, b) debug("CMSG_" a "_" b " {")
#define debug_end(a, b) debug("}")
#define debug_field(a, b, c) debug("\t." str(b) " = " c, a->b)
#define debug_field_mac(a, b) \
  debug("\t." str(b) " = %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", \
        a->b[0], a->b[1], a->b[2], a->b[3], a->b[4], a->b[5])

#define debug_dump(a, b, c) debug_hex("\t." str(b) " = ", a->b, a->c)

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static int strcount(const char *str, char ch)
{
	int i;
	int count = 0;

	for (i = 0; str[i]; i++) {
		if (str[i] == ch) {
			count++;
		}
	}

	return count;
}

void debug_hex(const char *info, const uint8_t *data, size_t length)
{
	int indent = strlen(info) + (strcount(info, '\t') * 8 - 1);
	int words_per_row = (2 * (80 - indent - 2) / 7) & ~1;
	size_t i;

	for (i = 0; i < length; i += words_per_row) {
		size_t ind;

		if (i == 0) {
			fprintf(stderr, "%s", info);
		} else {
			int j;
			for (j = 0; j < indent; j++) {
				fprintf(stderr, " ");
			}
		}

		for (ind = 0; ind < words_per_row; ind++) {
			if (ind % 2 == 0) {
				fprintf(stderr, " ");
			}

			if (i + ind < length) {
				fprintf(stderr, "%.2X", data[i + ind]);
			} else {
				fprintf(stderr, "  ");
			}
		}

		fprintf(stderr, " ");

		for (ind = 0; ind < words_per_row; ind++) {
			if (i + ind < length) {
				if (isprint(data[i + ind])) {
					fprintf(stderr, "%c", data[i + ind]);
				} else {
					fprintf(stderr, ".");
				}
			} else {
				fprintf(stderr, " ");
			}
		}
		fprintf(stderr, "\n");
	}
}

void dump_msg(const control_msg_t *msg, uint64_t flags)
{
	if ((flags & (1 << msg->type)) == 0) {
		return;
	}

	switch (msg->type) {
	case CMSG_CONSOLE:
		if (msg->subtype == CMSG_CONSOLE_DATA) {
			debug_begin("CONSOLE", "DATA");
			debug_field(msg, length, "%u");
			debug_dump(msg, msg, length);
			debug_end("CONSOLE", "DATA");
		} else {
			debug_begin("CONSOLE", "UNKNOWN");
			debug_field(msg, subtype, "%u");
			debug_field(msg, length, "%u");
			debug_dump(msg, msg, length);
			debug_end("CONSOLE", "UNKNOWN");
		}
		break;
	case CMSG_BLKIF_BE:
		if (msg->subtype == CMSG_BLKIF_BE_CREATE) {
			blkif_be_create_t *load;
			load = (blkif_be_create_t *)msg->msg;
			debug_begin("BLKIF_BE", "CREATE");
			debug_field(load, domid, "%u");
			debug_field(load, blkif_handle, "%u");
			debug_field(load, status, "%u");
			debug_end("BLKIF_BE", "CREATE");
		} else if (msg->subtype == CMSG_BLKIF_BE_DESTROY) {
			blkif_be_destroy_t *load;
			load = (blkif_be_destroy_t *)msg->msg;
			debug_begin("BLKIF_BE", "DESTROY");
			debug_field(load, domid, "%u");
			debug_field(load, blkif_handle, "%u");
			debug_field(load, status, "%u");
			debug_end("BLKIF_BE", "DESTROY");
		} else if (msg->subtype == CMSG_BLKIF_BE_CONNECT) {
			blkif_be_connect_t *load;
			load = (blkif_be_connect_t *)msg->msg;
			debug_begin("BLKIF_BE", "CONNECT");
			debug_field(load, domid, "%u");
			debug_field(load, blkif_handle, "%u");
			debug_field(load, shmem_frame, "%lu");
			debug_field(load, evtchn, "%u");
			debug_field(load, status, "%u");
			debug_end("BLKIF_BE", "CONNECT");
		} else if (msg->subtype == CMSG_BLKIF_BE_DISCONNECT) {
			blkif_be_disconnect_t *load;
			load = (blkif_be_disconnect_t *)msg->msg;
			debug_begin("BLKIF_BE", "DISCONNECT");
			debug_field(load, domid, "%u");
			debug_field(load, blkif_handle, "%u");
			debug_field(load, status, "%u");
			debug_end("BLKIF_BE", "DISCONNECT");
		} else if (msg->subtype == CMSG_BLKIF_BE_VBD_CREATE) {
			blkif_be_vbd_create_t *load;
			load = (blkif_be_vbd_create_t *)msg->msg;
			debug_begin("BLKIF_BE", "VBD_CREATE");
			debug_field(load, domid, "%u");
			debug_field(load, blkif_handle, "%u");
			debug_field(load, vdevice, "%u");
			debug_field(load, readonly, "%u");
			debug_field(load, status, "%u");
			debug_end("BLKIF_BE", "VBD_CREATE");
		} else if (msg->subtype == CMSG_BLKIF_BE_VBD_DESTROY) {
			blkif_be_vbd_destroy_t *load;
			load = (blkif_be_vbd_destroy_t *)msg->msg;
			debug_begin("BLKIF_BE", "VBD_DESTROY");
			debug_field(load, domid, "%u");
			debug_field(load, blkif_handle, "%u");
			debug_field(load, vdevice, "%u");
			debug_field(load, status, "%u");
			debug_end("BLKIF_BE", "VBD_DESTROY");
		} else if (msg->subtype == CMSG_BLKIF_BE_VBD_GROW) {
			blkif_be_vbd_grow_t *load;
			load = (blkif_be_vbd_grow_t *)msg->msg;
			debug_begin("BLKIF_BE", "VBD_GROW");
			debug_field(load, domid, "%u");
			debug_field(load, blkif_handle, "%u");
			debug_field(load, extent.sector_start, "%llu");
			debug_field(load, extent.sector_length, "%llu");
			debug_field(load, extent.device, "%u");
			debug_field(load, vdevice, "%u");
			debug_field(load, status, "%u");
			debug_end("BLKIF_BE", "VBD_GROW");
		} else if (msg->subtype == CMSG_BLKIF_BE_VBD_SHRINK) {
			blkif_be_vbd_shrink_t *load;
			load = (blkif_be_vbd_shrink_t *)msg->msg;
			debug_begin("BLKIF_BE", "VBD_SHRINK");
			debug_field(load, domid, "%u");
			debug_field(load, blkif_handle, "%u");
			debug_field(load, vdevice, "%u");
			debug_field(load, status, "%u");
			debug_end("BLKIF_BE", "VBD_SHRINK");
		} else if (msg->subtype == CMSG_BLKIF_BE_DRIVER_STATUS) {
			blkif_be_driver_status_t *load;
			load = (blkif_be_driver_status_t *)msg->msg;
			debug_begin("BLKIF_BE", "DRIVER_STATUS");
			debug_field(load, status, "%u");
			debug_end("BLKIF_BE", "DRIVER_STATUS");
		} else {
			debug_begin("BLKIF_BE", "UNKNOWN");
			debug_field(msg, subtype, "%u");
			debug_field(msg, length, "%u");
			debug_dump(msg, msg, length);
			debug_end("BLKIF_BE", "UNKNOWN");
		}
		break;
	case CMSG_BLKIF_FE:
		if (msg->subtype == CMSG_BLKIF_FE_INTERFACE_STATUS) {
			blkif_fe_interface_status_t *load;
			load = (blkif_fe_interface_status_t *)msg->msg;
			debug_begin("BLKIF_FE", "INTERFACE_STATUS");
			debug_field(load, handle, "%u");
			debug_field(load, status, "%u");
			debug_field(load, evtchn, "%u");
			debug_field(load, domid, "%u");
			debug_end("BLKIF_FE", "INTERFACE_STATUS");
		} else if (msg->subtype == CMSG_BLKIF_FE_DRIVER_STATUS) {
			blkif_fe_driver_status_t *load;
			load = (blkif_fe_driver_status_t *)msg->msg;
			debug_begin("BLKIF_FE", "DRIVER_STATUS");
			debug_field(load, status, "%u");
			debug_field(load, max_handle, "%u");
			debug_end("BLKIF_FE", "DRIVER_STATUS");
		} else if (msg->subtype == CMSG_BLKIF_FE_INTERFACE_CONNECT) {
			blkif_fe_interface_connect_t *load;
			load = (blkif_fe_interface_connect_t *)msg->msg;
			debug_begin("BLKIF_FE", "INTERFACE_CONNECT");
			debug_field(load, handle, "%u");
			debug_field(load, shmem_frame, "%lu");
			debug_end("BLKIF_FE", "INTERFACE_CONNECT");
		} else if (msg->subtype == CMSG_BLKIF_FE_INTERFACE_DISCONNECT) {
			blkif_fe_interface_disconnect_t *load;
			load = (blkif_fe_interface_disconnect_t *)msg->msg;
			debug_begin("BLKIF_FE", "INTERFACE_DISCONNECT");
			debug_field(load, handle, "%u");
			debug_end("BLKIF_FE", "INTERFACE_DISCONNECT");
		} else if (msg->subtype == CMSG_BLKIF_FE_INTERFACE_QUERY) {
			blkif_fe_interface_query_t *load;
			load = (blkif_fe_interface_query_t *)msg->msg;
			debug_begin("BLKIF_FE", "INTERFACE_QUERY");
			debug_field(load, handle, "%u");
			debug_field(load, status, "%u");
			debug_field(load, evtchn, "%u");
			debug_field(load, domid, "%u");
			debug_end("BLKIF_FE", "INTERFACE_QUERY");
		} else {
			debug_begin("BLKIF_FE", "UNKNOWN");
			debug_field(msg, subtype, "%u");
			debug_field(msg, length, "%u");
			debug_dump(msg, msg, length);
			debug_end("BLKIF_FE", "UNKNOWN");
		}
		break;
	case CMSG_NETIF_BE:
		if (msg->subtype == CMSG_NETIF_BE_CREATE) {
			netif_be_create_t *load;
			load = (netif_be_create_t *)msg->msg;
			debug_begin("NETIF_BE", "CREATE");
			debug_field(load, domid, "%u");
			debug_field(load, netif_handle, "%u");
			debug_field_mac(load, mac);
			debug_field_mac(load, be_mac);
			debug_field(load, status, "%u");
			debug_end("NETIF_BE", "CREATE");
		} else if (msg->subtype == CMSG_NETIF_BE_DESTROY) {
			netif_be_destroy_t *load;
			load = (netif_be_destroy_t *)msg->msg;
			debug_begin("NETIF_BE", "DESTROY");
			debug_field(load, domid, "%u");
			debug_field(load, netif_handle, "%u");
			debug_field(load, status, "%u");
			debug_end("NETIF_BE", "DESTROY");
		} else if (msg->subtype == CMSG_NETIF_BE_CONNECT) {
			netif_be_connect_t *load;
			load = (netif_be_connect_t *)msg->msg;
			debug_begin("NETIF_BE", "CONNECT");
			debug_field(load, domid, "%u");
			debug_field(load, netif_handle, "%u");
			debug_field(load, tx_shmem_frame, "%lu");
			debug_field(load, rx_shmem_frame, "%lu");
			debug_field(load, evtchn, "%u");
			debug_field(load, status, "%u");
			debug_end("NETIF_BE", "CONNECT");
		} else if (msg->subtype == CMSG_NETIF_BE_DISCONNECT) {
			netif_be_disconnect_t *load;
			load = (netif_be_disconnect_t *)msg->msg;
			debug_begin("NETIF_BE", "DISCONNECT");
			debug_field(load, domid, "%u");
			debug_field(load, netif_handle, "%u");
			debug_field(load, status, "%u");
			debug_end("NETIF_BE", "DISCONNECT");
		} else if (msg->subtype == CMSG_NETIF_BE_DRIVER_STATUS) {
			netif_be_driver_status_t *load;
			load = (netif_be_driver_status_t *)msg->msg;
			debug_begin("NETIF_BE", "DRIVER_STATUS");
			debug_field(load, status, "%u");
			debug_end("NETIF_BE", "DRIVER_STATUS");
		} else {
			debug_begin("NETIF_BE", "UNKNOWN");
			debug_field(msg, subtype, "%u");
			debug_field(msg, length, "%u");
			debug_dump(msg, msg, length);
			debug_end("NETIF_BE", "UNKNOWN");
		}
		break;
	case CMSG_NETIF_FE:
		if (msg->subtype == CMSG_NETIF_FE_INTERFACE_STATUS) {
			netif_fe_interface_status_t *load;
			load = (netif_fe_interface_status_t *)msg->msg;
			debug_begin("NETIF_FE", "INTERFACE_STATUS");
			debug_field(load, handle, "%u");
			debug_field(load, status, "%u");
			debug_field(load, evtchn, "%u");
			debug_field_mac(load, mac);
			debug_field(load, domid, "%u");
			debug_end("NETIF_FE", "INTERFACE_STATUS");
		} else if (msg->subtype == CMSG_NETIF_FE_DRIVER_STATUS) {
			netif_fe_driver_status_t *load;
			load = (netif_fe_driver_status_t *)msg->msg;
			debug_begin("NETIF_FE", "DRIVER_STATUS");
			debug_field(load, status, "%u");
			debug_field(load, max_handle, "%u");
			debug_end("NETIF_FE", "DRIVER_STATUS");
		} else if (msg->subtype == CMSG_NETIF_FE_INTERFACE_CONNECT) {
			netif_fe_interface_connect_t *load;
			load = (netif_fe_interface_connect_t *)msg->msg;
			debug_begin("NETIF_FE", "INTERFACE_CONNECT");
			debug_field(load, handle, "%u");
			debug_field(load, tx_shmem_frame, "%lu");
			debug_field(load, rx_shmem_frame, "%lu");
			debug_end("NETIF_FE", "INTERFACE_CONNECT");
		} else if (msg->subtype == CMSG_NETIF_FE_INTERFACE_DISCONNECT) {
			netif_fe_interface_disconnect_t *load;
			load = (netif_fe_interface_disconnect_t *)msg->msg;
			debug_begin("NETIF_FE", "INTERFACE_DISCONNECT");
			debug_field(load, handle, "%u");
			debug_end("NETIF_FE", "INTERFACE_DISCONNECT");
		} else if (msg->subtype == CMSG_NETIF_FE_INTERFACE_QUERY) {
			netif_fe_interface_query_t *load;
			load = (netif_fe_interface_query_t *)msg->msg;
			debug_begin("NETIF_FE", "INTERFACE_QUERY");
			debug_field(load, handle, "%u");
			debug_field(load, status, "%u");
			debug_field(load, evtchn, "%u");
			debug_field_mac(load, mac);
			debug_field(load, domid, "%u");
			debug_end("NETIF_FE", "INTERFACE_QUERY");
		} else {
			debug_begin("NETIF_FE", "UNKNOWN");
			debug_field(msg, subtype, "%u");
			debug_field(msg, length, "%u");
			debug_dump(msg, msg, length);
			debug_end("NETIF_FE", "UNKNOWN");
		}
		break;
	case CMSG_SHUTDOWN:
		if (msg->subtype == CMSG_SHUTDOWN_POWEROFF) {
			debug_begin("SHUTDOWN", "POWEROFF");
			debug_end("SHUTDOWN", "POWEROFF");
		} else if (msg->subtype == CMSG_SHUTDOWN_REBOOT) {
			debug_begin("SHUTDOWN", "REBOOT");
			debug_end("SHUTDOWN", "REBOOT");
		} else if (msg->subtype == CMSG_SHUTDOWN_SUSPEND) {
			debug_begin("SHUTDOWN", "SUSPEND");
			debug_end("SHUTDOWN", "SUSPEND");
		} else if (msg->subtype == CMSG_SHUTDOWN_SYSRQ) {
			debug_begin("SHUTDOWN", "SYSRQ");
			debug_end("SHUTDOWN", "SYSRQ");
		} else {
			debug_begin("SHUTDOWN", "UNKNOWN");
			debug_field(msg, subtype, "%u");
			debug_field(msg, length, "%u");
			debug_dump(msg, msg, length);
			debug_end("SHUTDOWN", "UNKNOWN");
		}		
		break;
	case CMSG_MEM_REQUEST:
		if (msg->subtype == CMSG_MEM_REQUEST_SET) {
			mem_request_t *load;
			load = (mem_request_t *)msg->msg;
			debug_begin("MEM_REQUEST", "SET");
			debug_field(load, target, "%u");
			debug_field(load, status, "%u");
			debug_end("MEM_REQUEST", "SET");
		} else {
			debug_begin("MEM_REQUEST", "UNKNOWN");
			debug_field(msg, subtype, "%u");
			debug_field(msg, length, "%u");
			debug_dump(msg, msg, length);
			debug_end("MEM_REQUEST", "UNKNOWN");
		}		
		break;
	case CMSG_USBIF_BE:
		if (msg->subtype == CMSG_USBIF_BE_CREATE) {
			usbif_be_create_t *load;
			load = (usbif_be_create_t *)msg->msg;
			debug_begin("USBIF_BE", "CREATE");
			debug_field(load, domid, "%u");
			debug_field(load, status, "%u");
			debug_end("USBIF_BE", "CREATE");
		} else if (msg->subtype == CMSG_USBIF_BE_DESTROY) {
			usbif_be_destroy_t *load;
			load = (usbif_be_destroy_t *)msg->msg;
			debug_begin("USBIF_BE", "DESTROY");
			debug_field(load, domid, "%u");
			debug_field(load, status, "%u");
			debug_end("USBIF_BE", "DESTROY");
		} else if (msg->subtype == CMSG_USBIF_BE_CONNECT) {
			usbif_be_connect_t *load;
			load = (usbif_be_connect_t *)msg->msg;
			debug_begin("USBIF_BE", "CONNECT");
			debug_field(load, domid, "%u");
			debug_field(load, shmem_frame, "%lu");
			debug_field(load, evtchn, "%u");
			debug_field(load, bandwidth, "%u");
			debug_field(load, status, "%u");
			debug_end("USBIF_BE", "CONNECT");
		} else if (msg->subtype == CMSG_USBIF_BE_DISCONNECT) {
			usbif_be_disconnect_t *load;
			load = (usbif_be_disconnect_t *)msg->msg;
			debug_begin("USBIF_BE", "DISCONNECT");
			debug_field(load, domid, "%u");
			debug_field(load, status, "%u");
			debug_end("USBIF_BE", "DISCONNECT");
		} else if (msg->subtype == CMSG_USBIF_BE_CLAIM_PORT) {
			usbif_be_claim_port_t *load;
			load = (usbif_be_claim_port_t *)msg->msg;
			debug_begin("USBIF_BE", "CLAIM_PORT");
			debug_field(load, domid, "%u");
			debug_field(load, usbif_port, "%u");
			debug_field(load, status, "%u");
			debug_field(load, path, "%s");
			debug_end("USBIF_BE", "CLAIM_PORT");
		} else if (msg->subtype == CMSG_USBIF_BE_RELEASE_PORT) {
			usbif_be_release_port_t *load;
			load = (usbif_be_release_port_t *)msg->msg;
			debug_begin("USBIF_BE", "RELEASE_PORT");
			debug_field(load, path, "%s");
			debug_end("USBIF_BE", "RELEASE_PORT");
		} else if (msg->subtype == CMSG_USBIF_BE_DRIVER_STATUS_CHANGED) {
			usbif_be_driver_status_changed_t *load;
			load = (usbif_be_driver_status_changed_t *)msg->msg;
			debug_begin("USBIF_BE", "DRIVER_STATUS_CHANGED");
			debug_field(load, status, "%u");
			debug_end("USBIF_BE", "DRIVER_STATUS_CHANGED");
		} else {
			debug_begin("USBIF_BE", "UNKNOWN");
			debug_field(msg, subtype, "%u");
			debug_field(msg, length, "%u");
			debug_dump(msg, msg, length);
			debug_end("USBIF_BE", "UNKNOWN");
		}
		break;
	case CMSG_USBIF_FE:
		if (msg->subtype == CMSG_USBIF_FE_INTERFACE_STATUS_CHANGED) {
			usbif_fe_interface_status_changed_t *load;
			load = (usbif_fe_interface_status_changed_t *)msg->msg;
			debug_begin("USBIF_FE", "INTERFACE_STATUS_CHANGED");
			debug_field(load, status, "%u");
			debug_field(load, evtchn, "%u");
			debug_field(load, domid, "%u");
			debug_field(load, bandwidth, "%u");
			debug_field(load, num_ports, "%u");
			debug_end("USBIF_FE", "INTERFACE_STATUS_CHANGED");
		} else if (msg->subtype == CMSG_USBIF_FE_DRIVER_STATUS_CHANGED) {
			usbif_fe_driver_status_changed_t *load;
			load = (usbif_fe_driver_status_changed_t *)msg->msg;
			debug_begin("USBIF_FE", "DRIVER_STATUS_CHANGED");
			debug_field(load, status, "%u");
			debug_end("USBIF_FE", "DRIVER_STATUS_CHANGED");
		} else if (msg->subtype == CMSG_USBIF_FE_INTERFACE_CONNECT) {
			usbif_fe_interface_connect_t *load;
			load = (usbif_fe_interface_connect_t *)msg->msg;
			debug_begin("USBIF_FE", "INTERFACE_CONNECT");
			debug_field(load, shmem_frame, "%lu");
			debug_end("USBIF_FE", "INTERFACE_CONNECT");
		} else if (msg->subtype == CMSG_USBIF_FE_INTERFACE_DISCONNECT) {
			debug_begin("USBIF_FE", "INTERFACE_DISCONNECT");
			debug_end("USBIF_FE", "INTERFACE_DISCONNECT");
		} else {
			debug_begin("USBIF_FE", "UNKNOWN");
			debug_field(msg, subtype, "%u");
			debug_field(msg, length, "%u");
			debug_dump(msg, msg, length);
			debug_end("USBIF_FE", "UNKNOWN");
		}
		break;
	default:
		debug_begin("UNKNOWN", "UNKNOWN");
		debug_field(msg, type, "%u");
		debug_field(msg, subtype, "%u");
		debug_field(msg, length, "%u");
		debug_dump(msg, msg, length);
		debug_end("UNKNOWN", "UNKNOWN");
		break;
	}
}

void _error(const char *fmt, ...)
{
	va_list ap;
	char buffer[4096];

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	fprintf(stderr, "%s\n", buffer);
}

