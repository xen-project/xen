// ===================================================================
//
// Copyright (c) 2005, Intel Corp.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following
//     disclaimer in the documentation and/or other materials provided
//     with the distribution.
//   * Neither the name of Intel Corporation nor the names of its
//     contributors may be used to endorse or promote products derived
//     from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// OF THE POSSIBILITY OF SUCH DAMAGE.
// ===================================================================

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "tcg.h"
#include "log.h"
#include "bsg.h"
#include "buffer.h"
#include "vtpm_migrator.h"

void build_error_msg( buffer_t *buf, TPM_RESULT status) {
  TPM_TAG tag = VTPM_MTAG_RSP;
  UINT32 out_param_size = VTPM_COMMAND_HEADER_SIZE;

  buffer_init(buf, out_param_size, NULL);
 
  BSG_PackList(buf->bytes, 3,
                 BSG_TPM_TAG, &tag,
                 BSG_TYPE_UINT32, &out_param_size,
                 BSG_TPM_RESULT, &status );
}

int main() {

    /* network variables */
    int sock_descr, client_sock=-1, len;
    struct sockaddr_in addr;
    struct sockaddr_in client_addr;
    unsigned int client_length;
    int bytes;

    /* variables for processing of command */
    TPM_RESULT status = TPM_FAIL;
    BYTE cmd_header[VTPM_COMMAND_HEADER_SIZE];
    TPM_TAG tag;
    TPM_COMMAND_CODE ord;
    UINT32 in_param_size, adj_param_size;
    int i, size_read, size_write;
    buffer_t in_param_buf=NULL_BUF, result_buf=NULL_BUF;


    /* setup socket */
    sock_descr = socket(AF_INET, SOCK_STREAM, 0);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(VTPM_MIG_PORT);

    if (bind(sock_descr, (struct sockaddr *)&addr, sizeof(addr)) == -1 ) {
        vtpmlogerror(VTPM_LOG_VTPM, "Failed to bind to port %d.\n", VTPM_MIG_PORT);
        return 1;
    }
        
    listen(sock_descr, 10);

    for(;;) {
        // ============ clear client info and wait for connection ==========
        memset(&client_addr, 0, sizeof(client_addr));
        client_length = sizeof(client_addr);

        vtpmloginfo(VTPM_LOG_VTPM, "Waiting for incoming migrations...\n");
        client_sock=accept(sock_descr, &client_addr, &client_length);
        if (client_sock == -1) {
            vtpmlogerror(VTPM_LOG_VTPM, "Incoming connectionn failed.\n");
            goto abort_command;
        } else {
            vtpmloginfo(VTPM_LOG_VTPM, "Incoming connection accepted.\n");
        }

        // =================== Read incoming command ======================
        size_read = read( client_sock, cmd_header, VTPM_COMMAND_HEADER_SIZE);
        if (size_read > 0) {
            vtpmloginfo(VTPM_LOG_VTPM_DEEP, "RECV: 0x");
            for (i=0; i<size_read; i++)
                vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", cmd_header[i]);

        } else {
            vtpmlogerror(VTPM_LOG_VTPM, "Error reading from socket.\n");
            build_error_msg(&result_buf, TPM_IOERROR);
            goto abort_command_with_error;
        }

        if (size_read < (int) VTPM_COMMAND_HEADER_SIZE) {
            vtpmlogerror(VTPM_LOG_VTPM, "Command from socket shorter than std header.\n");
            build_error_msg(&result_buf, TPM_BAD_PARAMETER);
            goto abort_command_with_error;
        }

        // Unpack response from client
        BSG_UnpackList(cmd_header, 3,
                       BSG_TPM_TAG, &tag,
                       BSG_TYPE_UINT32, &in_param_size,
                       BSG_TPM_COMMAND_CODE, &ord );


        // If response has parameters, read them.
        // Note that out_param_size is in the client's context
        adj_param_size = in_param_size - VTPM_COMMAND_HEADER_SIZE;
        if (adj_param_size > 0) {
            buffer_init( &in_param_buf, adj_param_size, NULL);
            size_read = read(client_sock, in_param_buf.bytes, adj_param_size);
            if (size_read > 0) {
                for (i=0; i< size_read; i++)
                vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", in_param_buf.bytes[i]);

            } else {
                vtpmlogerror(VTPM_LOG_VTPM, "Error reading from socket.\n");
                build_error_msg(&result_buf, TPM_IOERROR);
                goto abort_command_with_error;
            }
            vtpmloginfomore(VTPM_LOG_VTPM, "\n");

            if (size_read < (int)adj_param_size) {
                vtpmloginfomore(VTPM_LOG_VTPM, "\n");
                vtpmlogerror(VTPM_LOG_VTPM, "Command read(%d) is shorter than header indicates(%d).\n", size_read, adj_param_size);
                build_error_msg(&result_buf, TPM_BAD_PARAMETER);
                goto abort_command_with_error;
            }
        } else {
            vtpmloginfomore(VTPM_LOG_VTPM, "\n");
        }

        /* Handle Command */
        switch (ord) {
        case VTPM_MORD_MIG_STEP2:
          handle_vtpm_mig_step2(&in_param_buf, &result_buf);
          break;
 
        case VTPM_MORD_MIG_STEP3:
          handle_vtpm_mig_step3(&in_param_buf, &result_buf);
          break;

        default:
            build_error_msg(&result_buf, TPM_BAD_PARAMETER);
            goto abort_command_with_error;
        }

  abort_command_with_error:
        /* Write Response */
        size_write = write(client_sock, result_buf.bytes, buffer_len(&result_buf));

        if (size_write > 0) {
            vtpmloginfo(VTPM_LOG_VTPM_DEEP, "SENT: 0x");
            for (i=0; i< buffer_len(&result_buf); i++) {
                vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", result_buf.bytes[i]);
            }
            vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
        } else {
            vtpmlogerror(VTPM_LOG_VTPM, "Error writing response to client.\n");
            goto abort_command;
        }

        if (size_write != (int) buffer_len(&result_buf) )
           vtpmlogerror(VTPM_LOG_VTPM, "Could not send entire response to client(%d/%d)\n", size_write, buffer_len(&result_buf));

  abort_command:
        close(client_sock);
        buffer_free(&in_param_buf);
        buffer_free(&result_buf);

    } // For (;;)

    return 0;
}

