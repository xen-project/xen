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
// 
// vtpmd.c
// 
//  Application
//
// ===================================================================

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include "vtpm_manager.h"
#include "vtpmpriv.h"
#include "tcg.h"
#include "log.h"
#include "vtpm_ipc.h"

#define TPM_EMULATOR_PATH "/usr/bin/vtpmd"

#define VTPM_BE_FNAME          "/dev/vtpm"
#define VTPM_DUMMY_TX_BE_FNAME "/var/vtpm/fifos/dummy_out.fifo"
#define VTPM_DUMMY_RX_BE_FNAME "/var/vtpm/fifos/dummy_in.fifo"
#define VTPM_TX_TPM_FNAME      "/var/vtpm/fifos/tpm_cmd_to_%d.fifo"
#define VTPM_RX_TPM_FNAME      "/var/vtpm/fifos/tpm_rsp_from_all.fifo"
#define VTPM_TX_VTPM_FNAME     "/var/vtpm/fifos/vtpm_rsp_to_%d.fifo"
#define VTPM_RX_VTPM_FNAME     "/var/vtpm/fifos/vtpm_cmd_from_all.fifo"
#define VTPM_TX_HP_FNAME       "/var/vtpm/fifos/to_console.fifo"
#define VTPM_RX_HP_FNAME       "/var/vtpm/fifos/from_console.fifo"

#define VTPM_TYPE_PVM_STRING "pvm"
#define VTPM_TYPE_HVM_STRING "hvm"

struct vtpm_thread_params_s {
  vtpm_ipc_handle_t *tx_ipc_h;
  vtpm_ipc_handle_t *rx_ipc_h;
  BOOL fw_tpm;
  vtpm_ipc_handle_t *fw_tx_ipc_h;
  vtpm_ipc_handle_t *fw_rx_ipc_h;
  BOOL is_priv;
  char *thread_name;
};

// This is needed to all extra_close_dmi to close this to prevent a
// broken pipe when no DMIs are left.
static vtpm_ipc_handle_t *g_rx_tpm_ipc_h;

void *vtpm_manager_thread(void *arg_void) {
  TPM_RESULT *status = (TPM_RESULT *) malloc(sizeof(TPM_RESULT) );
  struct vtpm_thread_params_s *arg = (struct vtpm_thread_params_s *) arg_void;

  *status = VTPM_Manager_Handler(arg->tx_ipc_h, arg->rx_ipc_h,
                                 arg->fw_tpm, arg->fw_tx_ipc_h, arg->fw_rx_ipc_h,
                                 arg->is_priv, arg->thread_name);

  return (status);
}


void signal_handler(int reason) {
  if (pthread_equal(pthread_self(), vtpm_globals->master_pid)) {
    vtpmloginfo(VTPM_LOG_VTPM, "VTPM Manager shutting down for signal %d.\n", reason);
  } else {
    // For old Linux Thread machines, signals are delivered to each thread. Deal with them.
    vtpmloginfo(VTPM_LOG_VTPM, "Child shutting down\n");
    pthread_exit(NULL);
  }

  VTPM_Stop_Manager();
  exit(-1);
}

struct sigaction ctl_c_handler;

TPM_RESULT VTPM_New_DMI_Extra(VTPM_DMI_RESOURCE *dmi_res, BYTE vm_type, BYTE startup_mode) {

  TPM_RESULT status = TPM_SUCCESS;
  int fh;
  char dmi_id_str[11]; // UINT32s are up to 10 digits + NULL
  char *tx_vtpm_name, *tx_tpm_name, *vm_type_string;
  struct stat file_info;

  if (dmi_res->dmi_id == VTPM_CTL_DM) {
    dmi_res->tx_tpm_ipc_h = NULL;
    dmi_res->rx_tpm_ipc_h = NULL;
    dmi_res->tx_vtpm_ipc_h = NULL;
    dmi_res->rx_vtpm_ipc_h = NULL;
  } else {
    // Create a pair of fifo pipes
    dmi_res->rx_tpm_ipc_h = NULL;
    dmi_res->rx_vtpm_ipc_h = NULL;

    if ( ((dmi_res->tx_tpm_ipc_h = (vtpm_ipc_handle_t *) malloc (sizeof(vtpm_ipc_handle_t))) == NULL ) ||
         ((dmi_res->tx_vtpm_ipc_h =(vtpm_ipc_handle_t *) malloc (sizeof(vtpm_ipc_handle_t))) == NULL ) ||
         ((tx_tpm_name = (char *) malloc(11 + strlen(VTPM_TX_TPM_FNAME))) == NULL ) ||
         ((tx_vtpm_name =(char *) malloc(11 + strlen(VTPM_TX_VTPM_FNAME))) == NULL) ) {
      status =TPM_RESOURCES;
      goto abort_egress;
    }

    sprintf(tx_tpm_name, VTPM_TX_TPM_FNAME, (uint32_t) dmi_res->dmi_id);
    sprintf(tx_vtpm_name, VTPM_TX_VTPM_FNAME, (uint32_t) dmi_res->dmi_id);

    if ( (vtpm_ipc_init(dmi_res->tx_tpm_ipc_h, tx_tpm_name, O_WRONLY | O_NONBLOCK, TRUE) != 0) ||
         (vtpm_ipc_init(dmi_res->tx_vtpm_ipc_h, tx_vtpm_name, O_WRONLY, TRUE) != 0) ) { //FIXME: O_NONBLOCK?
      status = TPM_IOERROR;
      goto abort_egress;
    }

    // Measure DMI
    // FIXME: This will measure DMI. Until then use a fixed DMI_Measurement value
    // Also, this mechanism is specific to 1 VM architecture.
    /*
    fh = open(TPM_EMULATOR_PATH, O_RDONLY);
    stat_ret = fstat(fh, &file_stat);
    if (stat_ret == 0)
      dmi_size = file_stat.st_size;
    else {
      vtpmlogerror(VTPM_LOG_VTPM, "Could not open vtpmd!!\n");
      status = TPM_IOERROR;
      goto abort_egress;
    }
    dmi_buffer
    */
    memset(&dmi_res->DMI_measurement, 0xcc, sizeof(TPM_DIGEST));

    if (vm_type == VTPM_TYPE_PVM)
      vm_type_string = (BYTE *)&VTPM_TYPE_PVM_STRING;
    else
      vm_type_string = (BYTE *)&VTPM_TYPE_HVM_STRING;

    // Launch DMI
    sprintf(dmi_id_str, "%d", (int) dmi_res->dmi_id);
#ifdef MANUAL_DM_LAUNCH
    vtpmlogerror(VTPM_LOG_VTPM, "Manually start VTPM with dmi=%s now.\n", dmi_id_str);
    dmi_res->dmi_pid = 0;
#else
    pid_t pid = fork();

    if (pid == -1) {
      vtpmlogerror(VTPM_LOG_VTPM, "Could not fork to launch vtpm\n");
      status = TPM_RESOURCES;
      goto abort_egress;
    } else if (pid == 0) {
      switch (startup_mode) {
      case TPM_ST_CLEAR:
        execl (TPM_EMULATOR_PATH, "vtpmd", "clear", vm_type_string, dmi_id_str, NULL);
        break;
      case TPM_ST_STATE:
        execl (TPM_EMULATOR_PATH, "vtpmd", "save", vm_type_string, dmi_id_str, NULL);
        break;
      case TPM_ST_DEACTIVATED:
        execl (TPM_EMULATOR_PATH, "vtpmd", "deactivated", vm_type_string, dmi_id_str, NULL);
        break;
      default:
        status = TPM_BAD_PARAMETER;
        goto abort_egress;
      }

      // Returning from these at all is an error.
      vtpmlogerror(VTPM_LOG_VTPM, "Could not exec to launch vtpm\n");
    } else {
      dmi_res->dmi_pid = pid;
      vtpmloginfo(VTPM_LOG_VTPM, "Launching DMI on PID = %d\n", pid);
    }
#endif // MANUAL_DM_LAUNCH

  } // If DMI = VTPM_CTL_DM
    status = TPM_SUCCESS;

abort_egress:
  return (status);
}

TPM_RESULT VTPM_Close_DMI_Extra(VTPM_DMI_RESOURCE *dmi_res) {
  TPM_RESULT status = TPM_SUCCESS;

  if (vtpm_globals->connected_dmis == 0) {
    // No more DMI's connected. Close fifo to prevent a broken pipe.
    // This is hackish. Need to think of another way.
    vtpm_ipc_close(g_rx_tpm_ipc_h);
  }

  
  if (dmi_res->dmi_id != VTPM_CTL_DM) {
    vtpm_ipc_close(dmi_res->tx_tpm_ipc_h);
    vtpm_ipc_close(dmi_res->tx_vtpm_ipc_h);

    free(dmi_res->tx_tpm_ipc_h->name);
    free(dmi_res->tx_vtpm_ipc_h->name);

#ifndef MANUAL_DM_LAUNCH
    if (dmi_res->dmi_id != VTPM_CTL_DM) {
      if (dmi_res->dmi_pid != 0) {
        vtpmloginfo(VTPM_LOG_VTPM, "Killing dmi on pid %d.\n", dmi_res->dmi_pid);
        if (kill(dmi_res->dmi_pid, SIGKILL) !=0) {
          vtpmloginfo(VTPM_LOG_VTPM, "DMI on pid %d is already dead.\n", dmi_res->dmi_pid);
        } else if (waitpid(dmi_res->dmi_pid, NULL, 0) != dmi_res->dmi_pid) {
          vtpmlogerror(VTPM_LOG_VTPM, "DMI on pid %d failed to stop.\n", dmi_res->dmi_pid);
          status = TPM_FAIL;
        }
      } else {
        vtpmlogerror(VTPM_LOG_VTPM, "Could not kill dmi because it's pid was 0.\n");
        status = TPM_FAIL;
      }
    }
#endif

  } //endif ! dom0
  return status;
}


int main(int argc, char **argv) {
  vtpm_ipc_handle_t *tx_be_ipc_h, *rx_be_ipc_h, rx_tpm_ipc_h, rx_vtpm_ipc_h, tx_hp_ipc_h, rx_hp_ipc_h; 
  struct vtpm_thread_params_s be_thread_params, dmi_thread_params, hp_thread_params;
  pthread_t be_thread, dmi_thread, hp_thread;

#ifdef DUMMY_BACKEND
  vtpm_ipc_handle_t tx_dummy_ipc_h, rx_dummy_ipc_h;
#else
  vtpm_ipc_handle_t real_be_ipc_h;
#endif

  vtpmloginfo(VTPM_LOG_VTPM, "Starting VTPM.\n");
 
  // -------------------- Initialize Manager ----------------- 
  if (VTPM_Init_Manager() != TPM_SUCCESS) {
    vtpmlogerror(VTPM_LOG_VTPM, "Closing vtpmd due to error during startup.\n");
    return -1;
  }
  
  // -------------------- Setup Ctrl+C Handlers --------------
  ctl_c_handler.sa_handler = signal_handler;
  sigemptyset(&ctl_c_handler.sa_mask);
  ctl_c_handler.sa_flags = 0;    
  
  if (sigaction(SIGINT, &ctl_c_handler, NULL) == -1) 
    vtpmlogerror(VTPM_LOG_VTPM, "Could not install SIGINT handler. Ctl+break will not stop manager gently.\n");
  
  // For easier debuggin with gdb
  if (sigaction(SIGHUP, &ctl_c_handler, NULL) == -1) 
    vtpmlogerror(VTPM_LOG_VTPM, "Could not install SIGHUP handler. Ctl+break will not stop manager gently.\n");    
  
  sigset_t sig_mask;
  sigemptyset(&sig_mask);
  sigaddset(&sig_mask, SIGPIPE);
  sigprocmask(SIG_BLOCK, &sig_mask, NULL);
  
  // ------------------- Set up file ipc structures ----------
#ifdef DUMMY_BACKEND
  if ( (vtpm_ipc_init(&tx_dummy_ipc_h, VTPM_DUMMY_TX_BE_FNAME, O_RDWR, TRUE) != 0) ||
       (vtpm_ipc_init(&rx_dummy_ipc_h, VTPM_DUMMY_RX_BE_FNAME, O_RDWR, TRUE) != 0) ) {

    vtpmlogerror(VTPM_LOG_VTPM, "Unable to create Dummy BE FIFOs.\n");
    exit(-1);
  }

  tx_be_ipc_h = &tx_dummy_ipc_h;
  rx_be_ipc_h = &rx_dummy_ipc_h;
#else
  vtpm_ipc_init(&real_be_ipc_h, VTPM_BE_FNAME, O_RDWR, FALSE);

  tx_be_ipc_h = &real_be_ipc_h;
  rx_be_ipc_h = &real_be_ipc_h;
#endif

  if ( (vtpm_ipc_init(&rx_tpm_ipc_h, VTPM_RX_TPM_FNAME, O_RDONLY, TRUE) != 0) ||
       (vtpm_ipc_init(&rx_vtpm_ipc_h, VTPM_RX_VTPM_FNAME, O_RDWR, TRUE) != 0) || //FIXME: O_RDONLY?
       (vtpm_ipc_init(&tx_hp_ipc_h,  VTPM_TX_HP_FNAME, O_RDWR, TRUE) != 0)    ||
       (vtpm_ipc_init(&rx_hp_ipc_h,  VTPM_RX_HP_FNAME, O_RDWR, TRUE) != 0) ) {
    vtpmlogerror(VTPM_LOG_VTPM, "Unable to create initial FIFOs.\n");
    exit(-1);
  }

  g_rx_tpm_ipc_h = &rx_tpm_ipc_h;

  // -------------------- Set up thread params ------------- 

  be_thread_params.tx_ipc_h = tx_be_ipc_h;
  be_thread_params.rx_ipc_h = rx_be_ipc_h;
  be_thread_params.fw_tpm = TRUE;
  be_thread_params.fw_tx_ipc_h = NULL;
  be_thread_params.fw_rx_ipc_h = &rx_tpm_ipc_h;
  be_thread_params.is_priv = FALSE;
  be_thread_params.thread_name = "Backend Listener";

  dmi_thread_params.tx_ipc_h = NULL;
  dmi_thread_params.rx_ipc_h = &rx_vtpm_ipc_h;
  dmi_thread_params.fw_tpm = FALSE; 
  dmi_thread_params.fw_tx_ipc_h = NULL;
  dmi_thread_params.fw_rx_ipc_h = NULL;
  dmi_thread_params.is_priv = FALSE; 
  dmi_thread_params.thread_name = "VTPM Listener";

  hp_thread_params.tx_ipc_h = &tx_hp_ipc_h;
  hp_thread_params.rx_ipc_h = &rx_hp_ipc_h;
  hp_thread_params.fw_tpm = FALSE;
  hp_thread_params.fw_tx_ipc_h = NULL;
  hp_thread_params.fw_rx_ipc_h = NULL;
  hp_thread_params.is_priv = TRUE;
  hp_thread_params.thread_name = "Hotplug Listener";

  // --------------------- Launch Threads -----------------

  vtpm_lock_init();

  vtpm_globals->master_pid = pthread_self();
  
  if (pthread_create(&be_thread, NULL, vtpm_manager_thread, &be_thread_params) != 0) {
    vtpmlogerror(VTPM_LOG_VTPM, "Failed to launch BE Thread.\n");
    exit(-1);
  }
  
  if (pthread_create(&dmi_thread, NULL, vtpm_manager_thread, &dmi_thread_params) != 0) {
    vtpmlogerror(VTPM_LOG_VTPM, "Failed to launch DMI Thread.\n");
    exit(-1);
  }

 
  if (pthread_create(&hp_thread, NULL, vtpm_manager_thread, &hp_thread_params) != 0) {
    vtpmlogerror(VTPM_LOG_VTPM, "Failed to launch HP Thread.\n");
    exit(-1);
  }
 
  //Join the other threads until exit time.
  pthread_join(be_thread, NULL);
  pthread_join(dmi_thread, NULL);
  pthread_join(hp_thread, NULL);
 
  vtpmlogerror(VTPM_LOG_VTPM, "VTPM Manager shut down unexpectedly.\n");
 
  VTPM_Stop_Manager();
  vtpm_lock_destroy();
  return 0;
}
