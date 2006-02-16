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
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "vtpm_manager.h"
#include "vtpmpriv.h"
#include "tcg.h"
#include "log.h"

#ifndef VTPM_MULTI_VM
 #include <pthread.h>
#endif

void signal_handler(int reason) {
#ifndef VTPM_MULTI_VM

  if (pthread_equal(pthread_self(), vtpm_globals->master_pid)) {
    vtpmloginfo(VTPM_LOG_VTPM, "VTPM Manager shutting down for signal %d.\n", reason);
  } else {
    // For old Linux Thread machines, signals are delivered to each thread. Deal with them.
    vtpmloginfo(VTPM_LOG_VTPM, "Child shutting down\n");
    pthread_exit(NULL);
  }
#endif
  VTPM_Stop_Service();
  exit(-1);
}

struct sigaction ctl_c_handler;

int main(int argc, char **argv) {

  vtpmloginfo(VTPM_LOG_VTPM, "Starting VTPM.\n");
  
  if (VTPM_Init_Service() != TPM_SUCCESS) {
    vtpmlogerror(VTPM_LOG_VTPM, "Closing vtpmd due to error during startup.\n");
    return -1;
  }
  
  ctl_c_handler.sa_handler = signal_handler;
  sigemptyset(&ctl_c_handler.sa_mask);
  ctl_c_handler.sa_flags = 0;    
  
  if (sigaction(SIGINT, &ctl_c_handler, NULL) == -1) 
    vtpmlogerror(VTPM_LOG_VTPM, "Could not install SIGINT handler. Ctl+break will not stop service gently.\n");
  
  // For easier debuggin with gdb
  if (sigaction(SIGHUP, &ctl_c_handler, NULL) == -1) 
    vtpmlogerror(VTPM_LOG_VTPM, "Could not install SIGHUP handler. Ctl+break will not stop service gently.\n");    
  
#ifdef VTPM_MULTI_VM
  TPM_RESULT status = VTPM_Service_Handler();
    
  if (status != TPM_SUCCESS) 
    vtpmlogerror(VTPM_LOG_VTPM, "VTPM Manager exited with status %s. It never should exit.\n", tpm_get_error_name(status));
  
  return -1;
#else
  sigset_t sig_mask;
      
  sigemptyset(&sig_mask);
  sigaddset(&sig_mask, SIGPIPE);
  sigprocmask(SIG_BLOCK, &sig_mask, NULL);
  //pthread_mutex_init(&vtpm_globals->dmi_mutex, NULL);
  pthread_t be_thread, dmi_thread;
  int betype_be, dmitype_dmi;
  
  vtpm_globals->master_pid = pthread_self();
  
  betype_be = BE_LISTENER_THREAD;
  if (pthread_create(&be_thread, NULL, VTPM_Service_Handler, &betype_be) != 0) {
    vtpmlogerror(VTPM_LOG_VTPM, "Failed to launch BE Thread.\n");
    exit(-1);
  }
  
  dmitype_dmi = DMI_LISTENER_THREAD;
  if (pthread_create(&dmi_thread, NULL, VTPM_Service_Handler, &dmitype_dmi) != 0) {
    vtpmlogerror(VTPM_LOG_VTPM, "Failed to launch DMI Thread.\n");
    exit(-1);
  }
  
  //Join the other threads until exit time.
  pthread_join(be_thread, NULL);
  pthread_join(dmi_thread, NULL);
#endif
 
  vtpmlogerror(VTPM_LOG_VTPM, "VTPM Manager shut down unexpectedly.\n");
 
  VTPM_Stop_Service();
  return 0;
}
