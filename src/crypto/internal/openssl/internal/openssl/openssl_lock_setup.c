// Copyright (c) Microsoft Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

#include "goopenssl.h"

#include <pthread.h>
 
/* This array will store all of the mutexes available to OpenSSL. */ 
static pthread_mutex_t *mutex_buf = NULL;
 
static void locking_function(int mode, int n, const char *file, int line)
{
  if(mode & CRYPTO_LOCK)
    pthread_mutex_lock(&mutex_buf[n]);
  else
    pthread_mutex_unlock(&mutex_buf[n]);
}
 
int _goboringcrypto_internal_OPENSSL_thread_setup(void)
{
  int i;
 
  mutex_buf = malloc(_goboringcrypto_internal_CRYPTO_num_locks() * sizeof(pthread_mutex_t));
  if(!mutex_buf)
    return 0;
  for(i = 0;  i < _goboringcrypto_internal_CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&mutex_buf[i], NULL);
  }
  _goboringcrypto_internal_CRYPTO_set_id_callback(pthread_self);
  _goboringcrypto_internal_CRYPTO_set_locking_callback(locking_function);
  return 1;
}
