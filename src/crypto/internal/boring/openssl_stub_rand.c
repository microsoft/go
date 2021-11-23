// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

#include "goboringcrypto.h"
#include <openssl/rand.h>

static RAND_METHOD fake_rand;
static const RAND_METHOD *old_rand;

int _goboringcrypto_stub_openssl_rand(void)
{
    /* save old rand method */
    if ((old_rand = _goboringcrypto_RAND_get_rand_method()) == NULL)
        return 0;

    fake_rand = *old_rand;
    /* use own random function */
    fake_rand.bytes = fbytes;

    /* set new RAND_METHOD */
    if (!_goboringcrypto_RAND_set_rand_method(&fake_rand))
        return 0;
    return 1;
}

int _goboringcrypto_restore_openssl_rand(void)
{
    if (!_goboringcrypto_RAND_set_rand_method(old_rand))
        return 0;
    else
        return 1;
}

int fbytes(unsigned char *buf, int num) {
    int i;
    for (i = 0; i < num; i++) {
        buf[i] = 1;
    }
    return 1;
}
