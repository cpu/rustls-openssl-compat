/**
 * Exercises openssl functions like `SSL_CONF_cmd_value_type`
 */

#include <assert.h>
#include <stdio.h>

#include <openssl/ssl.h>

#define CUSTOM_PREFIX "Rustls-"

static const int conf_flags[] = {SSL_CONF_FLAG_SERVER, SSL_CONF_FLAG_CLIENT,
                                 SSL_CONF_FLAG_CERTIFICATE};

#define NUM_FLAGS (sizeof(conf_flags) / sizeof(conf_flags[0]))

static const char *supported_cmds[] = {
    "-min_protocol", CUSTOM_PREFIX "min_protocol",
    "MinProtocol",   CUSTOM_PREFIX "MinProtocol",

    "-max_protocol", CUSTOM_PREFIX "max_protocol",
    "MaxProtocol",   CUSTOM_PREFIX "MaxProtocol",

    "VerifyMode",    CUSTOM_PREFIX "VerifyMode",

    "-cert",         CUSTOM_PREFIX "cert",
    "Certificate",   CUSTOM_PREFIX "Certificate",

    "-key",          CUSTOM_PREFIX "key",
    "PrivateKey",    CUSTOM_PREFIX "PrivateKey"};

#define NUM_CMDS (sizeof(supported_cmds) / sizeof(supported_cmds[0]))

void test_cmds(int base_flags, const char *prefix) {
  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
  assert(cctx != NULL);
  assert(SSL_CONF_CTX_set1_prefix(cctx, prefix));

  int flags = base_flags;
  for (unsigned long i = 0; i <= NUM_FLAGS; i++) {
    unsigned int new_flags = SSL_CONF_CTX_set_flags(cctx, flags);
    printf("cctx flags = %u\n", new_flags);

    for (unsigned long j = 0; j < NUM_CMDS; j++) {
      const char *cmd = supported_cmds[j];
      int value = SSL_CONF_cmd_value_type(cctx, cmd);
      printf("\tcmd %s has value type %d\n", cmd, value);
    }

    if (i < NUM_FLAGS) {
      flags |= conf_flags[i];
    }
  }

  assert(SSL_CONF_CTX_finish(cctx));
  SSL_CONF_CTX_free(cctx);
}

int main(void) {
  printf("no base flags, default prefix:\n");
  test_cmds(0, "");
  printf("no base flags, custom prefix:\n");
  test_cmds(0, CUSTOM_PREFIX);

  printf("CMDLINE base flags, default prefix:\n");
  test_cmds(SSL_CONF_FLAG_CMDLINE, "");
  printf("CMDLINE base flags,custom prefix:\n");
  test_cmds(SSL_CONF_FLAG_CMDLINE, CUSTOM_PREFIX);

  printf("FILE base flags, default prefix:\n");
  test_cmds(SSL_CONF_FLAG_FILE, "");
  printf("FILE base flags, custom prefix:\n");
  test_cmds(SSL_CONF_FLAG_FILE, CUSTOM_PREFIX);
}
