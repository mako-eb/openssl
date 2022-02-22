
#include "ssl_local.h"

static int min(int a, int b) { return a < b ? a : b; }
static int max(int a, int b) { return a > b ? a : b; }

static int is_eval_set(const char* eval)
{   
    if (eval != NULL) {
        const char* eval_value = getenv(eval);
        return (eval_value != NULL && strcmp(eval_value, "1") == 0);
    }
    return 0;
}

int EBEVAL_get_security_level()
{
    /// initialize with default security level
    // https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_security_level.html
    int security_level = 1;
    const char* security_level_str = getenv("SECURITY_LEVEL");
    if (security_level_str != NULL) {

        const int new_security_level = atoi(security_level_str);
        if (new_security_level != 0 || strcmp(security_level_str, "0") == 0) {

            security_level = max(0, new_security_level);
            security_level = min(5, security_level);
        }
    }

    return security_level;
}

int EBEVAL_enforce_alpn_alert_fatal()
{
    return is_eval_set("ENFORCE_ALPN_ALERT_FATAL");
}

int EBEVAL_disable_extms()
{
    return is_eval_set("DISABLE_EXTMS");
}

int EBEVAL_enable_dtls_comp()
{
    return is_eval_set("ENABLE_DTLS_COMP");
}

int EBEVAL_disable_null_comp()
{
    return is_eval_set("DISABLE_NULL_COMP");
}
