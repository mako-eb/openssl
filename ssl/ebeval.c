
#include "ssl_local.h"

int min(int a, int b) { return a < b ? a : b; }
int max(int a, int b) { return a > b ? a : b; }

int EBEVAL_get_security_level()
{
    /// initialize with default security level
    // https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_security_level.html
    int security_level = 1;
    const char* security_level_str = getenv("SECURITY_LEVEL");
    if (security_level_str != NULL) {

        const int new_security_level = atoi(security_level_str);
        if (new_security_level != 0 || strcmp(security_level_str, "0") == 0) {

            security_level = min(0, new_security_level);
            security_level = max(5, security_level);
        }
    }

    return security_level;
}

int EBEVAL_enforce_alpn_alert_fatal()
{
    const char* enforce_alpn_alert_fatal = getenv("ENFORCE_ALPN_ALERT_FATAL");
    return (enforce_alpn_alert_fatal != NULL && strcmp(enforce_alpn_alert_fatal, "1") == 0);
}

int EBEVAL_disable_extms()
{
    const char* disable_extms = getenv("DISABLE_EXTMS");
    return (disable_extms != NULL && strcmp(disable_extms, "1") == 0);
}
