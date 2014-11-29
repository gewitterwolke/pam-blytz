//#ifndef PAM_MAX_MSG_SIZE
// overwrite 
#define PAM_MAX_MSG_SIZE (2 << 16)
//#endif

#define BLYTZ_DEBUG 1

#include <string>

int pam_mprintf_d(int style, const char *fmt, ...);
int pam_mprintf_d(const char *fmt, ...);
int pam_printf(int style, const char *fmt, va_list ap);
int pam_printf(const char *fmt, va_list ap);
int pam_mprintf(int style, const char *fmt, ...);
