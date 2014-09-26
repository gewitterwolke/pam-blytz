#include <cstdlib>
#include <cstdio>
#include <cstdarg>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include <string>
#include <bitset>
#include <sstream>
#include <fstream>

#include <cstring>

#include "pam_blytz_printf.h"

// to be set externally
extern pam_handle_t *pamhg;

int pam_printf(const char *fmt, va_list ap) {
	return pam_printf(PAM_PROMPT_ECHO_ON, fmt, ap);
}

int pam_printf(int style, const char *fmt, va_list ap) {

	char msgbuf[PAM_MAX_MSG_SIZE];
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *rsp;
	const struct pam_conv *conv;
	const void *convp;
	int r;

	//int style = PAM_PROMPT_ECHO_ON;
	// output currently doesn't work with these two, only escape seqs are printed
	//int style = PAM_TEXT_INFO;
	//int style = PAM_ERROR_MSG;

/*
*/
	r = pam_get_item(pamhg, PAM_CONV, &convp);
	if (r != PAM_SUCCESS)
		return r;

	conv = (const struct pam_conv *)convp;
	if (conv == NULL || conv->conv == NULL) {
		return PAM_SYSTEM_ERR;
	}

	vsnprintf(msgbuf, PAM_MAX_MSG_SIZE, fmt, ap);
	msg.msg_style = style;
	msg.msg = msgbuf;
	msgp = &msg;
	rsp = NULL;

	r = (conv->conv)(1, &msgp, &rsp, conv->appdata_ptr);
	//r = converse(1, &msgp, &rsp, NULL);

	FILE *bla = fopen("/tmp/lol.txt", "w");
	fprintf(bla, "%s", rsp->resp);
	fclose(bla);

	free(rsp);

	return r;
}

int pam_mprintf_d(int style, const char *fmt, ...) {
#ifdef BLYTZ_DEBUG
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = pam_printf(style, fmt, ap);
	va_end(ap);
	return r;
#else
	return 0;
#endif
}

int pam_mprintf_d(const char *fmt, ...) {
#ifdef BLYTZ_DEBUG
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = pam_printf(PAM_PROMPT_ECHO_ON, fmt, ap);
	va_end(ap);
	return r;
#else
	return 0;
#endif
}

int pam_mprintf(int style, const char *fmt, ...) {

	va_list ap;
	int r;

	va_start(ap, fmt);
	r = pam_printf(style, fmt, ap);
	va_end(ap);
	return r;
}
