#ifndef __FreeBSD__

#include <crypt.h>
#include <shadow.h>
#include <pwd.h>
#include <malloc.h>

#include <string.h>

#include "linux_auth.h"
#include "pam_blyt_printf.h"

bool is_auth(char *user, char *pass) {

	return false;
}

char *get_pwd_from_shadow(char *user) {

	struct passwd *pw;
	struct spwd *spwd;
	spwd = getspnam(user);

	pw = getpwnam(user);
	if (!pw) {
		pam_mprintf_d("Error getting user/password information for user %s\n", user);
		return NULL;
	}

	pam_mprintf_d("Got user information for %s\n", user);

	if (spwd) {
		pw->pw_passwd = spwd->sp_pwdp;
	} else {
		pam_mprintf("Error getting shadowed password for user %s\n", user);
		return NULL;
	}

	pam_mprintf_d("Got shadowed password %s\n", pw->pw_passwd);
	
	char *pwd = (char *) malloc(MAX_PWD_LEN + 1);
	strncpy(pwd, pw->pw_passwd, MAX_PWD_LEN);

	return pwd;
}

#define HASH_TYPE_LEN 2 // 1 + 1
#define SALT_LEN 9 // 8 + 1
#define KEY_LEN 1025 // 1024 + 1

//
// If return value is true, out consists of three parts: the hash type, the 
// salt and the hashed password, each starting with a '$'
// The salt is in the format $hash_type$salt so it can be used for crypt()
//
bool split_shadowed_pwd(char *shadowed_pwd, char **out) {
	if (shadowed_pwd == NULL || strlen(shadowed_pwd) < 5 || 
			strstr(shadowed_pwd, "$") == NULL) {
		pam_mprintf("Malformed shadowed password\n");
		return false;
	}

	out = (char **) malloc(3 * sizeof(char *));
	out[0] = (char *) malloc(HASH_TYPE_LEN + 1);
	out[1] = (char *) malloc(HASH_TYPE_LEN + 1 +SALT_LEN + 1);
	out[2] = (char *) malloc(KEY_LEN + 1);

	size_t len = 0;

	// tokenize shadowed passwort at '$'
	char *tok = strtok(shadowed_pwd, "$");
	if (tok == NULL) {
		goto tokerr;
	}
	out[0][0] = '$';
	strncpy(out[0] + 1, tok, HASH_TYPE_LEN);

	// get salt token and copy the has type as well as the salt to the result
	// buffer
	char *tok = strtok(NULL, "$");
	if (tok == NULL) {
		goto tokerr;
	}
	strncpy(out[1], out[0], HASH_TYPE_LEN);
	len = strlen(out[0]);
	out[1][len] = '$';
	strncpy(out[1] + len + 1, tok, SALT_LEN);

	// get key and store in buffer
	char *tok = strtok(NULL, "$");
	if (tok == NULL) {
		goto tokerr;
	}
	out[2][0] = '$';
	strncpy(out[2] + 1, tok, KEY_LEN);

	return true;

tokerr:
		pam_mprintf("Error reading part of shadowed pwd\n");
		free(out[2]);
		free(out[1]);
		free(out[0]);
		free(out);
		return false;
}

char *get_password(char *user) {

}

#endif
