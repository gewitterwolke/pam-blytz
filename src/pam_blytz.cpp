/**
 * PAM-BLYTZ
 *
 * (insert foo here)
 */

#include <string.h>
#include <unistd.h>

#ifdef __FreeBSD__
#include <login_cap.h>
#else

#endif

#include <pwd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#ifdef __FreeBSD__
#include <security/pam_mod_misc.h>
#else
#include <security/pam_misc.h>
#include <shadow.h>
//#include <pwauth.h>
#endif

#include <libssh/libssh.h>

// c++
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <fstream>
#include <cstdlib>

#include "helpers.h"
#include "pam_blytz_printf.h"
#include "pam_blytz.h"

#include "blytz-api.h"
#include "blytz-rest.h"
#include "blytz-qr.h"
using namespace blytz;

#ifndef __FreeBSD__
extern "C" {
#include "linux2/support.h"
}
#endif

// FIXME: get rid of .eof()s

// global pam handle, accessed by pam-blytz-printf
pam_handle_t *pamhg;

// globally available
const char *user;

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[]) {

	pamhg = pamh;

	int ret;
	int has_blytz = 0;

	// get user information
	struct passwd *pwd;
	ret = pam_get_user(pamh, &user, NULL);
	if (ret != PAM_SUCCESS) {
		return (ret);
	}

	// get connecting user's information (ssh is running as root)
	pwd = getpwnam(user);
	pam_mprintf_d("User: %s %d %d", user, pwd->pw_uid, pwd->pw_gid);

	// get hostname
	char hostname[256] = {0};

	// zero fill in case the hostname gets truncated
	memset( hostname, 0, 256);
	gethostname(hostname, 256);

	pam_mprintf_d("Hostname: %s", hostname);

	std::string blytz_server = BLYTZ_SERVER;
	blytz_server = "http://localhost:3000";
	pam_mprintf_d("BLYTZ server URL: %s", blytz_server.c_str());
	set_server_url(blytz_server.c_str());

	set_application_name("ssh");
	set_identifier(hostname);
	set_encryption_pwd("test123");

	// first connection to blytz to obtain session id
	pam_mprintf_d("Doing init/rest call: /connectSSH");
	retval retv;
	retv = init();

	if (retv.error != OK) {
		pam_mprintf_d(("Error in init:" + std::string(retv.message)).c_str());
		return PAM_SYSTEM_ERR;
	}

	pam_mprintf_d("Rest done");

	// get the session id
	std::string sessid = get_sessionid();
	pam_mprintf_d("SESSIONID: %s", sessid.c_str());
	
	// qrcode for encryption
	std::string qrstr = sessid + "|" + "test123";
	pam_mprintf_d("QR string: %s", qrstr.c_str());
	const char *qrcode = get_qrcode_ascii(qrstr.c_str());

	// show it so the user may scan it
	pam_mprintf(PAM_PROMPT_ECHO_OFF, "%s", qrcode);

	// check if current user has a blytz token 
	has_blytz = blytz_has_pkey();

	std::string stored_pkey;

	if (has_blytz) {

		// fetch the pkey
		stored_pkey = blytz_get_pkey();

	} else {

		pam_mprintf_d("No previous BLYTZ Login, switching to default login.");

		// no blytz token, i.e. first login via blytz,
		// attempt to authenticate user via unix_pam 
		ret = pam_unix_auth(pamh, flags, argc, argv);

		if (ret != PAM_SUCCESS) {
			return PAM_AUTH_ERR;
		}

		// user is authenticated, create blytz token
		pam_mprintf_d("Login successful, generating BLYTZ Login Token");

		std::string key = blytz_create_key();
		if (key == NO_KEY) {
			return PAM_SYSTEM_ERR;
		}

		// // prepare rest call
		// std::string creds;
		// std::stringstream sts;
		// sts << "{\n\"username\":\"" << user << "\",\n\"password\":\"" <<
		// 	key << "\",\n\"status\":\"widgetsetcredentials\"\n}";
		// creds = sts.str();

		// pam_mprintf_d("%s", creds.c_str());

		// send to blytz server (-> app)
		pam_mprintf_d("Doing rest call: /credentials/set");
		//conn_str = blytz_server + "/credentials/set";
		//res = restclient.post( conn_str.c_str(), "application/json", creds.c_str());
		//res = rest_post( conn_str, creds);
		retv = set_credentials(user,key.c_str());

		if (retv.error != OK) {
			pam_mprintf_d(("Error transferring key to BLYTZ Server: %d" + 
						std::string(retv.message)).c_str());
			// cleanup on error
			unlink((get_sshdir() + "blytzkey.pub").c_str());
		}

		// get pkey
		stored_pkey = blytz_get_pkey();
		pam_end(pamh, ret);
	}

	// at this point, a blytz token (=pkey) exists, continue with blytz login

	// check if the blytz server already returned some credentials
	pam_mprintf_d("Doing rest call: /credentials/get");
	//conn_str = blytz_server + "/credentials/get";
	//res = restclient.get(conn_str.c_str());
	//rest_post(conn_str
	//res = rest_get(conn_str);
	//retv = get_credentials();
	
	/*
	retv = get_password();

	if (retv.error != OK) {
			pam_mprintf_d(("Rest call failed: %d\n" + 
						std::string(retv.message)).c_str(), retv.error);
			return PAM_SYSTEM_ERR;
	}

	pam_mprintf_d("Response body: %s", body.c_str());
	*/

	retv = get_password();
	std::string body = retv.message;

	// wait for useful response from blytz server
	const int maxcnt = 10;
	int cnt = 0;

	//while (body.find("false") != std::string::npos) {
	while (!has_credentials()) {

		pam_mprintf_d("No credentials yet");

		sleep(3);
		/*
		//res = restclient.get(conn_str.c_str());
		//res = rest_get(conn_str);
		//retv = get_credentials();
		retv = get_password();
		body = retv.message;

		if (retv.error != OK) {
			pam_mprintf_d(("Rest call failed: %d" + 
						std::string(retv.message)).c_str());
			return PAM_SYSTEM_ERR;
		}

		//pam_mprintf_d("Response body: %s", body.c_str());
		pam_mprintf_d("Response body: %s", retv.message);
		*/

		if (cnt++ >= 10) {
			pam_mprintf_d("Timeout");
			return PAM_SYSTEM_ERR;
		}
	}

	// some kind of response, try to parse the private key
	std::string key = parse_key(body);
	pam_mprintf_d("Key from server: %s\n", key.c_str());

	std::string pkey = get_pkey_from_key(key);
	if (pkey == NO_KEY) {
		pam_mprintf_d("Could not get key");
		return PAM_SYSTEM_ERR;
	}
	key.clear();

	// delete cookie
	delete_cookie();

	pam_mprintf_d("stored: %s\n", stored_pkey.c_str());
	pam_mprintf_d("got   : %s\n", pkey.c_str());

	int i = stored_pkey == pkey;
	pam_mprintf_d("%d %d %d", i, strlen(stored_pkey.c_str()), strlen(pkey.c_str()));

	if (stored_pkey == pkey) {
		return PAM_SUCCESS;
	}

	return PAM_AUTH_ERR;
}

std::string parse_key(std::string body) {

	std::string key;

	std::stringstream body_stream;
	body_stream.str(body);

	// look for key in server response (in json "password" kv pair)
	std::string line;
	while (!body_stream.eof()) {
		std::getline(body_stream, line);

		pam_mprintf_d("%s\n", line.c_str());

		size_t pos;
		if ((pos = line.find("password")) != std::string::npos) {
			size_t startpos = line.find_first_of("\"", pos);
			size_t endpos = line.find_last_of("\"");
			key = line.substr(startpos + 4, endpos - startpos - 4);
			pam_mprintf_d("Found key: %d - %d : %s\n", startpos, endpos, key.c_str());
		}
	}

	// erase response body
	body.clear();
	
	// replace '!' by '\n'
	// key = replace( key, '!', '\n');

	return key;
}

// compute public key from private key
std::string get_pkey_from_key(std::string key) {
	
	std::string sshdir = get_sshdir();

	ssh_key pkey;
	ssh_key pubkey;

	int res = ssh_pki_import_privkey_base64( key.c_str(), 
			NULL, NULL, NULL, &pkey);
	if (res != SSH_OK) {
		pam_mprintf_d("Error importing private key");
		return NO_KEY;
	}

	res = ssh_pki_export_privkey_to_pubkey( pkey, &pubkey);
	if (res != SSH_OK) {
		pam_mprintf_d("Error exporting public key from private key");
		return NO_KEY;
	}

	char *buf;
	res = ssh_pki_export_pubkey_base64( pubkey, &buf);
	if (res != SSH_OK) {
		pam_mprintf_d("Error encoding public key to Base64");
		return NO_KEY;
	}

	std::string pubkey_str(buf);
	free(buf);

	/*
	// temporary write key to disk
	std::string tmpkeyfile = sshdir + "tmpkey";
	std::ofstream keyfile;
	keyfile.open(tmpkeyfile.c_str());

	if (keyfile.is_open()) {
		
		keyfile << key;
		keyfile.close();
	}

	// fix permissions
	chmod( tmpkeyfile.c_str(), S_IRUSR | S_IWUSR);
	pam_mprintf_d("tmp key written to disk");

	// execute ssh-keygen
	std::stringstream sts;
	sts << "ssh-keygen -y -f " << sshdir << "tmpkey > " << 
		sshdir << "tmppublickey";
	std::string create_pkey_cmd = sts.str();
	std::system(create_pkey_cmd.c_str());

	pam_mprintf_d("tmp pkey written to disk");
	
	// erase private key
	unlink( (sshdir + "tmpkey").c_str());
	key.clear();
	
	// read public key from file
	std::string pubkey;
	std::ifstream pubkeyfile;
	pubkeyfile.open( (sshdir + "tmppublickey").c_str());

	if (pubkeyfile.is_open()) {

		std::getline(pubkeyfile, pubkey);

		pubkeyfile.close();
	}

	pam_mprintf_d("Got converted public key");

	// erase public key
	unlink( (sshdir + "tmppublickey").c_str());

	// FIXME: ?
	pubkey += " ";
	*/

	return pubkey_str;
}

bool find_key_in_pkeys(std::string key) {

	std::vector<std::string> pkeys = get_authorized_keys();

	for (int i = 0; i < pkeys.size(); i++) {
		std::string curkeystr = pkeys.at(i);
		pam_mprintf_d("curkey: %s", curkeystr.c_str());
		if (curkeystr.compare(key)) {
			pam_mprintf_d("found key");
			return true;
		}
	}

	return false;
}

std::vector<std::string> get_authorized_keys() {

	std::vector<std::string> ks;
	std::string file = get_sshdir() + "authorized_keys";

	std::ifstream authkeys;
	authkeys.open(file.c_str());

	if (authkeys.is_open()) {

		std::string line;

		while(!authkeys.eof()) {

			std::getline(authkeys, line);
			ks.push_back(line);
		}

	authkeys.close();
	}
	return ks;
}

#ifdef __FreeBSD__
/*
 * authentication management from FreeBSD's pam_unix.c
 */
int pam_unix_auth(pam_handle_t *pamh, int flags,
    int argc, const char *argv[]) {
	login_cap_t *lc;
	struct passwd *pwd;
	int retval;
	const char *pass, *user, *realpw, *prompt;

	if (openpam_get_option(pamh, PAM_OPT_AUTH_AS_SELF)) {
		user = getlogin();
	} else {
		retval = pam_get_user(pamh, &user, NULL);
		if (retval != PAM_SUCCESS)
			return (retval);
	}
	pwd = getpwnam(user);

	pam_mprintf_d( "Got user: %s", user);
	PAM_LOG("Got user: %s", user);

	if (pwd != NULL) {
		pam_mprintf_d( "Doing real authentication");
		PAM_LOG("Doing real authentication");
		realpw = pwd->pw_passwd;
		pam_mprintf_d( "realpw: %s", realpw);
		if (realpw[0] == '\0') {
			if (!(flags & PAM_DISALLOW_NULL_AUTHTOK) &&
			    openpam_get_option(pamh, PAM_OPT_NULLOK))
				return (PAM_SUCCESS);
			realpw = "*";
		}
		lc = login_getpwclass(pwd);
	} else {
		PAM_LOG("Doing dummy authentication");
		realpw = "*";
		lc = login_getclass(NULL);
	}

	prompt = login_getcapstr(lc, "passwd_prompt", NULL, NULL);
	pam_mprintf_d( "get_authtok");
	retval = pam_get_authtok(pamh, PAM_AUTHTOK, &pass, prompt);
	login_close(lc);
	if (retval != PAM_SUCCESS) {
		pam_mprintf_d( "hehe noe");
		return (retval);
	}

	pam_mprintf_d( "got password");
	PAM_LOG("Got password");
	if (strcmp(crypt(pass, realpw), realpw) == 0) {
		return (PAM_SUCCESS);
	}

	PAM_VERBOSE_ERROR("UNIX authentication refused");
	return (PAM_AUTH_ERR);
}

#else

int pam_unix_auth(pam_handle_t *pamh, int flags,
    int argc, const char *argv[]) {

		int ret;
		char *pass = (char*) calloc( 1000, 1);
		ret = _unix_read_password(pamh, 0, NULL, "Password: ", NULL, "data", (const void **)&pass);

		if (ret == PAM_SUCCESS) {
			ret = _unix_verify_password( pamh, user, pass, 0);
			if (ret != PAM_SUCCESS) {
				return PAM_AUTH_ERR;
			}
		}

		free(pass);
}
#endif

std::string blytz_create_key() {


	ssh_key nkey;
	int res;


	// create public/private key pair
	res = ssh_pki_generate( SSH_KEYTYPE_RSA, 2048, &nkey);
	if (res != SSH_OK) {
		pam_mprintf_d("Error creating key pair");
		return NO_KEY;
	}

	pam_mprintf_d("Key pair created");

	// save to BLYTZ key location
	std::string sshdir = get_sshdir();

	// public key
	char *buf;
  res = ssh_pki_export_pubkey_base64( nkey, &buf);
	if (res != SSH_OK) {
		pam_mprintf_d("Error saving public key");
		return NO_KEY;
	}

	std::ofstream pubkeyfile;
	pubkeyfile.open((sshdir + "/blytzkey.pub"));

	if (pubkeyfile.is_open()) {
		pubkeyfile << buf;
	}

	pubkeyfile.close();
	free(buf);

	// private key
	res = ssh_pki_export_privkey_file( nkey, NULL, NULL, NULL, 
			(sshdir + "/blytzkey").c_str());

	// fix permissions
	chmod( (sshdir + "/blytzkey").c_str(), S_IRUSR | S_IWUSR);

	std::string key;
	if (blytz_has_pkey()) {
		key = blytz_get_key();

		// delete key, as we only need the public key file from here on
		// (assuming, the private key will be successfully transferred to the
		// blytz server)
		pam_mprintf_d("Deleting blytz private key");
		unlink( (sshdir + "blytzkey").c_str());

		// fix permissions
		struct passwd *pwd = getpwnam(user);
		chown((sshdir + "blytzkey.pub").c_str(), pwd->pw_uid, pwd->pw_gid);
		chmod((sshdir + "blytzkey.pub").c_str(), 
				S_IRUSR | S_IWUSR | S_IRGRP | S_IRGRP);
		chown((sshdir + "authorized_keys").c_str(), pwd->pw_uid, pwd->pw_gid);
		chmod((sshdir + "authorized_keys").c_str(), 
				S_IRUSR | S_IWUSR | S_IRGRP | S_IRGRP);

		// append new public key at the end of authorized_keys to enable login
		// with the corresponding private key

		std::string pkey = blytz_get_pkey();

		// FIXME: ssh-keygen adds an extra ' '?
		pkey.erase(pkey.length() - 1);

		std::ofstream akeysfile;
		akeysfile.open( (sshdir + "authorized_keys").c_str(), std::fstream::app);

		if (akeysfile.is_open()) {
			akeysfile << pkey << std::endl;
		}

		return key;
	} else {
		printf("Error: No BLYTZ token created");
		return NO_KEY;
	}

}

std::string get_homedir() {
	struct passwd *pw = getpwnam(user);
	const char *homedir = pw->pw_dir;

	std::string dir = homedir;

	// add trailing '/'
	if (dir.at(dir.length() - 1) != '/') {
		dir += "/";
	}

	return dir;
}

// get ssh directory and create it if it does not exist
std::string get_sshdir() {
	std::string dir = get_homedir();
	std::string sshdir = dir + ".ssh/";

	if (access(sshdir.c_str(), 0) != 0) {

		mkdir( sshdir.c_str(), S_IWUSR | S_IRUSR | S_IXUSR);
	}

	return sshdir;
}

std::string blytz_get_filename() {

	std::string sshdir = get_sshdir();
	std::string blytz_pubkey = "blytzkey.pub";

	return sshdir + blytz_pubkey;
}

bool blytz_has_pkey() {
	
	std::string filename = blytz_get_filename();

	pam_mprintf_d("In has_pkey: filename: %s", filename.c_str());

	std::ifstream blytzfile;
	blytzfile.open(filename.c_str());

	if (blytzfile.is_open())  {
		blytzfile.close();
		pam_mprintf_d("Has token");
		return true;
	} else {
		pam_mprintf_d("Has no token");
		return false;
	}
}

// load BLYTZ public key from file
std::string blytz_get_pkey() {

	std::string pkeyfilename = blytz_get_filename();

	/*
	pkeyfile.open(pkeyfilename.c_str());

	if (pkeyfile.is_open()) {

		std::getline(pkeyfile, pkey);

		//pam_mprintf_d("_get_pkey: %s", pkey.c_str());

		pkeyfile.close();
	}
	*/
	std::ifstream in(pkeyfilename.c_str());
	std::string pkey((std::istreambuf_iterator<char>(in)), 
			std::istreambuf_iterator<char>());

	return pkey;
}

// get key from keyfile 
std::string blytz_get_key() {

	std::string keyfile = get_sshdir() + "blytzkey";

	/*
	std::string token;

	std::ifstream blytzfile;
	blytzfile.open(keyfile.c_str());

	if (blytzfile.is_open()) {

		std::string line;
		while (!blytzfile.eof()) {
			std::getline(blytzfile, line);

			// add a '!' except for the last (empty) line
			if (!line.empty())
				line += '!';
			token.append(line);
		}

		// delete '!' at end of key
		token.erase(token.length() - 1);
		blytzfile.close();
	}
	*/

	// read the whole keyfile into a string
	std::ifstream in(keyfile.c_str());
	std::string keyfile_str((std::istreambuf_iterator<char>(in)), 
			std::istreambuf_iterator<char>());

	// import the key
	// int res;
	// ssh_key pkey;
	// res = ssh_pki_import_privkey_base64( keyfile_str.c_str(), 
	//		NULL, NULL, NULL, &pkey);

	pam_mprintf_d("got key: %s\n", keyfile_str.c_str());
	return keyfile_str;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	int argc, const char *argv[]) {

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

//#ifdef PAM_MODULE_ENTRY
//PAM_MODULE_ENTRY("pam_unix");
//#endif

