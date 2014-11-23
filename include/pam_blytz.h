#include <string>
#include <vector>

int pam_unix_auth(pam_handle_t *pamh, int flags,
    int argc, const char *argv[]);

std::string get_sshdir();
std::string get_homedir();

bool blytz_has_pkey();
std::string blytz_get_key();
std::string blytz_get_pkey();
std::string blytz_create_key();

std::string parse_key(std::string body);
std::string get_pkey_from_key(std::string key);

std::vector<std::string> get_authorized_keys();

std::string NO_KEY = "";

//#define BLYTZ_SERVER "http://localhost:3000"
#define BLYTZ_SERVER "https://blytz.tobik.eu"
