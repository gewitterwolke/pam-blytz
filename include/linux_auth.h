#define MAX_PWD_LEN 1024

bool is_auth(char *user, char *pass);
char *get_pwd_from_shadow(char *user);
char *get_password(char *user);
