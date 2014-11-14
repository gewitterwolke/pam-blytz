pam-blytz
=========

C++ library for BLYTZ PAM authentication.

When used as SSH PAM backend there is a naming clash of libssh and
FreeBSD's OpenSSH implementation (under '/usr/lib/private/libssh.so').
Both use functions called e.g. 'ssh_key_new' and FreeBSD's library has
precedence over libssh's implementation. 

Therefore, I currently work around this by renaming the functions in libssh
and compiling it myself. This is not a really tenable solution but still serves
as a proof of concept.
