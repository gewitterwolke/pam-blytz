LQR_CFLAGS=$(shell pkg-config --cflags libqrencode)
LQR_LDFLAGS=$(shell pkg-config --libs libqrencode)
LCURL_CFLAGS=$(shell curl-config --cflags)
LCURL_LDFLAGS=$(shell curl-config --libs)
LDFLAGS=$(LCURL_LDFLAGS) $(LQR_LDFLAGS) -lpam_misc -lpam -lcrypt -lnsl -lblytz -lssh
#LDFLAGS=$(LQR_LDFLAGS)
CFLAGS=$(LCURL_CFLAGS) $(LQR_CFLAGS) -I./include -I/home/rod/projects/blytz/libblytz/

all: pam_blytz.so

SHELL := /bin/bash

UNAME := $(shell uname -a)

install: pam_blytz.so
	if [[ '$(UNAME)' =~ 'Ubuntu' ]]; then sudo cp pam_blytz.so /lib/security/pam_blytz.so; elif [[ '$(UNAME)' =~ 'Linux' ]]; then sudo cp pam_blytz.so /lib/security/pam_blytz.so; fi

deinstall:
	if [[ '$(UNAME)' =~ 'Ubuntu' ]]; then sudo rm /lib/security/pam_blytz.so; elif [[ '$(UNAME)' =~ 'Linux' ]]; then sudo rm /lib/security/pam_blytz.so; fi

pam_blytz.so: pam_blytz_printf.o pam_blytz.o helpers.o linux_auth.o
	g++ -g -gstabs --shared -o pam_blytz.so \
		pam_blytz.o \
		helpers.o pam_blytz_printf.o $(LDFLAGS) $(LDLIBS) 

pam_blytz.o: src/pam_blytz.cpp
	g++ -g -fPIC $(CFLAGS) -c src/pam_blytz.cpp -o pam_blytz.o

pam_blytz_printf.o: src/pam_blytz_printf.cpp
	g++ -g -fPIC $(CFLAGS) -c src/pam_blytz_printf.cpp -o pam_blytz_printf.o

linux_auth.o: src/linux_auth.cpp
	g++ -g -fPIC $(CFLAGS) -c src/linux_auth.cpp -o linux_auth.o

helpers.o: src/helpers.cpp
	g++ -g -fPIC $(CFLAGS) -c src/helpers.cpp -o helpers.o

clean:
	rm -rf *~ .*~ *.o *.so
	rm -rf src/*~ .*~ 
