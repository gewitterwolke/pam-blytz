LDLIBS=-lblytz -lssh
LDPATHS=-L../libblytz -L/usr/local/lib
LDFLAGS=$(LDPATHS) 
PAMLDFLAGS=-lpam
CCPATHS=-I/usr/local/include -I./include -I/usr/src/crypto -I../libblytz
DEBUG= -g
CC=clang++

all: pam_blytz.so
install: pam_blytz.so
		sudo cp pam_blytz.so /usr/lib/pam_blytz.so

make deinstall:
	sudo rm /usr/lib/pam_blytz.so

pam_blytz.so: pam_blytz_printf.o pam_blytz.o helpers.o
	$(CC) $(DEBUG) $(LDFLAGS) $(LDLIBS) --shared -o pam_blytz.so \
		helpers.o pam_blytz_printf.o pam_blytz.o 

pam_blytz.o: src/pam_blytz.cpp
	$(CC) $(DEBUG) -fPIC $(CCPATHS) -c src/pam_blytz.cpp -o pam_blytz.o

pam_blytz_printf.o: src/pam_blytz_printf.cpp
	$(CC) $(DEBUG) -fPIC $(CCPATHS) -c src/pam_blytz_printf.cpp -o pam_blytz_printf.o

helpers.o: src/helpers.cpp
	$(CC) $(DEBUG) -fPIC $(CCPATHS) -c src/helpers.cpp -o helpers.o

clean:
	rm -rf *~ .*~ *.o *.so
	rm -rf src/*~ src/.*~ 
