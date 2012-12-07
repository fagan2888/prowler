prowler:
	gcc -DAPI_KEY='"$(API_KEY)"' -Wall -lssl -lcrypto -o prowler main.c prowl.c

clean:
	rm -f prowler

install: prowler
	cp prowler /usr/local/bin/prowler
