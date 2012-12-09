prowler:
	gcc -DAPI_KEY='"$(API_KEY)"' -Wall -o prowler main.c prowl.c -lssl -lcrypto

clean:
	rm -f prowler

install: prowler
	cp prowler /usr/local/bin/prowler
