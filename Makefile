PASSWD = samplepasswd

test-ssl: test-ssl.c
	cc -DPASSWD="\"$(PASSWD)\"" -g -O0 $^ -o $@ -lcrypto

.PHONY: ref-dumpkey
ref-dumpkey:
	openssl enc -nosalt -aes-256-cbc -k $(PASSWD) -P

lorem.txt.enc.ref: lorem.txt
	openssl aes-256-cbc -e -k $(PASSWD) -nosalt -pbkdf2 -in $^ -out $@

.PHONY: ref-encrypt
ref-encrypt: lorem.txt.enc.ref

.PHONY: ref-decrypt
ref-decrypt: lorem.txt.enc.ref
	openssl aes-256-cbc -d -k $(PASSWD) -nosalt -pbkdf2 -in $^

lorem.txt.enc.test: test-ssl lorem.txt lorem.txt.enc.ref
	./test-ssl lorem.txt lorem.txt.enc.test

.PHONY: test
test: lorem.txt.enc.ref lorem.txt.enc.test
	cmp lorem.txt.enc.ref lorem.txt.enc.test

clean:
	@rm -rvf
	@rm -rvf *.o
	@rm -rvf test-ssl
	@rm -rvf lorem.txt.enc.test lorem.txt.enc.ref

.DEFAULT_GOAL := test
