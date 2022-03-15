PASSWD = samplepasswd

test-ssl: test-ssl.c
	cc -DPASSWD="\"$(PASSWD)\"" -g -O0 $^ -o $@ -lcrypto

.PHONY: test
test: test-ssl lorem.txt
	./test-ssl lorem.txt lorem.txt.enc.test

.PHONY: ref-dumpkey
ref-dumpkey:
	openssl enc -nosalt -aes-256-cbc -k $(PASSWD) -P

.PHONY: ref-encrypt
ref-encrypt: lorem.txt
	openssl aes-256-cbc -e -k $(PASSWD) -nosalt -pbkdf2 -in $^ -out $^.enc.ref

.PHONY: ref-decrypt
ref-decrypt: lorem.txt.enc.ref
	openssl aes-256-cbc -d -k $(PASSWD) -nosalt -pbkdf2 -in $^

clean:
	@rm -rvf
	@rm -rvf *.o
	@rm -rvf test-ssl
	@rm -rvf lorem.txt.enc.test lorem.txt.enc.ref

.DEFAULT_GOAL := test
