libmach8db: libmach8db.c
	9c libmach8db.c && 9l -o libmach8db libmach8db.o; rm libmach8db.o

newdecode.txt:
	cd ..; go test -cover -run Objdump -v -timeout 10h -printtests 2>&1 | tee log
	cd ..; go test -cover -run Xed -v -timeout 10h -printtests 2>&1 | tee -a log
	egrep '	(gnu|intel)	' ../log |sort >newdecode.txt

