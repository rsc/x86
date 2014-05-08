newdecode.txt:
	cd ..; go test -cover -run Objdump -v -timeout 10h -printtests 2>&1 | tee log
	cd ..; go test -cover -run Xed -v -timeout 10h -printtests 2>&1 | tee -a log
	egrep '	(gnu|intel)	' ../log |sort >newdecode.txt
