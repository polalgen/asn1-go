
all:
	go build main.go

lib:
	$(MAKE) -C asn1c all 

clean:
	$(MAKE) -C asn1c clean 