TARGET=decode.go

all:lib
	go build $(TARGET)

lib:
	$(MAKE) -C asn1c all 

clean:
	$(MAKE) -C asn1c clean 