GO := go

BINARY := nmapify

all: build install

build:
	$(GO) build -o $(BINARY) main.go

install:
	sudo cp $(BINARY) /usr/bin/$(BINARY)

clean:
	rm -f $(BINARY)

run: build
	./$(BINARY)

run-installed: install
	sudo /usr/bin/$(BINARY)


uninstall:
	sudo rm -f /usr/bin/$(BINARY)

.PHONY: all build install clean run run-installed uninstall