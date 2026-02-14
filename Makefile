.PHONY: build test install uninstall clean

BINARY = almost-yolo-guard
SRC_DIR = plugin/src
INSTALL_DIR = $(HOME)/.local/bin

build:
	cd $(SRC_DIR) && go build -o ../../$(BINARY) .

test:
	cd $(SRC_DIR) && go test -count=1 ./...

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo "installed $(INSTALL_DIR)/$(BINARY)"

uninstall:
	rm -f $(INSTALL_DIR)/$(BINARY)

clean:
	rm -f $(BINARY)
