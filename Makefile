.PHONY: build clean install install-panel install-detector panel detector deps test

# Build variables
BINARY_DIR := bin
PANEL_BINARY := $(BINARY_DIR)/panel
DETECTOR_BINARY := $(BINARY_DIR)/detector

# Go build flags
BUILD_FLAGS := -ldflags="-s -w"

all: build

# Create binary directory
$(BINARY_DIR):
	mkdir -p $(BINARY_DIR)

# Install dependencies
deps:
	go mod download
	go mod tidy

# Build all binaries
build: $(BINARY_DIR) deps
	@echo "Building Panel..."
	CGO_ENABLED=1 go build $(BUILD_FLAGS) -o $(PANEL_BINARY) ./cmd/panel
	@echo "Building Detector..."
	CGO_ENABLED=1 go build $(BUILD_FLAGS) -o $(DETECTOR_BINARY) ./cmd/detector
	@echo "Build completed successfully!"

# Build only panel
panel: $(BINARY_DIR) deps
	@echo "Building Panel..."
	CGO_ENABLED=1 go build $(BUILD_FLAGS) -o $(PANEL_BINARY) ./cmd/panel

# Build only detector
detector: $(BINARY_DIR) deps
	@echo "Building Detector..."
	CGO_ENABLED=1 go build $(BUILD_FLAGS) -o $(DETECTOR_BINARY) ./cmd/detector

# Install binaries to system
install: build
	sudo cp $(PANEL_BINARY) /usr/local/bin/malicious-ip-panel
	sudo cp $(DETECTOR_BINARY) /usr/local/bin/malicious-ip-detector
	sudo chmod +x /usr/local/bin/malicious-ip-panel
	sudo chmod +x /usr/local/bin/malicious-ip-detector
	@echo "Binaries installed to /usr/local/bin/"

# Install only panel binary to system
install-panel: panel
	sudo cp $(PANEL_BINARY) /usr/local/bin/malicious-ip-panel
	sudo chmod +x /usr/local/bin/malicious-ip-panel
	@echo "Panel binary installed to /usr/local/bin/malicious-ip-panel"

# Install only detector binary to system
install-detector: detector
	sudo cp $(DETECTOR_BINARY) /usr/local/bin/malicious-ip-detector
	sudo chmod +x /usr/local/bin/malicious-ip-detector
	@echo "Detector binary installed to /usr/local/bin/malicious-ip-detector"

# Create systemd service files
systemd-services:
	@echo "Creating systemd service files..."

# Test the code
test:
	go test ./...

# Clean build artifacts
clean:
	rm -rf $(BINARY_DIR)
	go clean

# Create sample configurations
configs:
	mkdir -p /etc/malicious-detector
	cp configs/detector-sample.yaml /etc/malicious-detector/
	cp configs/panel.yaml /etc/malicious-detector/
	@echo "Sample configurations copied to /etc/malicious-detector/"

# Run panel in development mode
run-panel: panel
	./$(PANEL_BINARY) -port 8080 -db ./panel.db

# Run detector in development mode (requires configuration)
run-detector: detector
	./$(DETECTOR_BINARY) -config ./detector.yaml

# Create detector sample config
create-detector-config: detector
	./$(DETECTOR_BINARY) -create-sample -config ./detector.yaml
	@echo "Sample detector configuration created at ./detector.yaml"

# Help
help:
	@echo "Available targets:"
	@echo "  build              - Build all binaries"
	@echo "  panel              - Build only panel binary"
	@echo "  detector           - Build only detector binary"
	@echo "  install            - Install both binaries to system"
	@echo "  install-panel      - Install only panel binary to system"
	@echo "  install-detector   - Install only detector binary to system"
	@echo "  systemd-services   - Create systemd service files"
	@echo "  test               - Run tests"
	@echo "  clean              - Clean build artifacts"
	@echo "  configs            - Create sample configurations"
	@echo "  run-panel          - Run panel in development mode"
	@echo "  run-detector       - Run detector in development mode"
	@echo "  create-detector-config - Create sample detector configuration"
	@echo "  deps               - Install dependencies"
	@echo "  help               - Show this help message"
