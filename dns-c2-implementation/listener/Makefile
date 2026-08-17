all: clean
	@ echo "    * Building BeaconDNS listener plugin"
	@ mkdir -p dist
	@ cp config.yaml ax_config.axs ./dist/
	@ go mod tidy
	@ GOEXPERIMENT=greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/BeaconDNS.so pl_main.go dns_server.go
	@ echo "      done..."

clean:
	@ rm -rf dist
