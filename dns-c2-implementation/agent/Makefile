all: clean
	@ echo "    * Building dns_agent plugin"
	@ mkdir -p dist
	@ cp config.yaml ax_config.axs ./dist/
	@ go mod tidy
	@ GOEXPERIMENT=greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/dns_agent.so pl_main.go commands.go protocol.go
	@ echo "      done..."

clean:
	@ rm -rf dist
