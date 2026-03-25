.PHONY: generate build run clean

generate:
	go generate ./agent/tracer

build: generate
	go build -o bin/sentinel ./agent

run: build
	sudo ./bin/sentinel

clean:
	rm -f agent/tracer/accept_bpf*.go
	rm -f agent/tracer/accept_bpf*.o
	rm -f bin/sentinel
