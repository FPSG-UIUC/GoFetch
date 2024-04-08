#!/bin/zsh
# build dilithium library
go build -buildmode=c-archive -o libdilithium.a dilithium.go
# translate header file
bindgen libdilithium.h -o bindings.rs