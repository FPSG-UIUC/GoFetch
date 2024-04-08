#!/bin/zsh
# build rsa library
go build -buildmode=c-archive -o librsa.a rsa.go
# translate header file
bindgen librsa.h -o bindings.rs