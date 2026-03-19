#!/bin/bash
set -e

# Build binary
mkdir -p dist
go build -o dist/iamctl main.go

# Run tests
bash test.sh

echo "Binary built and tests passed. Installing to $HOME/local/bin..."

# Install
mkdir -p $HOME/local/bin
mv dist/iamctl $HOME/local/bin/iamctl
rm -f $HOME/local/bin/iam-pb-check $HOME/local/bin/ec2-pb-check
ln -sf $HOME/local/bin/iamctl $HOME/local/bin/iam-pb-check
ln -sf $HOME/local/bin/iamctl $HOME/local/bin/ec2-pb-check
