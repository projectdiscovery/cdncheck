#!/bin/bash

# reading os type from arguments
CURRENT_OS=$1

if [ "${CURRENT_OS}" == "windows-latest" ];then
    extension=.exe
fi

echo "::group::Building functional-test binary"
go build -o functional-test$extension
echo "::endgroup::"

echo "::group::Building cdncheck binary from current branch"
go build -o cdncheck_dev$extension ../cdncheck
echo "::endgroup::"


echo 'Starting cdncheck functional test'
./functional-test$extension -dev ./cdncheck_dev$extension
