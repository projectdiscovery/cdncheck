#!/bin/bash

echo "::group::Build cdncheck
"
rm integration-test cdncheck
 2>/dev/null
cd ../cmd/cdncheck

go build
mv cdncheck ../../integration_tests/cdncheck

echo "::endgroup::"

echo "::group::Build cdncheck
 integration-test"
cd ../integration-test
go build
mv integration-test ../../integration_tests/integration-test
cd ../../integration_tests
echo "::endgroup::"

./integration-test
if [ $? -eq 0 ]
then
  exit 0
else
  exit 1
fi
