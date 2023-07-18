#!/bin/bash

set -e

# Check if proper arguments are provided
if [ $# -ne 2 ]; then
  echo "Usage: $0 <file> <part>"
  echo "<file> : The file containing the version string"
  echo "<part> : The part of the version to bump (major, minor, patch)"
  exit 1
fi

file=$1
part=$2

# Define a map of part names to array indices
declare -A parts
parts=( ["major"]=0 ["minor"]=1 ["patch"]=2 )

# Check if the provided part name is valid
if [[ ! ${parts[$part]} ]]; then
  echo "Invalid part name. Must be one of: major, minor, patch"
  exit 1
fi

# Extract the current version from the provided file
# current_version=$(grep -oP 'const version = `\K.*(?=`)' $file) #get from file
current_version=$(git tag --sort=-v:refname | head -n 1 | awk -F. '{OFS="."; $NF; print $0}') #get from git tags


# Split the version into parts
IFS='.' read -a version_parts <<< "$current_version"

# Bump the specified part of the version
version_parts[${parts[$part]}]=$((version_parts[${parts[$part]}]+1))

# Reset all lower parts to 0 if we are not bumping the patch version
if [[ "$part" != "patch" ]]; then
  version_parts[2]=0
fi

# Reset the minor version to 0 if we are bumping the major version
if [[ "$part" == "major" ]]; then
  version_parts[1]=0
fi

# Rejoin the version parts
new_version="${version_parts[0]}.${version_parts[1]}.${version_parts[2]}"

# Replace the version in the provided file
sed -i "/const version =/s/v[0-9]\+\.[0-9]\+\.[0-9]\+/v$new_version/g" $file
