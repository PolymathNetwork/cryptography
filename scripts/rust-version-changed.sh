#! /bin/bash

set -eo pipefail

PROJECT_DIR=$1

if [ "$#" -ne 1 ]; then
    echo "$0 <PROJECT_DIR>"
    exit 1
fi

cd "$PROJECT_DIR"

NEW_VERSION=$(cargo metadata --format-version 1 | python ../scripts/parse-cargo-version.py ${PROJECT_DIR})
git checkout $PREV_SHA
PREV_VERSION=$(cargo metadata --format-version 1 | python ../scripts/parse-cargo-version.py ${PROJECT_DIR})
echo "---> Version before the PR $PREV_VERSION"
echo "---> Version in the PR $NEW_VERSION"

if [ "$PREV_VERSION" == "$NEW_VERSION" ]
then
  echo "VERSION_CHANGED=" >> $GITHUB_ENV
else
  echo "VERSION_CHANGED=yes" >> $GITHUB_ENV
  echo "NEW_VERSION=$NEW_VERSION" >> $GITHUB_ENV
fi

