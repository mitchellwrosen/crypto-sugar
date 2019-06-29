#!/bin/sh

if [ -z "$1" ]; then
  echo "Usage: ./init.sh <package name>"
  exit 1
fi

sed -i "s/pkgname/$1/g" pkgname.cabal
sed -i "s/pkgname/$1/g" README.md
mv pkgname.cabal "$1".cabal
