#!/bin/sh
set -e

if [ "$GOPATH" != "" ]; then
  echo "$0: WARNING: unsetting GOPATH as we don't need it" 1>&2
  unset GOPATH
fi

if [ "$1" = "windows" ]; then
  set -x
  CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++                         \
    CGO_ENABLED=1 GOOS=windows GOARCH=amd64                                    \
      go build -o dist/windows/amd64/ooniprobe.exe -v ./cmd/ooniprobe

elif [ "$1" = "linux" ]; then
  set -x
  docker build -t oonibuild .
  docker run -v `pwd`:/oonibuild -w /oonibuild -t --cap-drop=all               \
    --user `id -u`:`id -g` -e 'GOCACHE=/tmp/go/cache' -e 'GOPATH=/tmp/go/path' \
    oonibuild                                                                  \
    go build -o dist/linux/amd64/ooniprobe -v ./cmd/ooniprobe

elif [ "$1" = "macos" ]; then
  set -x
  go build -o dist/macos/amd64/ooniprobe -v ./cmd/ooniprobe

elif [ "$1" = "_travis-linux" ]; then
  set -x
  $0 linux
  docker run -v `pwd`:/oonibuild -w /oonibuild -t oonibuild                    \
    go test -v -coverprofile=ooni.cov ./...

elif [ "$1" = "_travis-osx" ]; then
  set -x
  brew tap measurement-kit/measurement-kit
  brew update
  brew upgrade
  brew install measurement-kit
  $0 macos
  go test -v -coverprofile=ooni.cov ./...

elif [ "$1" = "help" ]; then
  echo "Usage: $0 linux | macos | windows"
  echo ""
  echo "Builds OONI on supported systems. The output binary will"
  echo "be saved at './dist/<system>/<arch>/ooniprobe[.exe]'."
  echo ""
  echo "# Linux"
  echo ""
  echo "To compile for Linux we use a docker container with the binary"
  echo "Measurement Kit dependency installed. So you need docker installed."
  echo ""
  echo "# macOS"
  echo ""
  echo "You must be on macOS. You must install Measurement Kit once using:"
  echo ""
  echo "- brew tap measurement-kit/measurement-kit"
  echo "- brew install measurement-kit"
  echo ""
  echo "You should keep Measurement Kit up-to-date using:"
  echo ""
  echo "- brew upgrade"
  echo ""
  echo "# Windows"
  echo ""
  echo "You must be on macOS. You must install Measurement Kit once using:"
  echo ""
  echo "- brew tap measurement-kit/measurement-kit"
  echo "- brew install mingw-w64-measurement-kit"
  echo ""
  echo "You should keep Measurement Kit up-to-date using:"
  echo ""
  echo "- brew upgrade"
  echo ""

else
  echo "Invalid usage; try '$0 help' for more help." 1>&2
  exit 1
fi
