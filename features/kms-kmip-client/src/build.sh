#!/bin/bash
VERSION=1.0
KC_DIR=c

# PREFIX must be an absolute path
# PREFIX must be exported for "make" subshell
export PREFIX=${PREFIX:-/opt/mtwilson/share/kmipclient}
export LINUX_TARGET=${LINUX_TARGET:-generic}
export CFLAGS="-fstack-protector-strong -fPIE -fPIC -O2 -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security"
export LDFLAGS="-z noexecstack -z relro -z now -pie"


install_kmipclient() {
  echo "PREFIX=$PREFIX"
  mkdir -p $PREFIX
  if [ -d "$KC_DIR" ]; then
    (cd $KC_DIR && CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}" ${KWFLAGS_KC} make)
    if [ $? -ne 0 ]; then echo "Failed to make kmipclient"; exit 1; fi
    (cd $KC_DIR && CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}" make install)
    if [ $? -ne 0 ]; then echo "Failed to make install kmipclient"; exit 2; fi
  fi
}

install_kmipclient
rm -rf dist-clean
mkdir dist-clean
cp -r $PREFIX dist-clean
