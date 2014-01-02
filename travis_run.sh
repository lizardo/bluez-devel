#!/bin/bash
set -e -u -x

prefix=/opt/bluez
options="--disable-systemd \
--prefix=$prefix \
--sysconfdir=$prefix/etc \
--localstatedir=$prefix/var"

if [ "$COVERAGE" == "yes" ]; then
    CFLAGS="--coverage -g" LDFLAGS="--coverage" \
        ./bootstrap-configure $options --disable-optimization
else
    ./bootstrap-configure $options
fi

make

sudo mkdir -p $prefix
sudo chown $USER: $prefix
make DESTDIR=/tmp/bluez-bin install
sudo cp src/bluetooth.conf /etc/dbus-1/system.d/
cp -a /tmp/bluez-bin/$prefix/* $prefix

blueish() {
    make -C /tmp/blueish $1
    /tmp/blueish/testcases/$2

    echo ========== BEGIN /tmp/$3 ==========
    grep -v '^\[EMULATOR\]' /tmp/$3
    echo ==========   END /tmp/$3 ==========

    # Force failure if any leak or Valgrind error is found
    # tr -d '\000' is necessary to remove NUL byte on bluetoothd log, which
    # affects how awk matches lines.
    test -z "$(cat /tmp/$3 | tr -d '\000' | awk '/ERROR SUMMARY:/ && $4 != 0')"
}

mkdir ~/trees
ln -s $PWD ~/trees/bluez.git
make -C /tmp/blueish/valgrind
blueish kernel-emulator gatt.py bluetoothd.log
blueish kernel-emulator-android android.py android.log

if [ "$COVERAGE" == "yes" ]; then
    coveralls -r . -b . || true
fi

TESTS_ENVIRONMENT="valgrind --leak-check=full --trace-children=yes \
    --log-file=/tmp/make_check.log" G_SLICE=always-malloc make check
test -z "$(awk '/ERROR SUMMARY:/ && $4 != 0' /tmp/make_check.log)"

make distcheck
