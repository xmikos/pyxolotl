#!/bin/bash

# Synchronize local copy of Pyxolotl Python dependencies
# to their latest revisions from git/hg/bzr

PY_LIBS_DIR="libs"

create_link() {
    rm -f "$1"
    ln -s "$PY_LIBS_DIR/$1/$1" "$1"
}

create_link_ext() {
    pushd "$PY_LIBS_DIR/$1" &>/dev/null
    rm -rf build
    python setup.py build
    popd &>/dev/null

    local ext_file_glob="$PY_LIBS_DIR/$1/build/lib.*/$1.cpython-*.so"
    rm -f $(basename $ext_file_glob)
    ln -s $ext_file_glob $(basename $ext_file_glob)
}

sync_git() {
    if [ ! -d "$PY_LIBS_DIR/$2" ]; then
        git clone --recursive "$1" "$PY_LIBS_DIR/$2"
    else
        pushd "$PY_LIBS_DIR/$2" &>/dev/null
        git pull
        git submodule update --init --recursive
        popd &>/dev/null
    fi

    if [ -z "$3" ]; then
        create_link "$2"
    else
        "$3" "$2"
    fi
}

sync_hg() {
    if [ ! -d "$PY_LIBS_DIR/$2" ]; then
        hg clone "$1" "$PY_LIBS_DIR/$2"
    else
        pushd "$PY_LIBS_DIR/$2" &>/dev/null
        hg pull -u
        popd &>/dev/null
    fi

    if [ -z "$3" ]; then
        create_link "$2"
    else
        "$3" "$2"
    fi
}

sync_bzr() {
    if [ ! -d "$PY_LIBS_DIR/$2" ]; then
        bzr branch "$1" "$PY_LIBS_DIR/$2"
    else
        pushd "$PY_LIBS_DIR/$2" &>/dev/null
        bzr pull
        popd &>/dev/null
    fi

    if [ -z "$3" ]; then
        create_link "$2"
    else
        "$3" "$2"
    fi
}

if [ ! -d "$PY_LIBS_DIR" ]; then
    mkdir -p "$PY_LIBS_DIR"
fi

sync_git https://github.com/tgalal/python-axolotl axolotl
sync_git https://github.com/tgalal/python-axolotl-curve25519 axolotl_curve25519 create_link_ext
