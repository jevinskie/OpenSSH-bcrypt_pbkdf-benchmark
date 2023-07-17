#/usr/bin/env zsh

set -e -o pipefail

if [[ "${OS}" == "Windows_NT" ]]; then
    echo "Windows not supported yet" 1>&2
    exit 1
else
    UNAME_S=$(uname -s)
    if [[ "${UNAME_S}" == "Darwin" ]]; then
        if type brew &>/dev/null; then
            brew install openssl ninja cmake pkg-config hyperfine
            JEV_BREW_ROOT="$(brew --prefix)"
            export PATH="${JEV_BREW_ROOT}/bin:${PATH}"
            export PKG_CONFIG_PATH="${JEV_BREW_ROOT}/opt/openssl/lib/pkgconfig:${PKG_CONFIG_PATH}"
        else
            echo "Only homebrew supported right now"
            exit 1
        fi
    fi
fi

cmake -B build -G Ninja -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build

echo "\n\nRunning benchmark:\n"
set -x
./build/tools/OpenSSH-bcrypt_pbkdf-benchmark 100 100
set +x
