#!/bin/bash

: ${root=$(pwd)}
: ${tag=latest}
: ${os=linux}
: ${name=pingly}

libpcap_version=1.10.5
libpcap_sha256=37ced90a19a302a7f32e458224a00c365c117905c2cd35ac544b6880a81488f0

# Function to print colored text based on log level
log() {
  local level=$1
  local message=$2
  local NC='\033[0m' # Reset to default color

  case "$level" in
  "info")
    echo -e "\033[0;32m[INFO] $message${NC}" # Green for INFO
    ;;
  "warning")
    echo -e "\033[0;33m[WARNING] $message${NC}" # Yellow for WARNING
    ;;
  "error")
    echo -e "\033[0;31m[ERROR] $message${NC}" # Red for ERROR
    ;;
  *)
    echo "$message" # Default to printing message without color for other levels
    ;;
  esac
}

[ ! -d bin ] && mkdir bin

# Build support paltform target
# 1. Linux (force musl)
linux_target=(
  "x86_64-unknown-linux-musl:mimalloc"
  "aarch64-unknown-linux-musl:mimalloc"
  "armv7-unknown-linux-musleabihf:jemalloc"
  "arm-unknown-linux-musleabihf:jemalloc"
  "i686-unknown-linux-musl:jemalloc"
)

# 2. MacOS
macos_target=(
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
)

# 3. Windows
windows_target=(
  "x86_64-pc-windows-gnu"
  "i686-pc-windows-gnu"
)

# Check linux rustup target installed
check_linux_rustup_target_installed() {
  for target in ${linux_target[@]}; do
    target=$(echo $target | cut -d':' -f1)
    installed=$(rustup target list | grep "${target} (installed)")
    if [ -z "$installed" ]; then
      log "info" "Installing ${target}..."
      rustup target add ${target}
    fi
  done
}

# Check macos rustup target installed
check_macos_rustup_target_installed() {
  for target in ${macos_target[@]}; do
    installed=$(rustup target list | grep "${target} (installed)")
    if [ -z "$installed" ]; then
      log "info" "Installing ${target}..."
      rustup target add ${target}
    fi
  done
}

# Check windows rustup target installed
check_windows_rustup_target_installed() {
  for target in ${windows_target[@]}; do
    installed=$(rustup target list | grep "${target} (installed)")
    if [ -z "$installed" ]; then
      log "info" "Installing ${target}..."
      rustup target add ${target}
    fi
  done
}

# The pcap crate provides bindings but not libpcap itself. Build a matching
# static library so each musl release remains self-contained.
build_linux_libpcap() {
  build_target=$1

  case "$build_target" in
  x86_64-unknown-linux-musl)
    zig_target=x86_64-linux-musl
    ;;
  aarch64-unknown-linux-musl)
    zig_target=aarch64-linux-musl
    ;;
  i686-unknown-linux-musl)
    zig_target=x86-linux-musl
    ;;
  armv7-unknown-linux-musleabihf | arm-unknown-linux-musleabihf)
    zig_target=arm-linux-musleabihf
    ;;
  *)
    log "error" "Unsupported libpcap target: ${build_target}"
    exit 1
    ;;
  esac

  libpcap_root="${root}/target/libpcap/${zig_target}"
  libpcap_prefix="${libpcap_root}/install"
  if [ -f "${libpcap_prefix}/lib/libpcap.a" ]; then
    return
  fi

  archive="${root}/target/libpcap/libpcap-${libpcap_version}.tar.gz"
  source_dir="${libpcap_root}/source"
  mkdir -p "$(dirname "$archive")" "$source_dir"

  if [ ! -f "$archive" ]; then
    wget -q "https://www.tcpdump.org/release/libpcap-${libpcap_version}.tar.gz" -O "$archive"
  fi

  if ! echo "${libpcap_sha256}  ${archive}" | sha256sum --check --status; then
    log "error" "libpcap ${libpcap_version} checksum verification failed"
    exit 1
  fi

  if ! tar xzf "$archive" --strip-components=1 -C "$source_dir"; then
    log "error" "Failed to extract libpcap ${libpcap_version}"
    exit 1
  fi

  if ! (
    cd "$source_dir"
    AR="zig ar" \
      CC="zig cc -target ${zig_target}" \
      RANLIB="zig ranlib" \
      ./configure \
      --host="$zig_target" \
      --prefix="$libpcap_prefix" \
      --disable-shared \
      --without-libnl \
      --disable-dbus \
      --disable-bluetooth \
      --disable-rdma \
      --disable-usb &&
      make -j"$(nproc)" &&
      make install
  ); then
    log "error" "Failed to build libpcap ${libpcap_version} for ${build_target}"
    exit 1
  fi
}

# Build linux target
build_linux_target() {
  for target in "${linux_target[@]}"; do
    build_target=$(echo $target | cut -d':' -f1)
    feature=$(echo $target | cut -d':' -f2)
    log "info" "Building ${target}..."
    build_linux_libpcap "$build_target"
    libpcap_dir="${root}/target/libpcap/${zig_target}/install/lib"
    if LIBPCAP_LIBDIR="$libpcap_dir" LIBPCAP_VER="$libpcap_version" \
      cargo zigbuild --release --target "${build_target}" --features "server,${feature}"; then
      compress_and_move $build_target
      log "info" "Build ${target} done"
    else
      log "error" "Build ${target} failed"
      exit 1
    fi
  done
}

# Build macos target
build_macos_target() {
  for target in "${macos_target[@]}"; do
    log "info" "Building ${target}..."
    if CARGO_PROFILE_RELEASE_STRIP=none cargo zigbuild --release --target "${target}" --features server; then
      compress_and_move $target
      log "info" "Build ${target} done"
    else
      log "error" "Build ${target} failed"
      exit 1
    fi
  done
}

# Build windows target
build_windows_target() {
  for target in "${windows_target[@]}"; do
    log "info" "Building ${target}..."
    if cargo build --release --target "${target}" --features server; then
      compress_and_move $target
      log "info" "Build ${target} done"
    else
      log "error" "Build ${target} failed"
      exit 1
    fi
  done
}

# upx and move target
compress_and_move() {
  build_target=$1
  target_dir="target/${build_target}/release"
  bin_name=$name
  if [[ $build_target == *windows* ]]; then
    bin_name="${name}.exe"
  fi
  upx "${target_dir}/${bin_name}"
  chmod +x "${target_dir}/${bin_name}"
  cd "${target_dir}"
  tar czvf $name-$tag-${build_target}.tar.gz $bin_name
  shasum -a 256 $name-$tag-${build_target}.tar.gz >$name-$tag-${build_target}.tar.gz.sha256
  mv $name-$tag-${build_target}.tar.gz $root/bin/
  mv $name-$tag-${build_target}.tar.gz.sha256 $root/bin/
  cd -
}

# Execute
if [ "$os" == "linux" ]; then
  log "info" "Building linux target..."
  check_linux_rustup_target_installed
  build_linux_target
elif [ "$os" == "macos" ]; then
  log "info" "Building macos target..."
  check_macos_rustup_target_installed
  build_macos_target
elif [ "$os" == "windows" ]; then
  log "info" "Building windows target..."
  check_windows_rustup_target_installed
  build_windows_target
else
  log "error" "Unsupported os: ${os}"
  exit 1
fi
