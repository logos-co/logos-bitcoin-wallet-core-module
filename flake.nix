{
  description = "Logos bitcoin_wallet_core_module: the Bitcoin wallet engine (BDK, watch-only, SQLCipher, a checked server-only chain authority).";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # Only its contract is consumed: the core asks it to open wallets and approve sends.
    signer_manager_module = {
      url = "github:logos-co/logos-signer-manager-module/9be21c3aeaa68ba915d36bfb67b5ed563585b9b7";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      # x86_64-windows is a cross build from x86_64-linux.
      targets = systems ++ [ "x86_64-windows" ];
      forAllSystems = f: nixpkgs.lib.genAttrs targets f;
      # x86_64-windows is built on x86_64-linux; checks run on the build machine.
      buildSystem = system: if system == "x86_64-windows" then "x86_64-linux" else system;
      # bip157 0.7.0 as published plus patches/bip157, held to the allowlist in
      # tools/kyoto/patch-bip157.sh, must equal rust-lib/vendor/bip157 byte for byte. The Rust
      # build depends on this check, so a patch outside the allowlist fails the module build.
      bip157Check = system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        pkgs.runCommand "bip157-0.7.0-patches-check" {
          crate = pkgs.fetchurl {
            url = "https://static.crates.io/crates/bip157/bip157-0.7.0.crate";
            sha256 = "b85126354e1cb28d64faa26f762dd32feba6051c31b5e4b27ac732afaa905ab1";
          };
          nativeBuildInputs = [ pkgs.git pkgs.gnutar pkgs.gzip pkgs.diffutils ];
        } ''
          export HOME=$TMPDIR
          mkdir pristine
          tar xzf $crate -C pristine --strip-components=1
          bash ${./tools/kyoto/patch-bip157.sh} pristine patched ${./patches/bip157}
          diff -r patched ${./rust-lib/vendor/bip157}
          echo "bip157 0.7.0 + $(ls ${./patches/bip157} | wc -l) patches" > $out
        '';
      # The same for bdk_kyoto 0.18.1, patches/bdk_kyoto and tools/kyoto/patch-bdk_kyoto.sh.
      bdkKyotoCheck = system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        pkgs.runCommand "bdk_kyoto-0.18.1-patches-check" {
          crate = pkgs.fetchurl {
            url = "https://static.crates.io/crates/bdk_kyoto/bdk_kyoto-0.18.1.crate";
            sha256 = "dc48e8d5e9301e29f3d60a25f897e3d6d4a3a7eada671a55239e8f22bf81eab4";
          };
          nativeBuildInputs = [ pkgs.git pkgs.gnutar pkgs.gzip pkgs.diffutils ];
        } ''
          export HOME=$TMPDIR
          mkdir pristine
          tar xzf $crate -C pristine --strip-components=1
          bash ${./tools/kyoto/patch-bdk_kyoto.sh} pristine patched ${./patches/bdk_kyoto}
          diff -r patched ${./rust-lib/vendor/bdk_kyoto}
          echo "bdk_kyoto 0.18.1 + $(ls ${./patches/bdk_kyoto} | wc -l) patches" > $out
        '';
      # tools/regtest/chain.sh with bitcoind and electrs, for harnesses outside this repository.
      regtestChain = system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        pkgs.runCommand "bitcoin-regtest-chain" { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
          mkdir -p $out/bin $out/share/regtest
          install -m 755 ${./tools/regtest/chain.sh} $out/share/regtest/chain.sh
          install -m 644 ${./tools/regtest/regtest.json} $out/share/regtest/regtest.json
          patchShebangs $out/share/regtest
          makeWrapper $out/share/regtest/chain.sh $out/bin/regtest-chain \
            --set-default BITCOIND ${pkgs.bitcoind}/bin/bitcoind \
            --set-default ELECTRS ${pkgs.electrs}/bin/electrs \
            --prefix PATH : ${nixpkgs.lib.makeBinPath [ pkgs.curl pkgs.perl pkgs.python3 ]}
        '';
      # Test programs for Windows, with the module's toolchain and the builder's MinGW wiring:
      # bin/storage.exe is tests/storage.rs (spike 4; run it with --ignored --nocapture) and
      # bin/p2p_proxy.exe the Kyoto tests' P2P proxy.
      testBinWindows =
        let
          common = logos-module-builder.lib.common;
          wpkgs = common.mkPkgs "x86_64-windows";
          bpkgs = common.mkPkgsWith [ (import logos-module-builder.inputs.rust-overlay) ] "x86_64-linux";
          triple = "x86_64-pc-windows-gnu";
          toolchain = bpkgs.rust-bin.stable."1.96.0".default.override { targets = [ triple ]; };
          rustPlatform = bpkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; };
          cc = wpkgs.stdenv.cc;
          src = bpkgs.runCommand "bitcoin-wallet-core-test-src" { } ''
            mkdir -p $out
            cp -r ${./rust-lib} $out/rust-lib
            cp -r ${logos-module-builder.packages.x86_64-linux.rust-sdk-src} $out/logos-rust-sdk-src
          '';
        in
        rustPlatform.buildRustPackage {
          pname = "bitcoin-wallet-core-test-bin";
          version = "0.1.0";
          inherit src;
          sourceRoot = "bitcoin-wallet-core-test-src/rust-lib";
          cargoLock = { lockFile = ./rust-lib/Cargo.lock; allowBuiltinFetchGit = true; };
          nativeBuildInputs = [ bpkgs.perl bpkgs.pkg-config cc ];
          env = {
            BIP157_PATCHES_CHECKED = "${bip157Check "x86_64-linux"}";
            BDK_KYOTO_PATCHES_CHECKED = "${bdkKyotoCheck "x86_64-linux"}";
            CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = "${cc}/bin/${cc.targetPrefix}cc";
            CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS = "-L native=${wpkgs.windows.pthreads}/lib";
            CC_x86_64_pc_windows_gnu = "${cc}/bin/${cc.targetPrefix}cc";
            CXX_x86_64_pc_windows_gnu = "${cc}/bin/${cc.targetPrefix}c++";
            AR_x86_64_pc_windows_gnu = "${cc.bintools}/bin/${cc.targetPrefix}ar";
            CFLAGS_x86_64_pc_windows_gnu = "-I${wpkgs.windows.pthreads}/include";
            CXXFLAGS_x86_64_pc_windows_gnu = "-I${wpkgs.windows.pthreads}/include";
          };
          buildPhase = ''
            runHook preBuild
            export CARGO_HOME=$TMPDIR/cargo
            cargo test --release --offline --locked --no-default-features --no-run --test storage --target ${triple}
            cargo build --release --offline --locked --no-default-features --example p2p_proxy --target ${triple}
            runHook postBuild
          '';
          doCheck = false;
          # Both import only Windows' own DLLs (checked with objdump), so bin/ runs as it is.
          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin
            cp target/${triple}/release/deps/storage-*.exe $out/bin/storage.exe
            cp target/${triple}/release/examples/p2p_proxy.exe $out/bin/
            runHook postInstall
          '';
        };
      # Blockstream's electrs, the esplora flavour, for the regtest test of the Esplora path.
      esploraElectrs = system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        pkgs.rustPlatform.buildRustPackage {
          pname = "esplora-electrs";
          version = "0.4.1-unstable-2026-10-05";
          src = pkgs.fetchFromGitHub {
            owner = "Blockstream";
            repo = "electrs";
            rev = "dd09701e84dc88a2c58a1365f798222b66e13772";
            hash = "sha256-AD+EYQnJdbd9VF8nw7dEYIieyjYdSHO8Y8l5HoQHdOs=";
          };
          cargoHash = "sha256-P8slOt07Fu6NNzYLEso3UQtfx7Yj+C4w98lq/Wr8oTk=";
          nativeBuildInputs = [ pkgs.pkg-config pkgs.rustPlatform.bindgenHook ];
          buildInputs = [ pkgs.zeromq ];
          # nixpkgs' RocksDB, linked dynamically, as electrs' own flake does.
          ROCKSDB_INCLUDE_DIR = "${pkgs.rocksdb}/include";
          ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib";
          # A test server: no LTO, so it builds in minutes.
          CARGO_PROFILE_RELEASE_LTO = "false";
          CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "16";
          cargoBuildFlags = [ "--bin" "electrs" ];
          doCheck = false;
        };
      # rustc leaves SQLCipher's OpenSSL (big-obj COFF) out of the staticlib's index, so ld took the
      # host's libcrypto DLL: prefix that OpenSSL and its callers apart from logos-protocol's, re-index.
      opensslApart = ''
        a=$PWD/lib/libbitcoin_wallet_core.a
        chmod u+w "$a"
        (
          set -euo pipefail
          export LC_ALL=C
          cd "$(mktemp -d)"
          O='^lib(crypto|ssl|common|default|legacy)-lib-.*[.]obj$'
          ossl=$($AR t "$a" | grep -E "$O")
          $AR x "$a" $ossl
          $NM -g --defined-only $ossl \
            | awk 'NF == 3 && $3 !~ /^[.@]/ { print $3 " bwc_openssl_" $3; print ".refptr." $3 " .refptr.bwc_openssl_" $3 }' \
            | sort -u > rename
          callers=$($NM -A -u "$a" \
            | awk -F: -v O="$O" 'NR == FNR { split($0, r, " "); s[r[1]] = 1; next } $2 !~ O { n = split($NF, f, " "); if (f[n] in s) print $2 }' rename - \
            | sort -u)
          grep -q -- '-sqlite3\.o$' <<< "$callers"
          echo "OpenSSL apart: $(( $(wc -l < rename) / 2 )) symbols, $(wc -w <<< "$ossl") objects, callers:" $callers
          $AR x "$a" $callers
          for m in $ossl $callers; do $OBJCOPY --redefine-syms=rename "$m"; done
          $AR r "$a" $ossl $callers
          $RANLIB "$a"
        )
      '';
    in
    {
      packages = forAllSystems (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
          rustEnv = {
            BIP157_PATCHES_CHECKED = "${bip157Check (buildSystem system)}";
            BDK_KYOTO_PATCHES_CHECKED = "${bdkKyotoCheck (buildSystem system)}";
          };
          preConfigure = nixpkgs.lib.optionalString (system == "x86_64-windows") opensslApart;
        }).packages.${system}
        // { bip157-check = bip157Check (buildSystem system); bdk_kyoto-check = bdkKyotoCheck (buildSystem system); }
        // nixpkgs.lib.optionalAttrs (system != "x86_64-windows") { regtest-chain = regtestChain system; esplora-electrs = esploraElectrs system; }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-windows") { test-bin = testBinWindows; });
    };
}
