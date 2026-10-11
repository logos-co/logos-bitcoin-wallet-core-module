{
  description = "Logos bitcoin_wallet_core_module: the Bitcoin wallet engine (BDK, watch-only, SQLCipher, a checked server-only chain authority).";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # Only its contract is consumed: the core asks it to open wallets and approve sends.
    signer_manager_module = {
      url = "github:logos-co/logos-signer-manager-module/80bc40ccbe6c689caadc736b3db2136bfbde1818";
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
    in
    {
      packages = forAllSystems (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
          rustEnv = { BIP157_PATCHES_CHECKED = "${bip157Check (buildSystem system)}"; };
        }).packages.${system}
        // { bip157-check = bip157Check (buildSystem system); }
        // nixpkgs.lib.optionalAttrs (system != "x86_64-windows") { regtest-chain = regtestChain system; esplora-electrs = esploraElectrs system; });
    };
}
