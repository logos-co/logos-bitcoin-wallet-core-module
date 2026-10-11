{
  description = "Logos bitcoin_wallet_core_module: the Bitcoin wallet engine (BDK, watch-only, SQLCipher, a checked server-only chain authority).";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # Only its contract is consumed: the core asks it to open wallets and approve sends.
    signer_manager_module = {
      url = "github:logos-co/logos-signer-manager-module/17eef7a343af9a849f816fa2d57dd7622a696c41";
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
    in
    {
      packages = forAllSystems (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system}
        // nixpkgs.lib.optionalAttrs (system != "x86_64-windows") { regtest-chain = regtestChain system; });
    };
}
