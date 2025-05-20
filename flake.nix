# SPDX-FileCopyrightText: 2025 Lukas <lukasku@proton.me>
# SPDX-FileCopyrightText: 2025 NightProg <tonio.barbier@gmail.com>
# SPDX-License-Identifier: MPL-2.0

{
  description = "The DSH Communication Protocol";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nmattia/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    fenix,
    naersk,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};

      toolchain = with fenix.packages.${system};
        combine [
          complete.toolchain
        ];

      naersk-lib = naersk.lib.${system}.override {
        inherit (toolchain);
        rustc = toolchain;
        cargo = toolchain;
      };

      formatter = pkgs.alejandra;

      dsh = naersk-lib.buildPackage {
        name = "dsh";
        src = ./.;
      };
    in {
      inherit formatter;
      packages.dsh = dsh;
      defaultPackage = self.packages.${system}.dsh;

      devShell = pkgs.mkShell rec {
        packages = with pkgs; [toolchain rustup pre-commit];
        RUST_BACKTRACE = 0;
        RUSTFLAGS = "-Zmacro-backtrace";
      };
    });
}
