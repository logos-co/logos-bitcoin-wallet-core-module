//! Bitcoin wallet engine for Logos: BDK, watch-only, with a server-only chain authority.

pub mod address;
pub mod authority;
pub mod checks;
pub mod crosscheck;
pub mod engine;
pub mod fees;
pub mod gate;
pub mod headers;
pub mod intent;
pub mod jobs;
pub mod kyoto;
pub mod ledger;
pub mod manager;
pub mod net;
pub mod network;
pub mod node;
pub mod peers;
pub mod pin;
pub mod routes;
pub mod send;
pub mod storage;
pub mod sync;
pub mod wallet;
pub mod walletdir;

#[cfg(feature = "logos_module")]
mod glue;

/// The core never takes a secret: no method or job parameter may be named like one.
#[cfg(test)]
mod contract {
    const BANNED: [&str; 12] = ["password", "passphrase", "phrase", "mnemonic", "seed", "secret", "key", "xprv", "tprv", "privkey", "wif", "pin"];

    fn banned(name: &str) -> Option<&'static str> {
        let n = name.to_ascii_lowercase();
        BANNED.iter().copied().find(|b| n.contains(b))
    }

    /// Parameter names of the IPC trait's methods.
    fn trait_params(src: &str) -> Vec<String> {
        let start = src.find("pub trait BitcoinWalletCoreModule:").expect("the contract trait");
        let body = &src[start..src[start..].find("\n}\n").map(|e| start + e).expect("trait end")];
        let mut out = vec![];
        for line in body.lines().map(str::trim).filter(|l| l.starts_with("fn ")) {
            let args = &line[line.find('(').unwrap() + 1..line.rfind(')').unwrap()];
            for a in args.split(',').map(str::trim).filter(|a| !a.is_empty() && !a.contains("self")) {
                out.push(a.split(':').next().unwrap().trim().to_string());
            }
        }
        out
    }

    /// Field names the job parser accepts, from its allow-lists.
    fn job_fields(src: &str) -> Vec<String> {
        src.lines()
            .filter(|l| l.contains("=> &[") || l.contains("[\"recipients\""))
            .flat_map(|l| l.split('"').skip(1).step_by(2).map(str::to_string).collect::<Vec<_>>())
            .collect()
    }

    #[test]
    fn no_parameter_is_named_like_a_secret() {
        let glue = include_str!("glue.rs");
        let params = trait_params(glue);
        assert!(params.len() >= 10, "found the trait's parameters: {params:?}");
        assert!(params.contains(&"receipt".to_string()), "a job receipt is not a secret parameter of ours");
        for p in &params {
            assert_eq!(banned(p), None, "IPC parameter {p} is named like a secret");
        }
        let mut fields = job_fields(include_str!("engine.rs"));
        fields.extend(job_fields(include_str!("send.rs")));
        assert!(fields.contains(&"previewId".to_string()) && fields.contains(&"recipients".to_string()), "{fields:?}");
        for f in &fields {
            assert_eq!(banned(f), None, "job field {f} is named like a secret");
        }
    }

    #[test]
    fn the_check_catches_a_secret() {
        assert_eq!(banned("password"), Some("password"));
        assert_eq!(banned("databaseKey"), Some("key"));
        let fake = "pub trait BitcoinWalletCoreModule: Send {\n    fn unlock(&self, wallet_password: String) -> String;\n}\n";
        assert_eq!(trait_params(fake), vec!["wallet_password"]);
        assert_eq!(banned(&trait_params(fake)[0]), Some("password"));
    }
}
