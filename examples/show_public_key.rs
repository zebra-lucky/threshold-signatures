use anyhow::{bail};
use curv::elliptic::curves::traits::{ECPoint};
use ecdsa_mpc::ecdsa::keygen::{MultiPartyInfo};
use std::{env, fs};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let _ = env_logger::builder().try_init();

    if args.len() < 2 {
        println!("usage: {} output_file_name_prefix", args[0]);
        bail!("too few arguments")
    }

    show_pubk_helper(
        &args[1],
    )
}

fn show_pubk_helper(
    filename_prefix: &String,
) -> anyhow::Result<()> {
    let f_path = format!("{}.0.json", &filename_prefix);
    let f_content = fs::read_to_string(&f_path)?;
    let mp_info: MultiPartyInfo = serde_json::from_str(&f_content)?;
    let pubkey = mp_info.public_key.clone();
    let pubkey_hex = pubkey.get_element().to_string();
    println!("Pubkey: {}", pubkey_hex);
    Ok(())
}
