use anyhow::{bail};
use curv::BigInt;
use curv::elliptic::curves::traits::{ECScalar};
use hex;
use ecdsa_mpc::ecdsa::{MessageHashType};
use secp256k1::{Secp256k1, Message, Signature, PublicKey};
use sha2::{Sha256, Digest};
use std::{env};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let _ = env_logger::builder().try_init();

    if args.len() < 4 {
        println!("usage: {} the_message hex_der_sig hex_pubkey",
                 args[0]);
        bail!("too few arguments")
    }

    sign_helper(
        &args[1],
        &args[2],
        &args[3],
    )
}

fn sign_helper(
    the_message: &String,
    hex_der_sig: &String,
    hex_pubkey: &String,
) -> anyhow::Result<()> {
    // Make msg_hash from the_message
    let mut hasher = Sha256::new();
    hasher.input(the_message);
    let msg_hash: MessageHashType = ECScalar::from(
        &BigInt::from(hasher.result().as_slice())
    );
    let msg_hash = msg_hash.get_element().to_string();

    let msg = Message::from_slice(&hex::decode(msg_hash).unwrap())
        .unwrap();
    let sig = Signature::from_der(&hex::decode(hex_der_sig).unwrap())
        .unwrap();
    let pubkey = PublicKey::from_slice(&hex::decode(hex_pubkey).unwrap())
        .unwrap();
    let secp = Secp256k1::new();

    if secp.verify(&msg, &sig, &pubkey).is_ok() {
        println!("Signature correct");
    } else {
        println!("Signature verification failed");
    }
    Ok(())
}
