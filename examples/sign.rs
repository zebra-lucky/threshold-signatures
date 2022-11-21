use anyhow::{anyhow,bail};
use crossbeam_channel::{Receiver, Sender};
use curv::BigInt;
use curv::elliptic::curves::traits::{ECScalar};
use sha2::{Sha256, Digest};
use ecdsa_mpc::ecdsa::{MessageHashType};
use ecdsa_mpc::ecdsa::keygen::{MultiPartyInfo};
use ecdsa_mpc::ecdsa::signature::{Phase1, SigningTraits, SignedMessage};
use ecdsa_mpc::ecdsa::messages::signing::{InMsg, OutMsg};
use ecdsa_mpc::protocol::{PartyIndex, InputMessage, Address};
use ecdsa_mpc::state_machine::sync_channels::StateMachine;
use rand::seq::SliceRandom;
use std::{env, fs, thread};
use std::thread::JoinHandle;

struct Node {
    party: PartyIndex,
    egress: Receiver<OutMsg>,
    ingress: Sender<InMsg>,
}

struct NodeResult {
    index: usize,
    join_handle: JoinHandle<anyhow::Result<SignedMessage>>,
}

struct OutputMessageWithSource {
    msg: OutMsg,
    source: PartyIndex,
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let _ = env_logger::builder().try_init();

    if args.len() < 5 {
        println!("usage: {} min_number_of_signers share_count \
                  output_file_name_prefix the_message", args[0]);
        bail!("too few arguments")
    }

    sign_helper(
        args[1].parse()?,
        args[2].parse()?,
        &args[3],
        &args[4],
    )
}

fn sign_helper(
    min_signers: usize,
    share_count: usize,
    filename_prefix: &String,
    the_message: &String,
) -> anyhow::Result<()> {
    // Make msg_hash from the_message
    let mut hasher = Sha256::new();
    hasher.input(the_message);
    let msg_hash: MessageHashType = ECScalar::from(
        &BigInt::from(hasher.result().as_slice())
    );

    // use random min_isngers parties from total share_count
    let mut parties_usize = (0..share_count).collect::<Vec<_>>();
    parties_usize.shuffle(&mut rand::thread_rng());
    let parties_usize = &parties_usize[..min_signers];
    let parties = &parties_usize.iter()
        .map(|i| PartyIndex::from(*i))
        .collect::<Vec<_>>();

    let mut nodes = Vec::new();
    let mut node_results = Vec::new();

    for party in parties_usize {
        let f_path = format!("{}.{}.json", &filename_prefix, &party);
        let f_content = fs::read_to_string(&f_path)?;
        let mp_info: MultiPartyInfo = serde_json::from_str(&f_content)?;
        log::info!("starting party {}", party);
        let parties = parties.clone();
        let (ingress, rx) = crossbeam_channel::unbounded();
        let (tx, egress) = crossbeam_channel::unbounded();
        let join_handle = thread::spawn(move || {
            let start_state = Box::new(Phase1::new(
                msg_hash,
                mp_info,
                &parties,
                None,
            )?);
            let mut machine = StateMachine::<SigningTraits>
                ::new(start_state, &rx, &tx);
            match machine.execute() {
                Some(Ok(fs)) => Ok(fs),
                Some(Err(e)) => bail!("error {:?}", e),
                None => bail!("error in the machine"),
            }
        });
        nodes.push(Node {
            party: PartyIndex::from(*party),
            egress,
            ingress,
        });
        node_results.push(NodeResult {
            index: *party,
            join_handle,
        })
    }

    let _mx_thread = thread::spawn(move || {
        loop {
            let mut output_messages = Vec::new();
            // collect output from nodes
            for node in nodes.iter() {
                if let Ok(out_msg) = node.egress.try_recv() {
                    output_messages.push(OutputMessageWithSource {
                        msg: out_msg,
                        source: node.party,
                    });
                }
            }
            // forward collected messages
            output_messages
                .iter()
                .for_each(|mm| match &mm.msg.recipient {
                    Address::Broadcast => {
                        log::trace!(
                            "broadcast from {} to parties {:?}",
                            mm.source,
                            nodes
                                .iter()
                                .filter(|node| node.party != mm.source)
                                .map(|node| node.party)
                                .collect::<Vec<_>>()
                        );
                        nodes
                            .iter()
                            .filter(|node| node.party != mm.source)
                            .for_each(|node| {
                                let message_to_deliver = InputMessage {
                                    sender: mm.source,
                                    body: mm.msg.body.clone(),
                                };
                                node.ingress.send(message_to_deliver).unwrap();
                            });
                    }
                    Address::Peer(peer) => {
                        if let Some(node) = nodes.iter().find(|node| (*node).party == *peer) {
                            node.ingress
                                .send(InputMessage {
                                    sender: mm.source,
                                    body: mm.msg.body.clone(),
                                })
                                .unwrap();
                        }
                    }
                })
        }
    });

    let results = node_results
        .into_iter()
        .map(|h| (h.index, h.join_handle.join()))
        .collect::<Vec<_>>();

    return if results
        .iter()
        .any(|(_, r)| r.is_err() || r.as_ref().unwrap().is_err())
    {
        results.iter().for_each(|r| match r {
            (_, Ok(result)) => match result {
                Ok(signed_msg) => log::error!("{:?}", signed_msg),
                Err(e) => log::error!("{:?}", e),
            },
            (_, Err(e)) => log::error!("{:?}", e),
        });
        Err(anyhow!("Some state machines returned error"))
    } else {
        for (index, result) in results.into_iter() {
            // safe to unwrap because results with errors cause the early exit
            let signed_msg = result.unwrap().unwrap();
            let sig_json = serde_json::to_string_pretty(&signed_msg)?;
            println!("Signed message from party {}: {}", index, sig_json);
        }
        Ok(())
    };
}