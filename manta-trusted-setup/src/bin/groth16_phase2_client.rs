// // Copyright 2019-2022 Manta Network.
// // This file is part of manta-rs.
// //
// // manta-rs is free software: you can redistribute it and/or modify
// // it under the terms of the GNU General Public License as published by
// // the Free Software Foundation, either version 3 of the License, or
// // (at your option) any later version.
// //
// // manta-rs is distributed in the hope that it will be useful,
// // but WITHOUT ANY WARRANTY; without even the implied warranty of
// // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// // GNU General Public License for more details.
// //
// // You should have received a copy of the GNU General Public License
// // along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

// //! Trusted Setup Ceremony Client

// extern crate alloc;

// use alloc::string::String;
// use clap::{Parser, Subcommand};
// use colored::Colorize;
// use core::fmt::{Display, Formatter};
// use dialoguer::{theme::ColorfulTheme, Input};
// use ed25519_dalek::SecretKey;
// use manta_crypto::rand::{OsRng, RngCore};
// use manta_trusted_setup::{
//     ceremony::{
//         client::Client,
//         message::{ContributeResponse, QueryMPCStateResponse},
//         queue::Priority,
//         server::HasNonce,
//         signature::{
//             ed_dalek::{self, Ed25519, PrivateKey, PublicKey},
//             HasPublicKey, SignatureScheme,
//         },
//         CeremonyError,
//     },
//     groth16::{ceremony::Participant, config::Config, mpc::Groth16Phase2},
// };
// use serde::{Deserialize, Serialize};
// use std::{thread, time::Duration};

// #[derive(Clone, Debug)]
// enum Error {
//     InvalidSecret,
// }

// impl Display for Error {
//     fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
//         match self {
//             Error::InvalidSecret => {
//                 write!(f, "Your {} is invalid. Please try again", "secret".italic())
//             }
//         }
//     }
// }

// fn handle_error<T>(result: Result<T, Error>) -> T {
//     match result {
//         Ok(x) => x,
//         Err(e) => {
//             println!("{}: {}", "error".red().bold(), e);
//             std::process::exit(1);
//         }
//     }
// }

// /// Command
// #[derive(Debug, Subcommand)]
// pub enum Command {
//     /// Register for the Trusted Setup Ceremony
//     Register,

//     /// Runs the Trusted Setup Ceremony as a Contributor
//     Contribute,
// }

// /// Trusted Setup Contributor
// #[derive(Debug, Parser)]
// pub struct Arguments {
//     /// Command
//     #[clap(subcommand)]
//     pub command: Command,
// }

// impl Arguments {
//     ///
//     #[inline]
//     pub fn run(self) -> Result<(), Error> {
//         match self.command {
//             Command::Register => {
//                 register();
//                 Ok(())
//             }
//             Command::Contribute => {
//                 match tokio::runtime::Builder::new_multi_thread() // TODO
//                     .worker_threads(4)
//                     .enable_io()
//                     .enable_time()
//                     .build()
//                 {
//                     Ok(runtime) => runtime
//                         .block_on(async { contribute().await })
//                         .map_err(|_| todo!()),
//                     Err(err) => {
//                         let _ = err;
//                         todo!()
//                     }
//                 }
//             }
//         }
//     }
// }

// /// Sample random seed and generate public key, printing both to stdout.
// #[inline]
// pub fn register() {
//     // Read in twitter account name
//     let twitter_account: String = Input::with_theme(&ColorfulTheme::default())
//         .with_prompt("Your twitter account")
//         .interact_text()
//         .expect("");

//     // Generate sk,pk from entropy
//     let mut rng = OsRng;
//     let mut secret_key_bytes = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
//     rng.fill_bytes(&mut secret_key_bytes);
//     let sk = PrivateKey(secret_key_bytes);
//     let pk = PublicKey(
//         ed25519_dalek::PublicKey::from(
//             &SecretKey::from_bytes(&secret_key_bytes).expect("`from_bytes` should succeed"),
//         )
//         .to_bytes(),
//     );

//     let pk_serialized = bincode::serialize(&pk).expect("Serializing public key should succeed");
//     let pk_str = bs58::encode(pk_serialized).into_string();
//     let keypair_serialized =
//         bincode::serialize(&(pk, sk)).expect("Serializing keypair should succeed"); // TODO: Will the user be stupid and send the seed to google form?
//     let keypair_str = bs58::encode(keypair_serialized).into_string();

//     let signature = ed_dalek::Ed25519::sign(
//         format!("manta-trusted-setup-twitter:{}", twitter_account),
//         &0,
//         &pk,
//         &sk,
//     )
//     .expect("Signing should succeed");
//     let signature_serialized =
//         bincode::serialize(&signature).expect("Serializing signature should succeed.");
//     let signature_str = bs58::encode(signature_serialized).into_string();

//     println!(
//         "Your {}: \nCopy the following text to \"Twitter\" Section in Google Form:\n {}\n\n\n\n",
//         "Twitter Account".italic(),
//         twitter_account.blue(),
//     );

//     println!(
//         "Your {}: \nCopy the following text to \"Public Key\" Section in Google Form:\n {}\n\n\n\n",
//         "Public Key".italic(),
//         pk_str.blue(),
//     );

//     println!(
//         "Your {}: \nCopy the following text to \"Signature\" Section in Google Form: \n {}\n\n\n\n",
//         "Signature".italic(),
//         signature_str.blue()
//     );

//     println!(
//         "Your {}: \nThe following text stores your secret for trusted setup.\
//          Save the following text somewhere safe. \n DO NOT share this to anyone else!\
//           Please discard this data after the trusted setup ceremony.\n {}",
//         "Secret".italic(),
//         keypair_str.red(),
//     );
// }

// type C = Client<Ed25519, Participant>;

// /// Prompt key pair from user
// fn prompt_key_pair() -> Result<(PrivateKey, PublicKey), Error> {
//     println!(
//         "Please enter your {} that you get when you registered yourself using this tool.",
//         "Secret".italic()
//     );
//     let secret_str: String = Input::with_theme(&ColorfulTheme::default())
//         .with_prompt("Your Secret")
//         .interact_text()
//         .expect("Please enter your secret received during `Register`.");
//     let secret_bytes = bs58::decode(&secret_str)
//         .into_vec()
//         .map_err(|_| Error::InvalidSecret)?;
//     bincode::deserialize(&secret_bytes).map_err(|_| Error::InvalidSecret)
// }

// /// Run `reqwest` contribution client, takes seed as input.
// #[inline]
// pub async fn contribute() -> Result<(), Error> {
//     // Note: seed is the same as the one used during registration.

//     // Generate sk, pk from seed
//     let key_pair = prompt_key_pair()?;

//     // Run ceremony client
//     let participant = init_participant(); // TODO： Replace with
//     let mut trusted_setup_client = C::new(participant, key_pair);

//     let network_client = reqwest::Client::new();

//     loop {
//         // TODO: Add Enqueue. May receive several:

//         // TODO: Handle nonce
//         let query_mpc_state_request = trusted_setup_client.query_mpc_state();
//         let query_mpc_state_response = network_client
//             .post("http://localhost:8080/query") // TODO: Change HTTP path
//             .json(&query_mpc_state_request)
//             .send()
//             .await
//             .unwrap();
//         // let parsed_query_mpc_state_response = match query_mpc_state_response.status() {
//         //     reqwest::StatusCode::OK => {
//         //         query_mpc_state_response.json::<QueryMPCStateResponse<Groth16Phase2<Config>>>().await.unwrap();
//         //     }
//         //     other => {
//         //         panic!("Uh No! Something unexpected happend: {:?}", other);
//         //     }
//         // };
//         let parsed_query_mpc_state_response = query_mpc_state_response
//             .json::<QueryMPCStateResponse<Groth16Phase2<Config>>>()
//             .await
//             .unwrap(); // TODO: Error handling here if response status is bad.
//         let (state, challenge) = match parsed_query_mpc_state_response {
//             QueryMPCStateResponse::Mpc(state, challenge) => {
//                 (state.to_actual(), challenge.to_actual())
//             }
//             QueryMPCStateResponse::QueuePosition(t) => {
//                 println!("Your current position is {}.", t);
//                 thread::sleep(Duration::from_millis(300000));
//                 continue;
//             }
//             QueryMPCStateResponse::NotRegistered => {
//                 println!("You have not registered.");
//                 return Ok(());
//             }
//             QueryMPCStateResponse::HaveContributed => {
//                 println!("You have contributed.");
//                 return Ok(());
//             }
//         };
//         let h = Config::generate_hasher();
//         // <Config as mpc::Configuration>::Hasher;
//         let contribute_request =
//             trusted_setup_client.contribute::<Groth16Phase2<Config>>(&h, &challenge, state);
//         let contribute_response = network_client
//             .post("http://localhost:8080/update") // TODO: Change HTTP path
//             .json(&contribute_request)
//             .send()
//             .await
//             .unwrap();
//         let parsed_contribute_response = contribute_response
//             .json::<ContributeResponse>()
//             .await
//             .unwrap(); // TODO: Error handling here if response status is bad.
//                        // TODO: Need to handle the case if contribute failed due to network reason or other reasons.
//         println!("Contribute succeed: {:?}", parsed_contribute_response);
//         break;
//     }
//     Ok(())
// }

// fn main() {
//     handle_error(Arguments::parse().run()); // TODO: When should we stop?
// }
fn main() {
    
}