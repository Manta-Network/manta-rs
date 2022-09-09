// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! Trusted Setup Client

use crate::groth16::{
    ceremony::{
        message::{CeremonySize, ContributeRequest, QueryRequest, Signed},
        signature::{sign, Message, Nonce},
        Ceremony, CeremonyError,
    },
    mpc::{contribute, State},
};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use colored::Colorize;
use console::{style, Term};
use core::fmt::Debug;
use dialoguer::{theme::ColorfulTheme, Input};
use manta_crypto::{
    dalek::ed25519::{generate_keys, Ed25519},
    rand::OsRng,
};
use manta_util::{
    http::reqwest::KnownUrlClient,
    serde::{de::DeserializeOwned, Serialize},
    BoxArray,
};

/// Client
pub struct Client<C, const CIRCUIT_COUNT: usize>
where
    C: Ceremony,
{
    /// Identifier
    identifier: C::Identifier,

    /// Current Nonce
    nonce: C::Nonce,

    /// Signing Key
    signing_key: C::SigningKey,
}

impl<C, const CIRCUIT_COUNT: usize> Client<C, CIRCUIT_COUNT>
where
    C: Ceremony,
{
    /// Builds a new [`Client`] with `participant` and `private_key`.
    #[inline]
    pub fn new(identifier: C::Identifier, nonce: C::Nonce, signing_key: C::SigningKey) -> Self {
        Self {
            identifier,
            nonce,
            signing_key,
        }
    }

    /// Queries the server state.
    #[inline]
    pub fn query(&mut self) -> Result<Signed<QueryRequest, C>, CeremonyError<C>>
    where
        C::Nonce: Clone,
    {
        let signed_message = Signed::new(
            QueryRequest,
            &self.nonce,
            &self.signing_key,
            self.identifier.clone(),
        )?;
        self.nonce.increment();
        Ok(signed_message)
    }

    /// Contributes to the state on the server.
    #[inline]
    pub fn contribute(
        &mut self,
        hasher: &C::Hasher,
        challenge: &BoxArray<C::Challenge, CIRCUIT_COUNT>,
        mut state: BoxArray<State<C>, CIRCUIT_COUNT>,
    ) -> Result<Signed<ContributeRequest<C, CIRCUIT_COUNT>, C>, CeremonyError<C>>
    where
        C::Nonce: Clone,
    {
        let circuit_name = ["ToPrivate", "PrivateTransfer", "ToPublic"];
        let mut rng = OsRng;
        let mut proofs = Vec::new();
        for i in 0..CIRCUIT_COUNT {
            println!(
                "{} Contributing to {} Circuits...",
                style(format!("[{}/9]", i + 5)).bold().dim(),
                circuit_name[i],
            );
            match contribute(hasher, &challenge[i], &mut state[i], &mut rng) {
                Some(proof) => proofs.push(proof),
                None => return Err(CeremonyError::Unexpected("Cannot contribute.".to_string())),
            }
        }
        println!(
            "{} Waiting for Confirmation from Server... Estimated Waiting Time: {} minutes.",
            style("[8/9]").bold().dim(),
            style("3").bold().blue(),
        );
        let signed_message = Signed::new(
            ContributeRequest((state, BoxArray::from_vec(proofs))),
            &self.nonce,
            &self.signing_key,
            self.identifier.clone(),
        );
        self.nonce.increment();
        signed_message
    }
}

/// Registers a participant.
#[inline]
pub fn register(twitter_account: String, email: String) {
    println!(
        "Your {}: \nCopy the following text to \"Twitter\" Section in Google Sheet:\n {}\n",
        "Twitter Account".italic(),
        twitter_account.blue(),
    );
    println!(
        "Your {}: \nCopy the following text to \"Email\" Section in Google Sheet:\n {}\n",
        "Email".italic(),
        email.blue(),
    );
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed = Seed::new(&mnemonic, "manta-trusted-setup");
    let key_pair = generate_keys(seed.as_bytes()).expect("Should generate a key pair.");
    println!(
        "Your {}: \nCopy the following text to \"Public Key\" Section in Google Sheet:\n {}\n",
        "Public Key".italic(),
        bs58::encode(key_pair.public).into_string().blue(),
    );
    let signature = sign::<_, Ed25519<Message<u64>>>(
        &key_pair.secret,
        0,
        &format!(
            "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
            twitter_account, email
        ),
    )
    .expect("Signing message should succeed.");
    println!(
        "Your {}: \nCopy the following text to \"Signature\" Section in Google Sheet: \n {}\n",
        "Signature".italic(),
        bs58::encode(signature).into_string().blue()
    );
    println!(
        "Your {}: \nThe following text stores your secret for trusted setup. \
         Save the following text somewhere safe. \n DO NOT share this to anyone else! \
         Please discard this data after the trusted setup ceremony.\n {}",
        "Secret".italic(),
        mnemonic.phrase().red(),
    );
}

/// Prompts the client information and get client keys.
#[inline]
pub fn get_client_keys<C>() -> Result<(C::SigningKey, C::VerifyingKey), CeremonyError<C>>
where
    C: Ceremony,
{
    println!(
        "Please enter your {} that you get when you registered yourself using this tool.",
        "Secret".italic()
    );
    let seed_bytes = Seed::new(
        &Mnemonic::from_phrase(
            Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Your Secret")
                .validate_with(|input: &String| -> Result<(), &str> {
                    Mnemonic::validate(input, Language::English)
                        .map_err(|_| "This is not a valid secret.")
                })
                .interact_text()
                .expect("Please enter your secret received during `Register`.")
                .as_str(),
            Language::English,
        )
        .expect("Should produce a mnemonic from the secret."),
        "manta-trusted-setup",
    )
    .as_bytes()
    .to_vec();
    match C::generate_keys(&seed_bytes) {
        Some(key_pair) => Ok(key_pair),
        None => Err(CeremonyError::Unexpected(
            "Cannot generate keys.".to_string(),
        )),
    }
}

/// Gets state size from server.
#[inline]
pub async fn get_start_meta_data<C, const CIRCUIT_COUNT: usize>(
    identity: C::Identifier,
    network_client: &KnownUrlClient,
) -> Result<(CeremonySize<CIRCUIT_COUNT>, C::Nonce), CeremonyError<C>>
where
    C: Ceremony,
    C::Identifier: Serialize,
    C::Nonce: DeserializeOwned + Debug,
{
    match network_client
        .post::<_, Result<(CeremonySize<CIRCUIT_COUNT>, C::Nonce), CeremonyError<C>>>(
            "start", &identity,
        )
        .await
        .map_err(|_| {
            return CeremonyError::Network(
                "Should have received starting meta data from server".to_string(),
            );
        })? {
        Ok((server_size, nonce)) => Ok((server_size, nonce)),
        Err(CeremonyError::NotRegistered) => Err(CeremonyError::NotRegistered),
        Err(e) => Err(CeremonyError::Unexpected(format!("{:?}", e))),
    }
}

// /// Contributes to the server.
// #[inline]
// pub async fn client_contribute<C, const CIRCUIT_COUNT: usize>() -> Result<(), CeremonyError<C>>
// where
//     C: Ceremony<Identifier = VerifyingKey>,
//     C::Identifier: Serialize,
//     C::Nonce: DeserializeOwned + Debug,
//     // C::Participant: CHasIdentifier<Identifier = PublicKey<C>> + Clone,
//     // E: PairingEngine,
//     // P: Pairing<Pairing = E>,
//     // ParticipantIdentifier<C>: Serialize,
//     // Nonce<C>: DeserializeOwned + Debug,
//     // State<C>: CanonicalDeserialize,
//     // Challenge<C>: CanonicalDeserialize,
//     // Proof<C>: CanonicalSerialize,
//     // <C as CeremonyConfig>::Setup: Types<State = ProvingKey<E>>,
// {
//     let network_client = KnownUrlClient::new("http://localhost:8080").expect("Should succeed.");
//     let (sk, pk) = get_client_keys()?;
//     println!(
//         "{} Contacting Server for Meta Data...",
//         style("[1/9]").bold().dim()
//     );
//     let term = Term::stdout();
//     let (size, nonce) = get_start_meta_data::<C, CIRCUIT_COUNT>(pk, &network_client).await?;
//     // let mut trusted_setup_client = Client::<C, CIRCUIT_COUNT>::new(pk, nonce, sk);
//     // println!("{} Waiting in Queue...", style("[2/9]").bold().dim(),);
//     // loop {
//     //     let mpc_state = match network_client
//     //         .post::<_, Result<QueryResponse<C, CIRCUIT_COUNT>, CeremonyError<C>>>(
//     //             "query",
//     //             &trusted_setup_client
//     //                 .query()
//     //                 .map_err(|_| Error::UnableToGenerateRequest("Queries the server state."))?,
//     //         )
//     //         .await
//     //         .map_err(|_| {
//     //             return Error::NetworkError(
//     //                 "Should have received starting meta data from server".to_string(),
//     //             );
//     //         })? {
//     //         Err(CeremonyError::Timeout) => {
//     //             term.clear_last_lines(1)
//     //                 .expect("Clear last lines should succeed.");
//     //             println!(
//     //                 "{} You have timed out. Waiting in Queue again...",
//     //                 style("[2/9]").bold().dim(),
//     //             );
//     //             continue;
//     //         }
//     //         Err(CeremonyError::NotRegistered) => return Err(Error::NotRegistered),
//     //         Err(CeremonyError::NonceNotInSync(_)) => {
//     //             return Err(Error::UnexpectedError(
//     //                 "Unexpected error when query mpc state. Nonce should have been synced."
//     //                     .to_string(),
//     //             ))
//     //         }
//     //         Err(CeremonyError::BadRequest) => {
//     //             return Err(Error::UnexpectedError(
//     //                 "Unexpected error when query mpc state since finding a bad request."
//     //                     .to_string(),
//     //             ))
//     //         }
//     //         Err(CeremonyError::AlreadyContributed) => return Err(Error::AlreadyContributed),
//     //         Err(CeremonyError::NotYourTurn) => {
//     //             return Err(Error::UnexpectedError(
//     //                     "Unexpected error when query mpc state. Should not receive NotYourTurn message."
//     //                         .to_string(),
//     //                 ));
//     //         }
//     //         Ok(message) => match message {
//     //             QueryResponse::QueuePosition(position) => {
//     //                 term.clear_last_lines(1)
//     //                     .expect("Clear last lines should succeed.");
//     //                 println!(
//     //                         "{} Waiting in Queue... There are {} people ahead of you. Estimated Waiting Time: {} minutes.",
//     //                         style("[2/9]").bold().dim(),
//     //                         style(position).bold().red(),
//     //                         style(5*position).bold().blue(),
//     //                     );
//     //                 thread::sleep(Duration::from_secs(10));
//     //                 continue;
//     //             }
//     //             QueryResponse::Mpc(mpc_state) => {
//     //                 term.clear_last_lines(1)
//     //                     .expect("Clear last lines should succeed.");
//     //                 println!("{} Waiting in Queue...", style("[2/9]").bold().dim(),);
//     //                 println!(
//     //                     "{} Downloading Ceremony States...",
//     //                     style("[3/9]").bold().dim(),
//     //                 );
//     //                 if !check_state_size::<P, CIRCUIT_COUNT>(&mpc_state.state, &size) {
//     //                     return Err(Error::UnexpectedError(
//     //                         "Received mpc state size is not correct.".to_string(),
//     //                     ));
//     //                 }
//     //                 mpc_state
//     //             }
//     //         },
//     //     };
//     //     println!(
//     //         "{} Starting contribution to 3 Circuits...",
//     //         style("[4/9]").bold().dim(),
//     //     );
//     //     match network_client
//     //         .post::<_, Result<(), CeremonyError<Groth16BLS12381>>>(
//     //             "update",
//     //             &trusted_setup_client
//     //                 .contribute(
//     //                     &Hasher::<C>::default(),
//     //                     &mpc_state.challenge,
//     //                     mpc_state.state,
//     //                 )
//     //                 .map_err(|_| Error::UnableToGenerateRequest("contribute"))?,
//     //         )
//     //         .await
//     //         .map_err(|_| {
//     //             return Error::NetworkError(
//     //                 "Should have received starting meta data from server".to_string(),
//     //             );
//     //         })? {
//     //         Err(CeremonyError::Timeout) => {
//     //             term.clear_last_lines(1)
//     //                 .expect("Clear last lines should succeed.");
//     //             println!(
//     //                 "{} You have timed out. Waiting in Queue again...",
//     //                 style("[2/9]").bold().dim(),
//     //             );
//     //             continue;
//     //         }
//     //         Err(CeremonyError::NotRegistered) => {
//     //             return Err(Error::UnexpectedError(
//     //                 "unexpected error when contribute. Should have registered.".to_string(),
//     //             ))
//     //         }
//     //         Err(CeremonyError::NonceNotInSync(_)) => {
//     //             return Err(Error::UnexpectedError(
//     //                 "unexpected error when contribute. Nonce should have been synced.".to_string(),
//     //             ))
//     //         }
//     //         Err(CeremonyError::BadRequest) => {
//     //             return Err(Error::UnexpectedError(
//     //                 "unexpected error when contribute since finding a bad request.".to_string(),
//     //             ))
//     //         }
//     //         Err(CeremonyError::NotYourTurn) => {
//     //             println!(
//     //                 "{} Lag behind server. Contacting Server again...",
//     //                 style("[8/9]").bold().dim(),
//     //             );
//     //             continue;
//     //         }
//     //         Err(CeremonyError::AlreadyContributed) => return Err(Error::AlreadyContributed),
//     //         Ok(_) => {
//     //             term.clear_last_lines(1)
//     //                 .expect("Clear last lines should succeed.");
//     //             println!(
//     //                 "{} Waiting for Confirmation from Server...",
//     //                 style("[8/9]").bold().dim(),
//     //             );
//     //             println!(
//     //                         "{} Congratulations! You have successfully contributed to Manta Trusted Setup Ceremony!...",
//     //                         style("[9/9]").bold().dim(),
//     //                     );
//     //             break;
//     //         }
//     //     }
//     // }
//     Ok(())
// }
