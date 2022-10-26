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

//! Groth16 Trusted Setup Ceremony Perpetual Powers of Tau Configuration

use crate::{
    ceremony::{
        participant, registry,
        signature::{sign, verify, Nonce as _, RawMessage, SignatureScheme},
    },
    groth16::{
        ceremony::{
            client::{self, Continue},
            message::ContributeResponse,
            Ceremony, CeremonyError, Circuits,
        },
        kzg::{self, Accumulator, Contribution, Size},
        mpc::{Configuration, Proof, ProvingKeyHasher, State},
    },
    mpc::{ChallengeType, ContributionType, ProofType, StateType},
    util::{BlakeHasher, KZGBlakeHasher},
};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use blake2::Digest;
use colored::Colorize;
use console::{style, Term};
use core::fmt::{self, Debug, Display};
use csv::{Reader, StringRecord, WriterBuilder};
// use dialoguer::{theme::ColorfulTheme, Input};
use manta_crypto::{
    arkworks::{
        bn254::{self, Fr},
        ec::{AffineCurve, PairingEngine},
        ff::field_new,
        pairing::Pairing,
        r1cs_std::eq::EqGadget,
        serialize::{CanonicalSerialize, SerializationError},
    },
    dalek::ed25519::{self, generate_keypair, Ed25519, SECRET_KEY_LENGTH},
    eclair::alloc::{
        mode::{Public, Secret},
        Allocate,
    },
    rand::{ChaCha20Rng, OsRng, Rand, SeedableRng},
    signature,
};
use manta_pay::{
    config::{FullParameters, Mint, PrivateTransfer, Reclaim},
    crypto::constraint::arkworks::{Fp, FpVar, R1CS},
    parameters::load_parameters,
};
use manta_util::{
    into_array_unchecked,
    serde::{de::DeserializeOwned, Deserialize, Serialize},
    Array,
};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

type Signature = Ed25519<RawMessage<u64>>;
type VerifyingKey = signature::VerifyingKey<Signature>;
type Nonce = <Signature as SignatureScheme>::Nonce;

/// Priority
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub enum Priority {
    /// High Priority
    High,

    /// Normal Priority
    Normal,
}

impl From<Priority> for usize {
    #[inline]
    fn from(priority: Priority) -> Self {
        match priority {
            Priority::High => 0,
            Priority::Normal => 1,
        }
    }
}

impl From<Priority> for String {
    #[inline]
    fn from(value: Priority) -> Self {
        match value {
            Priority::High => "high".to_string(),
            _ => "normal".to_string(),
        }
    }
}

impl From<&Priority> for String {
    #[inline]
    fn from(value: &Priority) -> Self {
        Self::from(*value)
    }
}

impl From<String> for Priority {
    #[inline]
    fn from(value: String) -> Self {
        match value.as_str() {
            "high" => Priority::High,
            _ => Priority::Normal,
        }
    }
}

/// Participant
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    bound(
        deserialize = r"
            VerifyingKey: Deserialize<'de>,
            Nonce: Deserialize<'de>,
        ",
        serialize = r"
            VerifyingKey: Serialize,
            Nonce: Serialize,
        "
    ),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct Participant {
    /// Twitter Account
    twitter: String,

    /// Priority
    priority: Priority,

    /// Verifying Key
    verifying_key: VerifyingKey,

    /// Nonce
    nonce: Nonce,

    /// Boolean on whether this participant has contributed
    contributed: bool,
}

impl fmt::Display for Participant {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.twitter())
    }
}

impl Participant {
    /// Builds a new [`Participant`].
    #[inline]
    pub fn new(
        verifying_key: VerifyingKey,
        twitter: String,
        priority: Priority,
        nonce: Nonce,
        contributed: bool,
    ) -> Self {
        Self {
            verifying_key,
            twitter,
            priority,
            nonce,
            contributed,
        }
    }

    /// Gets `twitter`.
    #[inline]
    pub fn twitter(&self) -> &str {
        &self.twitter
    }
}

impl participant::Participant for Participant {
    type Identifier = VerifyingKey;
    type VerifyingKey = VerifyingKey;
    type Nonce = Nonce;

    #[inline]
    fn id(&self) -> &Self::Identifier {
        &self.verifying_key
    }

    #[inline]
    fn verifying_key(&self) -> &Self::VerifyingKey {
        &self.verifying_key
    }

    #[inline]
    fn has_contributed(&self) -> bool {
        self.contributed
    }

    #[inline]
    fn set_contributed(&mut self) {
        self.contributed = true
    }

    #[inline]
    fn nonce(&self) -> &Self::Nonce {
        &self.nonce
    }

    #[inline]
    fn increment_nonce(&mut self) {
        self.nonce.increment();
    }
}

impl participant::Priority for Participant {
    type Priority = Priority;

    #[inline]
    fn priority(&self) -> Self::Priority {
        self.priority
    }

    #[inline]
    fn reduce_priority(&mut self) {
        self.priority = Priority::Normal;
    }
}

/// Record
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(
    bound(deserialize = "", serialize = ""),
    crate = "manta_util::serde",
    deny_unknown_fields
)]
pub struct Record {
    /// Twitter Account
    twitter: String,

    /// Email Account
    email: String,

    /// Priority Level
    priority: String,

    /// Verifying Key
    verifying_key: String,

    /// Signature
    signature: String,
}

impl Record {
    /// Constructor
    pub fn new(
        twitter: String,
        email: String,
        priority: String,
        verifying_key: String,
        signature: String,
    ) -> Self {
        Self {
            twitter,
            email,
            priority,
            verifying_key,
            signature,
        }
    }
}

impl registry::csv::Record<VerifyingKey, Participant> for Record {
    type Error = String;

    #[inline]
    fn parse(self) -> Result<(VerifyingKey, Participant), Self::Error> {
        let verifying_key = ed25519::public_key_from_bytes(
            bs58::decode(self.verifying_key)
                .into_vec()
                .map_err(|e| {
                    println!("Error decoding verifying key {:?}", e);
                    "Cannot decode signature.".to_string()
                })?
                .try_into()
                .map_err(|e| {
                    println!("Array conversion failed on verifying key {:?}", e);
                    "Cannot decode to array.".to_string()
                })?,
        )
        .map_err(|_| "Byte conversion failed on verifying key.".to_string())?;
        let verifying_key = Array::from_unchecked(*verifying_key.as_bytes());
        let signature: ed25519::Signature = ed25519::signature_from_bytes(
            bs58::decode(self.signature)
                .into_vec()
                .map_err(|e| {
                    println!("Error decoding signature {:?}", e);
                    "Cannot decode signature.".to_string()
                })?
                .try_into()
                .map_err(|e| {
                    println!("Array conversion failed on signature {:?}", e);
                    "Cannot decode to array.".to_string()
                })?,
        )
        .map_err(|_| "Byte conversion failed on signature.".to_string())?;
        verify::<Signature, _>(
            &verifying_key,
            0,
            &format!(
                "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
                self.twitter, self.email
            ),
            &signature,
        )
        .map_err(|_| "Cannot verify signature.".to_string())?;
        Ok((
            verifying_key,
            Participant::new(
                verifying_key,
                self.twitter,
                self.priority.into(),
                OsRng.gen::<_, u16>() as u64,
                false,
            ),
        ))
    }
}

/// Errors that may occur when processing raw registration data.
#[derive(Debug)]
pub enum RegistrationProcessingError {
    /// Raw data headers don't match expected
    WrongHeaders,

    /// Attempted to process data in unsupported format
    BadDataFormat,

    /// Error when writing processed data
    WriteError,
}

/// Sets the header (column names) of this CSV Reader. Error if
/// the existing field names do not match the given expected names.
pub fn set_header(
    reader: &mut Reader<&File>,
    expected_headers: Vec<&str>,
    short_headers: Vec<&str>,
) -> Result<(), RegistrationProcessingError> {
    match reader.byte_headers() {
        Ok(headers) => {
            if headers != expected_headers {
                println!("Actual headers were \n{headers:?}");
                Err(RegistrationProcessingError::WrongHeaders)
            } else {
                assert_eq!(expected_headers.len(), short_headers.len());
                reader.set_headers(StringRecord::from(short_headers));
                Ok(())
            }
        }
        _ => Err(RegistrationProcessingError::BadDataFormat),
    }
}

/// Extracts all [`Record`]s from a CSV file of raw registration
/// data and creates new CSV file containing only these `Record`s
/// at the specified path. A [`Registry`] can be loaded from the
/// resulting file. Creates another CSV file of malformed registry entries
/// in case ceremony coordinators wish to examine these.
/// Returns the pair (number successfully parsed, number malformed)
/// Participants are given default priority
pub fn extract_registry<R>(
    file: &File,
    path: PathBuf,
    expected_headers: Vec<&str>,
    short_headers: Vec<&str>,
    priority_list: HashMap<Array<u8, 32>, Priority>,
) -> Result<(usize, usize), RegistrationProcessingError>
where
    R: DeserializeOwned + Into<Record> + Clone,
{
    let mut reader = Reader::from_reader(file);
    set_header(&mut reader, expected_headers, short_headers)?;
    let mut file_out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|_| RegistrationProcessingError::WriteError)?;
    let mut file_malformed = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(
            path.parent()
                .expect("Path should have a parent")
                .join("malformed_registry_submissions.csv"),
        )
        .map_err(|_| RegistrationProcessingError::WriteError)?;
    let mut writer = WriterBuilder::new().from_writer(&mut file_out);
    let mut writer_malformed = WriterBuilder::new().from_writer(&mut file_malformed);

    let mut num_successful = 0;
    let mut num_malformed = 0;
    for (i, record) in reader.deserialize::<R>().flatten().enumerate() {
        match <Record as registry::csv::Record<_, _>>::parse(record.clone().into()) {
            Ok((verifying_key, _)) => {
                let mut record: Record = record.into();
                if let Some(priority) = priority_list.get(&verifying_key) {
                    record.priority = priority.into();
                } else {
                    record.priority = Priority::Normal.into();
                }
                num_successful += 1;
                writer
                    .serialize(record)
                    .map_err(|_| RegistrationProcessingError::WriteError)?
            }
            Err(e) => {
                println!("Encountered error {e:?} when reading entry {}", i + 2);
                num_malformed += 1;
                writer_malformed
                    .serialize(record.into())
                    .map_err(|_| RegistrationProcessingError::WriteError)?
            }
        }
    }
    Ok((num_successful, num_malformed))
}

/// The registry used in this ceremony
pub type Registry = HashMap<VerifyingKey, Participant>;

impl registry::Configuration for Registry {
    type Identifier = VerifyingKey;
    type Participant = Participant;
    type Record = Record;
    type Registry = Self;
}

/// Generates an ed25519 keypair with `bytes` as seed.
#[inline]
pub fn generate_keys(bytes: &[u8]) -> Option<(ed25519::SecretKey, ed25519::PublicKey)> {
    if ed25519::SECRET_KEY_LENGTH > bytes.len() {
        return None;
    }
    let keypair = generate_keypair(&mut ChaCha20Rng::from_seed(
        bytes[0..SECRET_KEY_LENGTH].try_into().ok()?,
    ));
    Some((keypair.secret, keypair.public))
}

/// Registers a participant.
#[inline]
pub fn register(twitter_account: String, email: String) {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed = Seed::new(&mnemonic, "manta-trusted-setup");
    let keypair = generate_keys(seed.as_bytes()).expect("Should generate a key pair.");
    let signature = sign::<Ed25519<RawMessage<u64>>, _>(
        &keypair.0,
        Default::default(),
        &format!(
            "manta-trusted-setup-twitter:{}, manta-trusted-setup-email:{}",
            twitter_account, email
        ),
    )
    .expect("Signing message should succeed.");
    println!(
        "Your {}: \nThe following text stores your secret for the trusted setup. \
         Save the following text somewhere safe. \n DO NOT share this with anyone else! \
         Please discard this data after the trusted setup ceremony.\n {} \n",
        "Secret".italic(),
        mnemonic.phrase().red().bold(),
    );

    println!("Your registration is not complete until you submit the following form: \nCopy this link to your browser and complete registration there \n \n{}\nBe sure to copy this link exactly! Do not leave out any characters!", register_link(twitter_account, email, bs58::encode(keypair.1).into_string(), bs58::encode(signature).into_string()).green());
}

/// Generates link to registration form with Twitter, Email, Public Key,
/// Signature fields pre-filled.
pub fn register_link(
    twitter: String,
    email: String,
    public_key: String,
    signature: String,
) -> String {
    format!("https://mantanetwork.typeform.com/trustedsetup2#twitter={twitter}&email={email}&verifying_key={public_key}&signature={signature} \n")
}

/// Prompts the client information and get client keys.
#[inline]
pub fn get_client_keys(
    text: &String,
) -> Result<(ed25519::SecretKey, ed25519::PublicKey), ClientKeyError> {
    Mnemonic::validate(text.trim(), Language::English)
        .map_err(|_| ClientKeyError::InvalidSecret)?;
    // println!(
    //     "Please enter the {} you received when you registered yourself using this tool.",
    //     "Secret".italic()
    // );
    // let text = Input::with_theme(&ColorfulTheme::default())
    //     .with_prompt("Your Secret")
    //     .validate_with(|input: &String| -> Result<(), &str> {
    //         Mnemonic::validate(input.trim(), Language::English)
    //             .map_err(|_| "This is not a valid secret.")
    //     })
    //     .interact_text()
    //     .map_err(|_| ClientKeyError::InvalidSecret)?;
    let mnemonic = Mnemonic::from_phrase(text.trim(), Language::English)
        .map_err(|_| ClientKeyError::MnemonicFailure)?;
    let seed_bytes = Seed::new(&mnemonic, "manta-trusted-setup")
        .as_bytes()
        .to_vec();
    generate_keys(&seed_bytes).ok_or(ClientKeyError::KeyGenerationFailure)
}

/// Client Key Error
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(crate = "manta_util::serde", deny_unknown_fields)]
pub enum ClientKeyError {
    /// Invalid Secret
    InvalidSecret,

    /// Mnemonic Generation Failure
    MnemonicFailure,

    /// Key Generation Failure
    KeyGenerationFailure,
}

impl fmt::Display for ClientKeyError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecret => {
                write!(
                    f,
                    "Your {} is invalid. Please enter the secret you received during `Register`.",
                    "secret".italic()
                )
            }
            Self::MnemonicFailure => {
                write!(f, "Should produce a mnemonic from the secret.")
            }
            Self::KeyGenerationFailure => {
                write!(f, "Failed to generate keys from seed bytes.")
            }
        }
    }
}

/// Contributes to the server.
#[inline]
pub async fn client_contribute<C>(
    signing_key: C::SigningKey,
    identifier: C::Identifier,
    url: String,
) -> Result<(), CeremonyError<C>>
where
    C: Ceremony,
    C::Challenge: Debug + DeserializeOwned,
    C::ContributionHash: AsRef<[u8]> + Debug,
    C::Identifier: Serialize,
    C::Nonce: Clone + Debug + DeserializeOwned + Serialize,
    C::Signature: Serialize,
    C::ContributionHash: AsRef<[u8]>,
{
    println!(
        "{} Retrieving ceremony metadata from server.",
        style("[0/6]").bold()
    );

    let term = Term::stdout();

    let mut downloading_state = false;

    let response =
        client::contribute(
            signing_key,
            identifier,
            url.as_str(),
            |metadata, state| match state {
                Continue::Started => {
                    println!("\n");
                }
                Continue::Position(position) => {
                    if !downloading_state {
                        let _ = term.clear_last_lines(2);
                        if position == 0 {
                            println!("{} Waiting in queue...", style("[1/6]").bold());
                            println!(
                                "{} Receiving data from Server... \
                             This may take a few minutes.",
                                style("[2/6]").bold()
                            );
                            downloading_state = true;
                        } else if position <= u32::MAX.into() {
                            let minutes =
                                metadata.contribution_time_limit.as_secs() * position / 60;
                            println!(
                                "{} Waiting in queue... There are {} people ahead of you.\n      \
                             Estimated Waiting Time: {}.",
                                style("[1/6]").bold(),
                                style(position).bold().red(),
                                style(format!("{minutes:?} min")).bold().red(),
                            );
                        } else {
                            println!(
                                "{} Waiting in queue... There are many people ahead of you. \
                             Estimated Waiting Time: forever.",
                                style("[1/6]").bold(),
                            );
                        }
                    }
                }
                Continue::ComputingUpdate => {
                    downloading_state = false;
                    println!(
                        "{} Computing contributions. This may take up to 10 minutes.",
                        style("[3/6]").bold()
                    );
                }
                Continue::SendingUpdate => {
                    println!(
                        "{} Contribution Computed. Sending data to server.",
                        style("[4/6]").bold()
                    );
                    println!(
                        "{} Awaiting confirmation from server.",
                        style("[5/6]").bold()
                    );
                }
                Continue::Timeout => {
                    downloading_state = false;
                    let _ = term.clear_last_lines(1);
                    println!(
                        "{} You have timed out. Waiting in queue again ... \n\n",
                        style("[WARN]").bold().yellow()
                    );
                }
            },
        )
        .await?;
    let contribution_hash = hex::encode(C::contribution_hash(&response));
    let tweet = style(format!(
        "I made contribution number {} to the #MantaNetworkTrustedSetup! \
         My contribution's hash is {contribution_hash}",
        response.index
    ))
    .bold()
    .blue();
    println!(
        "{} Success! You have contributed to the security of Manta Pay! \n\
        Now set your contribution in stone! Tweet:\n{}",
        style("[6/6]").bold(),
        tweet,
    );
    Ok(())
}

/// Contributes to the server.
#[inline]
pub async fn client_contribute_bad_proof<C>(
    signing_key: C::SigningKey,
    identifier: C::Identifier,
    url: String,
) -> Result<(), CeremonyError<C>>
where
    C: Ceremony,
    C::Challenge: Debug + DeserializeOwned,
    C::ContributionHash: AsRef<[u8]> + Debug,
    C::Identifier: Serialize,
    C::Nonce: Clone + Debug + DeserializeOwned + Serialize,
    C::Signature: Serialize,
    C::ContributionHash: AsRef<[u8]>,
{
    println!(
        "{} Retrieving ceremony metadata from server.",
        style("[0/6]").bold()
    );

    let term = Term::stdout();

    let mut downloading_state = false;

    let response =
        client::contribute_bad_proof(signing_key, identifier, url.as_str(), |metadata, state| {
            match state {
                Continue::Started => {
                    println!("\n");
                }
                Continue::Position(position) => {
                    if !downloading_state {
                        let _ = term.clear_last_lines(2);
                        if position == 0 {
                            println!("{} Waiting in queue...", style("[1/6]").bold());
                            println!(
                                "{} Receiving data from Server... \
                             This may take a few minutes.",
                                style("[2/6]").bold()
                            );
                            downloading_state = true;
                        } else if position <= u32::MAX.into() {
                            let minutes =
                                metadata.contribution_time_limit.as_secs() * position / 60;
                            println!(
                                "{} Waiting in queue... There are {} people ahead of you.\n      \
                             Estimated Waiting Time: {}.",
                                style("[1/6]").bold(),
                                style(position).bold().red(),
                                style(format!("{:?} min", minutes)).bold().red(),
                            );
                        } else {
                            println!(
                                "{} Waiting in queue... There are many people ahead of you. \
                             Estimated Waiting Time: forever.",
                                style("[1/6]").bold(),
                            );
                        }
                    }
                }
                Continue::ComputingUpdate => {
                    downloading_state = false;
                    println!(
                        "{} Computing contributions. This may take up to 10 minutes.",
                        style("[3/6]").bold()
                    );
                }
                Continue::SendingUpdate => {
                    println!(
                        "{} Contribution Computed. Sending data to server.",
                        style("[4/6]").bold()
                    );
                    println!(
                        "{} Awaiting confirmation from server.",
                        style("[5/6]").bold()
                    );
                }
                Continue::Timeout => {
                    downloading_state = false;
                    let _ = term.clear_last_lines(1);
                    println!(
                        "{} You have timed out. Waiting in queue again ... \n\n",
                        style("[WARN]").bold().yellow()
                    );
                }
            }
        })
        .await?;
    let contribution_hash = hex::encode(C::contribution_hash(&response));
    let tweet = style(format!(
        "I made contribution number {} to the #MantaNetworkTrustedSetup! \
         My contribution's hash is {}",
        response.index, contribution_hash
    ))
    .bold()
    .blue();
    println!(
        "{} Success! You have contributed to the security of Manta Pay! \n\
        Now set your contribution in stone! Tweet:\n{}",
        style("[6/6]").bold(),
        tweet,
    );
    Ok(())
}

/// Configuration for the Groth16 Phase2 Server.
#[derive(Clone, Default)]
pub struct Config(Ed25519<RawMessage<u64>>);

impl Pairing for Config {
    type Scalar = bn254::Fr;
    type G1 = bn254::G1Affine;
    type G1Prepared = <bn254::Bn254 as PairingEngine>::G1Prepared;
    type G2 = bn254::G2Affine;
    type G2Prepared = <bn254::Bn254 as PairingEngine>::G2Prepared;
    type Pairing = bn254::Bn254;

    #[inline]
    fn g1_prime_subgroup_generator() -> Self::G1 {
        bn254::G1Affine::prime_subgroup_generator()
    }

    #[inline]
    fn g2_prime_subgroup_generator() -> Self::G2 {
        bn254::G2Affine::prime_subgroup_generator()
    }
}

impl Size for Config {
    const G1_POWERS: usize = (Self::G2_POWERS << 1) - 1;
    const G2_POWERS: usize = 1 << 17;
}

impl ProvingKeyHasher<Self> for Config {
    type Output = [u8; 64];

    #[inline]
    fn hash(proving_key: &ark_groth16::ProvingKey<<Self as Pairing>::Pairing>) -> Self::Output {
        let mut hasher = BlakeHasher::default();
        proving_key
            .serialize(&mut hasher)
            .expect("Hasher is not allowed to fail");
        into_array_unchecked(hasher.0.finalize())
    }
}

impl kzg::Configuration for Config {
    type DomainTag = u8;
    type Challenge = [u8; 64];
    type Response = [u8; 64];
    type HashToGroup = KZGBlakeHasher<Self>;
    const TAU_DOMAIN_TAG: Self::DomainTag = 0;
    const ALPHA_DOMAIN_TAG: Self::DomainTag = 1;
    const BETA_DOMAIN_TAG: Self::DomainTag = 2;

    #[inline]
    fn hasher(domain_tag: Self::DomainTag) -> Self::HashToGroup {
        Self::HashToGroup { domain_tag }
    }

    #[inline]
    fn response(
        state: &Accumulator<Self>,
        challenge: &Self::Challenge,
        proof: &kzg::Proof<Self>,
    ) -> Self::Response {
        let mut hasher = BlakeHasher::default();
        for item in &state.tau_powers_g1 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        for item in &state.tau_powers_g2 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        for item in &state.alpha_tau_powers_g1 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        for item in &state.beta_tau_powers_g1 {
            item.serialize_uncompressed(&mut hasher).unwrap();
        }
        state.beta_g2.serialize_uncompressed(&mut hasher).unwrap();
        hasher.0.update(challenge);
        proof
            .tau
            .serialize(&mut hasher)
            .expect("Consuming ratio proof of tau failed.");
        proof
            .alpha
            .serialize(&mut hasher)
            .expect("Consuming ratio proof of alpha failed.");
        proof
            .beta
            .serialize(&mut hasher)
            .expect("Consuming ratio proof of beta failed.");
        into_array_unchecked(hasher.0.finalize())
    }
}

impl StateType for Config {
    type State = State<Self>;
}

impl ProofType for Config {
    type Proof = Proof<Self>;
}

/// Challenge Type
pub type Challenge = manta_util::Array<u8, 64>;

impl ChallengeType for Config {
    type Challenge = Challenge;
}

impl ContributionType for Config {
    type Contribution = Contribution<Self>;
}

impl Configuration for Config {
    type Hasher = BlakeHasher;

    #[inline]
    fn challenge(
        challenge: &Self::Challenge,
        prev: &State<Self>,
        next: &State<Self>,
        proof: &Proof<Self>,
    ) -> Self::Challenge {
        let mut hasher = Self::Hasher::default();
        hasher.0.update(challenge.0);
        prev.0
            .serialize_uncompressed(&mut hasher)
            .expect("Consuming the previous state failed.");
        next.0
            .serialize_uncompressed(&mut hasher)
            .expect("Consuming the current state failed.");
        proof
            .0
            .serialize_uncompressed(&mut hasher)
            .expect("Consuming proof failed");
        into_array_unchecked(hasher.0.finalize()).into()
    }
}

impl signature::SignatureType for Config {
    type Signature = <Ed25519<RawMessage<u64>> as signature::SignatureType>::Signature;
}

impl signature::SigningKeyType for Config {
    type SigningKey = <Ed25519<RawMessage<u64>> as signature::SigningKeyType>::SigningKey;
}

impl signature::MessageType for Config {
    type Message = <Ed25519<RawMessage<u64>> as signature::MessageType>::Message;
}

impl signature::RandomnessType for Config {
    type Randomness = <Ed25519<RawMessage<u64>> as signature::RandomnessType>::Randomness;
}

impl signature::VerifyingKeyType for Config {
    type VerifyingKey = <Ed25519<RawMessage<u64>> as signature::VerifyingKeyType>::VerifyingKey;
}

impl signature::Sign for Config {
    #[inline]
    fn sign(
        &self,
        signing_key: &Self::SigningKey,
        randomness: &Self::Randomness,
        message: &Self::Message,
        compiler: &mut (),
    ) -> Self::Signature {
        self.0.sign(signing_key, randomness, message, compiler)
    }
}

impl signature::Verify for Config {
    type Verification = <Ed25519<RawMessage<u64>> as signature::Verify>::Verification;

    #[inline]
    fn verify(
        &self,
        verifying_key: &Self::VerifyingKey,
        message: &Self::Message,
        signature: &Self::Signature,
        compiler: &mut (),
    ) -> Self::Verification {
        self.0.verify(verifying_key, message, signature, compiler)
    }
}

impl SignatureScheme for Config {
    type Nonce = <Ed25519<RawMessage<u64>> as SignatureScheme>::Nonce;
    type Error = <Ed25519<RawMessage<u64>> as SignatureScheme>::Error;
}

impl Ceremony for Config {
    type Identifier = Self::VerifyingKey;
    type Priority = Priority;
    type Participant = Participant;
    type SerializationError = SerializationError;
    type ContributionHash = [u8; 16];

    #[inline]
    fn check_state(state: &Self::State) -> Result<(), Self::SerializationError> {
        state.check()
    }

    #[inline]
    fn contribution_hash(response: &ContributeResponse<Self>) -> Self::ContributionHash {
        let mut hasher = blake2::Blake2b::default();
        hasher.update(response.index.to_le_bytes());
        for challenge in &response.challenge {
            hasher.update(challenge.0);
        }
        into_array_unchecked(hasher.finalize())
    }
}

impl Circuits<<Self as Pairing>::Scalar> for Config {
    #[inline]
    fn circuits() -> Vec<(R1CS<<Self as Pairing>::Scalar>, String)> {
        let mut circuits = Vec::new();

        // TODO: manta_parameters needs to be updated to Bn254 parameters

        // let path = Path::new("/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/src/tests"); // What directory can I use?
        // let (_multi_proving_context, _multi_verifying_context, parameters, utxo_accumulator_model) =
        //     load_parameters(path).expect("Error loading parameters");

        // circuits.push((
        //     Mint::unknown_constraints(FullParameters::new(&parameters, &utxo_accumulator_model)),
        //     "mint".to_string(),
        // ));
        // circuits.push((
        //     PrivateTransfer::unknown_constraints(FullParameters::new(
        //         &parameters,
        //         &utxo_accumulator_model,
        //     )),
        //     "transfer".to_string(),
        // ));
        // circuits.push((
        //     Reclaim::unknown_constraints(FullParameters::new(&parameters, &utxo_accumulator_model)),
        //     "reclaim".to_string(),
        // ));

        // Placeholder:
        for i in 0..3 {
            let mut cs = R1CS::for_contexts();
            dummy_circuit(&mut cs);
            circuits.push((cs, format!("dummy_{i}")));
        }
        circuits
    }
}

/// Generates a dummy R1CS circuit.
#[inline]
pub fn dummy_circuit(cs: &mut R1CS<<Config as Pairing>::Scalar>) {
    let a = Fp(field_new!(Fr, "2")).as_known::<Secret, FpVar<_>>(cs);
    let b = Fp(field_new!(Fr, "3")).as_known::<Secret, FpVar<_>>(cs);
    let c = &a * &b;
    let d = Fp(field_new!(Fr, "6")).as_known::<Public, FpVar<_>>(cs);
    c.enforce_equal(&d)
        .expect("enforce_equal is not allowed to fail");
}

/// Displays whenever `result` is an `Err`-variant and formats the error.
#[inline]
pub fn display_on_error<T, E>(result: Result<T, E>)
where
    E: Display,
{
    if let Err(e) = result {
        println!("{} {e}", style("[ERROR]").bold().red());
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;

    /// Tests if register is visually correct.
    #[test]
    fn register_is_visually_correct() {
        register(
            "Mantalorian".to_string(),
            "mantalorian@manta.network".to_string(),
        );
    }
}
