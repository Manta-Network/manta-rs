// Copyright 2019-2021 Manta Network.
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

//! Identities, Senders, and Receivers

// FIXME: Check the secret key APIs.
// TODO:  Since `Configuration::SecretKey: Clone`, should `Identity: Clone`?

use crate::{
    asset::{Asset, AssetBalance, AssetId, AssetVar},
    keys::SecretKeyGenerator,
};
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use manta_crypto::{
    commitment::{CommitmentScheme, Input as CommitmentInput},
    ies::{self, EncryptedMessage, IntegratedEncryptionScheme},
    set::{ContainmentProof, VerifiedSet},
    PseudorandomFunctionFamily,
};
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, RngCore, SeedableRng,
};

pub(crate) mod prelude {
    #[doc(inline)]
    pub use super::{
        Identity, Receiver, Sender, SenderError, ShieldedIdentity, Spend, SpendError, Utxo,
        VoidNumber,
    };
}

/// [`Identity`] Configuration
pub trait Configuration {
    /// Secret Key Type
    type SecretKey: Clone;

    /// Pseudorandom Function Family Type
    type PseudorandomFunctionFamily: PseudorandomFunctionFamily<Seed = Self::SecretKey>;

    /// Commitment Scheme Type
    type CommitmentScheme: CommitmentScheme
        + CommitmentInput<PublicKey<Self>>
        + CommitmentInput<VoidNumberGenerator<Self>>
        + CommitmentInput<Asset>
        + CommitmentInput<VoidNumberCommitment<Self>>;

    /// Seedable Cryptographic Random Number Generator Type
    type Rng: CryptoRng + RngCore + SeedableRng<Seed = Self::SecretKey>;
}

/// [`PseudorandomFunctionFamily::Input`] Type
type PseudorandomFunctionFamilyInput<C> =
    <<C as Configuration>::PseudorandomFunctionFamily as PseudorandomFunctionFamily>::Input;

/// [`PseudorandomFunctionFamily::Output`] Type
type PseudorandomFunctionFamilyOutput<C> =
    <<C as Configuration>::PseudorandomFunctionFamily as PseudorandomFunctionFamily>::Output;

/// [`CommitmentScheme::Randomness`] Type
type CommitmentSchemeRandomness<C> =
    <<C as Configuration>::CommitmentScheme as CommitmentScheme>::Randomness;

/// [`CommitmentScheme::Output`] Type
type CommitmentSchemeOutput<C> =
    <<C as Configuration>::CommitmentScheme as CommitmentScheme>::Output;

/// Secret Key Type
pub type SecretKey<C> = <C as Configuration>::SecretKey;

/// Public Key Type
pub type PublicKey<C> = PseudorandomFunctionFamilyOutput<C>;

/// Void Number Generator Type
pub type VoidNumberGenerator<C> = PseudorandomFunctionFamilyInput<C>;

/// Void Number Type
pub type VoidNumber<C> = PseudorandomFunctionFamilyOutput<C>;

/// Void Number Commitment Randomness Type
pub type VoidNumberCommitmentRandomness<C> = CommitmentSchemeRandomness<C>;

/// Void Number Commitment Type
pub type VoidNumberCommitment<C> = CommitmentSchemeOutput<C>;

/// UTXO Randomness Type
pub type UtxoRandomness<C> = CommitmentSchemeRandomness<C>;

/// UTXO Type
pub type Utxo<C> = CommitmentSchemeOutput<C>;

/// Generates a void number commitment from `public_key`, `void_number_generator`, and
/// `void_number_commitment_randomness`.
#[inline]
pub fn generate_void_number_commitment<CS, PK, VNG>(
    commitment_scheme: &CS,
    public_key: &PK,
    void_number_generator: &VNG,
    void_number_commitment_randomness: &CS::Randomness,
) -> CS::Output
where
    CS: CommitmentScheme + CommitmentInput<PK> + CommitmentInput<VNG>,
{
    commitment_scheme
        .start()
        .update(public_key)
        .update(void_number_generator)
        .commit(void_number_commitment_randomness)
}

/// Generates a UTXO from `asset`, `void_number_commitment`, and `utxo_randomness`.
#[inline]
pub fn generate_utxo<CS, A, VNC>(
    commitment_scheme: &CS,
    asset: &A,
    void_number_commitment: &VNC,
    utxo_randomness: &CS::Randomness,
) -> CS::Output
where
    CS: CommitmentScheme + CommitmentInput<A> + CommitmentInput<VNC>,
{
    commitment_scheme
        .start()
        .update(asset)
        .update(void_number_commitment)
        .commit(utxo_randomness)
}

/// Public Parameters for using an [`Asset`]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(
        bound = "VoidNumberGenerator<C>: Clone, VoidNumberCommitmentRandomness<C>: Clone, UtxoRandomness<C>: Clone"
    ),
    Copy(
        bound = "VoidNumberGenerator<C>: Copy, VoidNumberCommitmentRandomness<C>: Copy, UtxoRandomness<C>: Copy"
    ),
    Debug(
        bound = "VoidNumberGenerator<C>: Debug, VoidNumberCommitmentRandomness<C>: Debug, UtxoRandomness<C>: Debug"
    ),
    Default(
        bound = "VoidNumberGenerator<C>: Default, VoidNumberCommitmentRandomness<C>: Default, UtxoRandomness<C>: Default"
    ),
    Eq(
        bound = "VoidNumberGenerator<C>: Eq, VoidNumberCommitmentRandomness<C>: Eq, UtxoRandomness<C>: Eq"
    ),
    Hash(
        bound = "VoidNumberGenerator<C>: Hash, VoidNumberCommitmentRandomness<C>: Hash, UtxoRandomness<C>: Hash"
    ),
    PartialEq(
        bound = "VoidNumberGenerator<C>: PartialEq, VoidNumberCommitmentRandomness<C>: PartialEq, UtxoRandomness<C>: PartialEq"
    )
)]
pub struct AssetParameters<C>
where
    C: Configuration,
{
    /// Void Number Generator
    pub void_number_generator: VoidNumberGenerator<C>,

    /// Void Number Commitment Randomness
    pub void_number_commitment_randomness: VoidNumberCommitmentRandomness<C>,

    /// UTXO Randomness
    pub utxo_randomness: UtxoRandomness<C>,
}

impl<C> AssetParameters<C>
where
    C: Configuration,
{
    /// Builds a new [`AssetParameters`].
    #[inline]
    pub fn new(
        void_number_generator: VoidNumberGenerator<C>,
        void_number_commitment_randomness: VoidNumberCommitmentRandomness<C>,
        utxo_randomness: UtxoRandomness<C>,
    ) -> Self {
        Self {
            void_number_generator,
            void_number_commitment_randomness,
            utxo_randomness,
        }
    }

    /// Generates a new void number commitment using `public_key`.
    #[inline]
    pub fn void_number_commitment(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        public_key: &PublicKey<C>,
    ) -> VoidNumberCommitment<C> {
        generate_void_number_commitment(
            commitment_scheme,
            public_key,
            &self.void_number_generator,
            &self.void_number_commitment_randomness,
        )
    }

    /// Generates a [`Utxo`] from a given `asset` and `void_number_commitment`.
    #[inline]
    pub fn utxo(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        asset: &Asset,
        void_number_commitment: &VoidNumberCommitment<C>,
    ) -> Utxo<C> {
        generate_utxo(
            commitment_scheme,
            asset,
            void_number_commitment,
            &self.utxo_randomness,
        )
    }
}

impl<C> Distribution<AssetParameters<C>> for Standard
where
    C: Configuration,
    Standard: Distribution<VoidNumberGenerator<C>>
        + Distribution<VoidNumberCommitmentRandomness<C>>
        + Distribution<UtxoRandomness<C>>,
{
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> AssetParameters<C> {
        AssetParameters::new(self.sample(rng), self.sample(rng), self.sample(rng))
    }
}

/// Account Identity
pub struct Identity<C>
where
    C: Configuration,
{
    /// Secret Key
    secret_key: SecretKey<C>,
}

impl<C> Identity<C>
where
    C: Configuration,
{
    /// Builds a new [`Identity`] from a [`SecretKey`].
    #[inline]
    pub fn new(secret_key: SecretKey<C>) -> Self {
        Self { secret_key }
    }

    /// Generates a new [`Identity`] from a secret key generation source.
    #[inline]
    pub fn generate<G>(source: &mut G) -> Result<Self, G::Error>
    where
        G: SecretKeyGenerator<SecretKey = SecretKey<C>>,
    {
        source.generate_key().map(Self::new)
    }

    /// Generates the associated `C::Rng` and a `AssetParameters<C>` for this identity.
    ///
    /// # API Note
    ///
    /// This function is intentionally private so that internal random number generator is
    /// not part of the public interface. See [`Self::parameters`] for access to the associated
    /// `parameters`.
    ///
    /// # Implementation Note
    ///
    /// Contributors should always use this function when generating an `rng` or a
    /// `parameters` in the folowing ways:
    ///
    /// ```text
    /// 1. [BOTH] let (mut rng, parameters) = self.rng_and_parameters();
    /// 2. [RNG]  let (mut rng, _) = self.rng_and_parameters();
    /// 2. [PAIR] let parameters = self.parameters();
    /// ```
    ///
    /// This is important because we need to preserve the order in which objects are randomly
    /// generated across different functions. The `parameters` is always generated immediately
    /// after creation of the random number generator.
    #[inline]
    fn rng_and_parameters(&self) -> (C::Rng, AssetParameters<C>)
    where
        Standard: Distribution<AssetParameters<C>>,
    {
        let mut rng = C::Rng::from_seed(self.secret_key.clone());
        let parameters = Standard.sample(&mut rng);
        (rng, parameters)
    }

    /// Generates [`AssetParameters`] for assets that are used by this identity.
    #[inline]
    fn parameters(&self) -> AssetParameters<C>
    where
        Standard: Distribution<AssetParameters<C>>,
    {
        let (_, parameters) = self.rng_and_parameters();
        parameters
    }

    /// Generates the associated [`AssetParameters`] and asset [`KeyPair`](ies::KeyPair) for
    /// this identity.
    #[inline]
    fn parameters_and_asset_keypair<I>(&self) -> (AssetParameters<C>, ies::KeyPair<I>)
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        let (mut rng, parameters) = self.rng_and_parameters();
        (parameters, I::generate_keys(&mut rng))
    }

    /// Generates the associated [`AssetParameters`] and asset [`PublicKey`](ies::PublicKey) for
    /// this identity.
    #[inline]
    fn parameters_and_asset_public_key<I>(&self) -> (AssetParameters<C>, ies::PublicKey<I>)
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        let (mut rng, parameters) = self.rng_and_parameters();
        (parameters, I::generate_public_key(&mut rng))
    }

    /// Generates the associated [`AssetParameters`] and asset [`SecretKey`](ies::SecretKey) for
    /// this identity.
    #[inline]
    fn parameters_and_asset_secret_key<I>(&self) -> (AssetParameters<C>, ies::SecretKey<I>)
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        let (mut rng, parameters) = self.rng_and_parameters();
        (parameters, I::generate_secret_key(&mut rng))
    }

    /// Returns the public key associated with this identity.
    #[inline]
    fn public_key(&self) -> PublicKey<C> {
        C::PseudorandomFunctionFamily::evaluate_zero(&self.secret_key)
    }

    /// Generates a new void number using the `void_number_generator` parameter.
    #[inline]
    fn void_number(&self, void_number_generator: &VoidNumberGenerator<C>) -> VoidNumber<C> {
        C::PseudorandomFunctionFamily::evaluate(&self.secret_key, void_number_generator)
    }

    /// Generates a new void number commitment using the `void_number_generator` and
    /// `void_number_commitment_randomness`.
    #[inline]
    fn void_number_commitment(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        parameters: &AssetParameters<C>,
    ) -> VoidNumberCommitment<C> {
        parameters.void_number_commitment(commitment_scheme, &self.public_key())
    }

    /// Returns the [`PublicKey`], [`VoidNumberCommitment`], and [`Utxo`] for this identity.
    #[inline]
    fn construct_utxo(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        asset: &Asset,
        parameters: &AssetParameters<C>,
    ) -> (PublicKey<C>, VoidNumberCommitment<C>, Utxo<C>) {
        let public_key = self.public_key();
        let void_number_commitment =
            parameters.void_number_commitment(commitment_scheme, &public_key);
        let utxo = parameters.utxo(commitment_scheme, asset, &void_number_commitment);
        (public_key, void_number_commitment, utxo)
    }

    /// Builds a new [`Sender`] for the given `asset`.
    #[inline]
    pub fn into_sender<S>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        utxo_set: &S,
    ) -> Result<Sender<C, S>, S::ContainmentError>
    where
        S: VerifiedSet<Item = Utxo<C>>,
        Standard: Distribution<AssetParameters<C>>,
    {
        // TODO: Generate pre-sender data structure in case the `utxo_set` is behind the
        //       current ledger state and we need to have everything ready for the `utxo_set`.
        //
        //   > pub struct PreSender<C> {
        //         secret_key,
        //         public_key,
        //         asset,
        //         parameters,
        //         void_number_commitment,
        //         void_number,
        //         utxo
        //     }
        //
        let parameters = self.parameters();
        let (public_key, void_number_commitment, utxo) =
            self.construct_utxo(commitment_scheme, &asset, &parameters);
        Ok(Sender {
            utxo_containment_proof: utxo_set.get_containment_proof(&utxo)?,
            void_number: self.void_number(&parameters.void_number_generator),
            secret_key: self.secret_key,
            public_key,
            asset,
            parameters,
            void_number_commitment,
            utxo,
        })
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`Sender`] from it.
    #[inline]
    pub fn generate_sender<G, S>(
        source: &mut G,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        utxo_set: &S,
    ) -> Result<Sender<C, S>, SenderError<G, S>>
    where
        G: SecretKeyGenerator<SecretKey = SecretKey<C>>,
        S: VerifiedSet<Item = Utxo<C>>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Self::generate(source)
            .map_err(SenderError::SecretKeyError)?
            .into_sender(commitment_scheme, asset, utxo_set)
            .map_err(SenderError::MissingUtxo)
    }

    /// Builds a new [`ShieldedIdentity`] from `commitment_scheme`, `parameters`, and
    /// `asset_keypair`.
    #[inline]
    fn build_shielded_identity<I>(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        parameters: AssetParameters<C>,
        asset_public_key: ies::PublicKey<I>,
    ) -> ShieldedIdentity<C, I>
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        ShieldedIdentity {
            void_number_commitment: self.void_number_commitment(commitment_scheme, &parameters),
            utxo_randomness: parameters.utxo_randomness,
            asset_public_key,
        }
    }

    /// Builds a new [`ShieldedIdentity`] from this identity.
    #[inline]
    pub fn into_shielded<I>(self, commitment_scheme: &C::CommitmentScheme) -> ShieldedIdentity<C, I>
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        let (parameters, asset_public_key) = self.parameters_and_asset_public_key();
        self.build_shielded_identity(commitment_scheme, parameters, asset_public_key)
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`ShieldedIdentity`] from it.
    #[inline]
    pub fn generate_shielded<G, I>(
        source: &mut G,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<ShieldedIdentity<C, I>, G::Error>
    where
        G: SecretKeyGenerator<SecretKey = SecretKey<C>>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(Self::generate(source)?.into_shielded(commitment_scheme))
    }

    /// Builds a new [`Spend`].
    #[inline]
    pub fn into_spend<I>(self) -> Spend<C, I>
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        let (_, asset_secret_key) = self.parameters_and_asset_secret_key();
        Spend::new(self, asset_secret_key)
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`Spend`] from it.
    #[inline]
    pub fn generate_spend<G, I>(source: &mut G) -> Result<Spend<C, I>, G::Error>
    where
        G: SecretKeyGenerator<SecretKey = SecretKey<C>>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(Self::generate(source)?.into_spend())
    }

    /// Tries to open an `encrypted_asset`, returning an [`OpenSpend`] if successful.
    #[inline]
    pub fn try_open<I>(
        self,
        encrypted_asset: &EncryptedMessage<I>,
    ) -> Result<OpenSpend<C>, I::Error>
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.into_spend().try_open(encrypted_asset)
    }

    /// Builds a new [`ExternalReceiver`].
    #[inline]
    pub fn into_external_receiver<I>(
        self,
        commitment_scheme: &C::CommitmentScheme,
    ) -> ExternalReceiver<C, I>
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        let (parameters, asset_keypair) = self.parameters_and_asset_keypair();
        let (asset_public_key, asset_secret_key) = asset_keypair.into();
        ExternalReceiver {
            shielded_identity: self.build_shielded_identity(
                commitment_scheme,
                parameters,
                asset_public_key,
            ),
            spend: Spend::new(self, asset_secret_key),
        }
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`ExternalReceiver`] from it.
    #[inline]
    pub fn generate_external_receiver<G, I>(
        source: &mut G,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<ExternalReceiver<C, I>, G::Error>
    where
        G: SecretKeyGenerator<SecretKey = SecretKey<C>>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(Self::generate(source)?.into_external_receiver(commitment_scheme))
    }

    /// Builds a new [`InternalReceiver`].
    #[inline]
    pub fn into_internal_receiver<I, R>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<InternalReceiver<C, I>, I::Error>
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        let (parameters, asset_public_key) = self.parameters_and_asset_public_key();
        Ok(InternalReceiver {
            receiver: self
                .build_shielded_identity(commitment_scheme, parameters, asset_public_key)
                .into_receiver(commitment_scheme, asset, rng)?,
            open_spend: OpenSpend::new(self, asset),
        })
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`InternalReceiver`] from it.
    #[inline]
    pub fn generate_internal_receiver<G, I, R>(
        source: &mut G,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<InternalReceiver<C, I>, InternalReceiverError<G, I>>
    where
        G: SecretKeyGenerator<SecretKey = SecretKey<C>>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        Self::generate(source)
            .map_err(InternalReceiverError::SecretKeyError)?
            .into_internal_receiver(commitment_scheme, asset, rng)
            .map_err(InternalReceiverError::EncryptionError)
    }
}

impl<C> Distribution<Identity<C>> for Standard
where
    C: Configuration,
    Standard: Distribution<SecretKey<C>>,
{
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> Identity<C> {
        Identity::new(self.sample(rng))
    }
}

/// Shielded Identity
pub struct ShieldedIdentity<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// UTXO Randomness
    utxo_randomness: UtxoRandomness<C>,

    /// Void Number Commitment
    void_number_commitment: VoidNumberCommitment<C>,

    /// Encrypted [`Asset`] Public Key
    asset_public_key: ies::PublicKey<I>,
}

impl<C, I> ShieldedIdentity<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Builds a new [`ShieldedIdentity`] from `identity` and `commitment_scheme`.
    #[inline]
    pub fn from_identity(identity: Identity<C>, commitment_scheme: &C::CommitmentScheme) -> Self
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        identity.into_shielded(commitment_scheme)
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a
    /// [`ShieldedIdentity`] from it.
    #[inline]
    pub fn generate<G>(
        source: &mut G,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<Self, G::Error>
    where
        G: SecretKeyGenerator<SecretKey = SecretKey<C>>,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Identity::generate_shielded(source, commitment_scheme)
    }

    /// Generates a [`Receiver`] from a [`ShieldedIdentity`].
    #[inline]
    pub fn into_receiver<R>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<Receiver<C, I>, I::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let Self {
            utxo_randomness,
            void_number_commitment,
            asset_public_key,
        } = self;
        Ok(Receiver {
            encrypted_asset: asset_public_key.encrypt(&asset, rng)?,
            utxo: generate_utxo(
                commitment_scheme,
                &asset,
                &void_number_commitment,
                &utxo_randomness,
            ),
            asset,
            utxo_randomness,
            void_number_commitment,
        })
    }
}

/// Spend Error
///
/// This `enum` is the error state for the [`into_sender`] method on [`Spend`].
/// See its documentation for more.
///
/// [`into_sender`]: Spend::into_sender
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "I::Error: Clone, S::ContainmentError: Clone"),
    Copy(bound = "I::Error: Copy, S::ContainmentError: Copy"),
    Debug(bound = "I::Error: Debug, S::ContainmentError: Debug"),
    Eq(bound = "I::Error: Eq, S::ContainmentError: Eq"),
    Hash(bound = "I::Error: Hash, S::ContainmentError: Hash"),
    PartialEq(bound = "I::Error: PartialEq, S::ContainmentError: PartialEq")
)]
pub enum SpendError<I, S>
where
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
    S: VerifiedSet,
{
    /// Encryption Error
    EncryptionError(I::Error),

    /// Missing UTXO Containment Proof
    MissingUtxo(S::ContainmentError),
}

/// Spending Information
pub struct Spend<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Spender Identity
    identity: Identity<C>,

    /// Encrypted [`Asset`] Secret Key
    asset_secret_key: ies::SecretKey<I>,
}

impl<C, I> Spend<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Builds a new `Spend` from an `Identity` and an `ies::SecretKey<I>`.
    ///
    /// # API Note
    ///
    /// This function is intentionally private so that `identity` and `asset_secret_key` are
    /// not part of the public interface.
    #[inline]
    fn new(identity: Identity<C>, asset_secret_key: ies::SecretKey<I>) -> Self {
        Self {
            identity,
            asset_secret_key,
        }
    }

    /// Builds a new [`Spend`] from an `identity`.
    #[inline]
    pub fn from_identity(identity: Identity<C>) -> Self
    where
        Standard: Distribution<AssetParameters<C>>,
    {
        identity.into_spend()
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a
    /// [`Spend`] from it.
    #[inline]
    pub fn generate<G>(source: &mut G) -> Result<Self, G::Error>
    where
        G: SecretKeyGenerator<SecretKey = SecretKey<C>>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Identity::generate_spend(source)
    }

    /// Tries to open an `encrypted_asset`, returning an [`OpenSpend`] if successful.
    #[inline]
    pub fn try_open(self, encrypted_asset: &EncryptedMessage<I>) -> Result<OpenSpend<C>, I::Error> {
        Ok(OpenSpend::new(
            self.identity,
            self.asset_secret_key.decrypt(encrypted_asset)?,
        ))
    }

    /// Builds a new [`Sender`] for the given `encrypted_asset`.
    #[inline]
    pub fn into_sender<S>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        encrypted_asset: EncryptedMessage<I>,
        utxo_set: &S,
    ) -> Result<Sender<C, S>, SpendError<I, S>>
    where
        S: VerifiedSet<Item = Utxo<C>>,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.try_open(&encrypted_asset)
            .map_err(SpendError::EncryptionError)?
            .into_sender(commitment_scheme, utxo_set)
            .map_err(SpendError::MissingUtxo)
    }
}

impl<C, I> From<Identity<C>> for Spend<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
    Standard: Distribution<AssetParameters<C>>,
{
    #[inline]
    fn from(identity: Identity<C>) -> Self {
        Self::from_identity(identity)
    }
}

/// External Receiver
pub struct ExternalReceiver<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Shielded Identity
    pub shielded_identity: ShieldedIdentity<C, I>,

    /// Spend
    pub spend: Spend<C, I>,
}

impl<C, I> ExternalReceiver<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`ExternalReceiver`] from it.
    #[inline]
    pub fn generate<G>(
        source: &mut G,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<Self, G::Error>
    where
        G: SecretKeyGenerator<SecretKey = SecretKey<C>>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Identity::generate_external_receiver(source, commitment_scheme)
    }
}

impl<C, I> From<ExternalReceiver<C, I>> for (ShieldedIdentity<C, I>, Spend<C, I>)
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    #[inline]
    fn from(external: ExternalReceiver<C, I>) -> Self {
        (external.shielded_identity, external.spend)
    }
}

/// Open [`Spend`]
pub struct OpenSpend<C>
where
    C: Configuration,
{
    /// Spender Identity
    identity: Identity<C>,

    /// Unencrypted [`Asset`]
    asset: Asset,
}

impl<C> OpenSpend<C>
where
    C: Configuration,
{
    /// Builds a new `OpenSpend` from an `Identity` and an `Asset`.
    ///
    /// # API Note
    ///
    /// This function is intentionally private so that `identity` and `asset` are
    /// not part of the public interface.
    #[inline]
    fn new(identity: Identity<C>, asset: Asset) -> Self {
        Self { identity, asset }
    }

    /// Builds a new [`Sender`] for `self`.
    #[inline]
    pub fn into_sender<S>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        utxo_set: &S,
    ) -> Result<Sender<C, S>, S::ContainmentError>
    where
        S: VerifiedSet<Item = Utxo<C>>,
        Standard: Distribution<AssetParameters<C>>,
    {
        self.identity
            .into_sender(commitment_scheme, self.asset, utxo_set)
    }
}

/// Internal Receiver Error
///
/// This `enum` is the error state for the [`generate`] method on [`InternalReceiver`].
/// See its documentation for more.
///
/// [`generate`]: InternalReceiver::generate
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "G::Error: Clone, I::Error: Clone"),
    Copy(bound = "G::Error: Copy, I::Error: Copy"),
    Debug(bound = "G::Error: Debug, I::Error: Debug"),
    Eq(bound = "G::Error: Eq, I::Error: Eq"),
    Hash(bound = "G::Error: Hash, I::Error: Hash"),
    PartialEq(bound = "G::Error: PartialEq, I::Error: PartialEq")
)]
pub enum InternalReceiverError<G, I>
where
    G: SecretKeyGenerator,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Secret Key Generator Error
    SecretKeyError(G::Error),

    /// Encryption Error
    EncryptionError(I::Error),
}

/// Internal Receiver
pub struct InternalReceiver<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Receiver
    pub receiver: Receiver<C, I>,

    /// Open Spend
    pub open_spend: OpenSpend<C>,
}

impl<C, I> InternalReceiver<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`InternalReceiver`] from it.
    #[inline]
    pub fn generate<G, R>(
        source: &mut G,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<Self, InternalReceiverError<G, I>>
    where
        G: SecretKeyGenerator<SecretKey = SecretKey<C>>,
        R: CryptoRng + RngCore + ?Sized,
        Standard: Distribution<AssetParameters<C>>,
    {
        Identity::generate_internal_receiver(source, commitment_scheme, asset, rng)
    }
}

impl<C, I> From<InternalReceiver<C, I>> for (Receiver<C, I>, OpenSpend<C>)
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    #[inline]
    fn from(internal: InternalReceiver<C, I>) -> Self {
        (internal.receiver, internal.open_spend)
    }
}

/// Sender Error
///
/// This `enum` is the error state for the [`generate`] method on [`Sender`].
/// See its documentation for more.
///
/// [`generate`]: Sender::generate
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "G::Error: Clone, S::ContainmentError: Clone"),
    Copy(bound = "G::Error: Copy, S::ContainmentError: Copy"),
    Debug(bound = "G::Error: Debug, S::ContainmentError: Debug"),
    Eq(bound = "G::Error: Eq, S::ContainmentError: Eq"),
    Hash(bound = "G::Error: Hash, S::ContainmentError: Hash"),
    PartialEq(bound = "G::Error: PartialEq, S::ContainmentError: PartialEq")
)]
pub enum SenderError<G, S>
where
    G: SecretKeyGenerator,
    S: VerifiedSet,
{
    /// Secret Key Generator Error
    SecretKeyError(G::Error),

    /// Containment Error
    MissingUtxo(S::ContainmentError),
}

/// Sender
pub struct Sender<C, S>
where
    C: Configuration,
    S: VerifiedSet<Item = Utxo<C>>,
{
    /// Secret Key
    secret_key: SecretKey<C>,

    /// Public Key
    public_key: PublicKey<C>,

    /// Asset
    asset: Asset,

    /// Asset Parameters
    parameters: AssetParameters<C>,

    /// Void Number
    void_number: VoidNumber<C>,

    /// Void Number Commitment
    void_number_commitment: VoidNumberCommitment<C>,

    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// UTXO Containment Proof
    utxo_containment_proof: ContainmentProof<S>,
}

impl<C, S> Sender<C, S>
where
    C: Configuration,
    S: VerifiedSet<Item = Utxo<C>>,
{
    /// Builds a new [`Sender`] for this `asset` from an `identity`.
    #[inline]
    pub fn from_identity(
        identity: Identity<C>,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        utxo_set: &S,
    ) -> Result<Self, S::ContainmentError>
    where
        Standard: Distribution<AssetParameters<C>>,
    {
        identity.into_sender(commitment_scheme, asset, utxo_set)
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`Sender`] from it.
    #[inline]
    pub fn generate<G>(
        source: &mut G,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        utxo_set: &S,
    ) -> Result<Self, SenderError<G, S>>
    where
        G: SecretKeyGenerator<SecretKey = SecretKey<C>>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Identity::generate_sender(source, commitment_scheme, asset, utxo_set)
    }

    /// Returns the asset id for this sender.
    #[inline]
    pub(crate) fn asset_id(&self) -> AssetId {
        self.asset.id
    }

    /// Returns the asset value for this sender.
    #[inline]
    pub(crate) fn asset_value(&self) -> AssetBalance {
        self.asset.value
    }

    /// Extracts ledger posting data for this sender.
    #[inline]
    pub fn into_post(self) -> SenderPost<C, S> {
        SenderPost {
            void_number: self.void_number,
            utxo_containment_proof_public_input: self.utxo_containment_proof.into_public_input(),
        }
    }
}

/// Sender Ledger
pub trait SenderLedger<C, S>
where
    C: Configuration,
    S: VerifiedSet<Item = Utxo<C>>,
{
    /// Valid [`VoidNumber`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`VoidNumber`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`is_valid_utxo_state`](Self::is_valid_utxo_state).
    type ValidVoidNumber;

    /// Valid Utxo State Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`S::Public`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`is_valid_utxo_state`](Self::is_valid_utxo_state).
    ///
    /// [`S::Public`]: VerifiedSet::Public
    type ValidUtxoState;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`SenderLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Ledger Error
    type Error;

    /// Checks if the ledger already contains the `void_number` in its set of void numbers.
    ///
    /// Existence of such a void number could indicate a possible double-spend.
    fn is_unspent(
        &self,
        void_number: VoidNumber<C>,
    ) -> Result<Option<Self::ValidVoidNumber>, Self::Error>;

    /// Checks if the `public_input` is up-to-date with the current state of the UTXO set that is
    /// stored on the ledger.
    ///
    /// Failure to match the ledger state means that the sender was constructed under an invalid or
    /// older state of the ledger.
    fn is_valid_utxo_state(
        &self,
        public_input: S::Public,
    ) -> Result<Option<Self::ValidUtxoState>, Self::Error>;

    /// Posts the `void_number` to the ledger, spending the asset.
    ///
    /// # Safety
    ///
    /// This function can only be called once we check that `void_number` is not already stored
    /// on the ledger. See [`is_unspent`](Self::is_unspent).
    fn spend(
        &mut self,
        void_number: Self::ValidVoidNumber,
        utxo_state: Self::ValidUtxoState,
        super_key: &Self::SuperPostingKey,
    ) -> Result<(), Self::Error>;
}

/// Sender Post Error
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "L::Error: Clone"),
    Copy(bound = "L::Error: Copy"),
    Debug(bound = "L::Error: Debug"),
    Eq(bound = "L::Error: Eq"),
    Hash(bound = "L::Error: Hash"),
    PartialEq(bound = "L::Error: PartialEq")
)]
pub enum SenderPostError<C, S, L>
where
    C: Configuration,
    S: VerifiedSet<Item = Utxo<C>>,
    L: SenderLedger<C, S>,
{
    /// Asset Spent Error
    ///
    /// The asset has already been spent.
    AssetSpent,

    /// Invalid UTXO State Error
    ///
    /// The sender was not constructed under the current state of the UTXO set.
    InvalidUtxoState,

    /// Ledger Error
    LedgerError(L::Error),
}

/// Sender Post
pub struct SenderPost<C, S>
where
    C: Configuration,
    S: VerifiedSet<Item = Utxo<C>>,
{
    /// Void Number
    void_number: VoidNumber<C>,

    /// UTXO Containment Proof Public Input
    utxo_containment_proof_public_input: S::Public,
}

impl<C, S> SenderPost<C, S>
where
    C: Configuration,
    S: VerifiedSet<Item = Utxo<C>>,
{
    /// Validates `self` on the sender `ledger`.
    #[inline]
    pub fn validate<L>(
        self,
        ledger: &L,
    ) -> Result<SenderPostingKey<C, S, L>, SenderPostError<C, S, L>>
    where
        L: SenderLedger<C, S>,
    {
        Ok(SenderPostingKey {
            void_number: match ledger
                .is_unspent(self.void_number)
                .map_err(SenderPostError::LedgerError)?
            {
                Some(key) => key,
                _ => return Err(SenderPostError::AssetSpent),
            },
            utxo_containment_proof_public_input: match ledger
                .is_valid_utxo_state(self.utxo_containment_proof_public_input)
                .map_err(SenderPostError::LedgerError)?
            {
                Some(key) => key,
                _ => return Err(SenderPostError::InvalidUtxoState),
            },
        })
    }
}

impl<C, S> From<Sender<C, S>> for SenderPost<C, S>
where
    C: Configuration,
    S: VerifiedSet<Item = Utxo<C>>,
{
    #[inline]
    fn from(sender: Sender<C, S>) -> Self {
        sender.into_post()
    }
}

/// Sender Posting Key
pub struct SenderPostingKey<C, S, L>
where
    C: Configuration,
    S: VerifiedSet<Item = Utxo<C>>,
    L: SenderLedger<C, S>,
{
    /// Void Number Posting Key
    void_number: L::ValidVoidNumber,

    /// UTXO Containment Proof Public Input Posting Key
    utxo_containment_proof_public_input: L::ValidUtxoState,
}

impl<C, S, L> SenderPostingKey<C, S, L>
where
    C: Configuration,
    S: VerifiedSet<Item = Utxo<C>>,
    L: SenderLedger<C, S>,
{
    /// Posts `self` to the sender `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) -> Result<(), L::Error> {
        ledger.spend(
            self.void_number,
            self.utxo_containment_proof_public_input,
            super_key,
        )
    }
}

/// Receiver
pub struct Receiver<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Asset
    asset: Asset,

    /// UTXO Randomness
    utxo_randomness: UtxoRandomness<C>,

    /// Void Number Commitment
    void_number_commitment: VoidNumberCommitment<C>,

    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// Encrypted [`Asset`]
    encrypted_asset: EncryptedMessage<I>,
}

impl<C, I> Receiver<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Build a [`Receiver`] from a [`ShieldedIdentity`] for the `asset`.
    #[inline]
    pub fn from_shielded<R>(
        identity: ShieldedIdentity<C, I>,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        rng: &mut R,
    ) -> Result<Self, I::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        identity.into_receiver(commitment_scheme, asset, rng)
    }

    /// Returns the asset id for this receiver.
    #[inline]
    pub(crate) fn asset_id(&self) -> AssetId {
        self.asset.id
    }

    /// Returns the asset value for this receiver.
    #[inline]
    pub(crate) fn asset_value(&self) -> AssetBalance {
        self.asset.value
    }

    /// Extracts ledger posting data for this receiver.
    #[inline]
    pub fn into_post(self) -> ReceiverPost<C, I> {
        ReceiverPost {
            utxo: self.utxo,
            encrypted_asset: self.encrypted_asset,
        }
    }
}

/// Receiver Ledger
pub trait ReceiverLedger<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Valid [`Utxo`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`Utxo`] which can only be constructed by this
    /// implementation of [`ReceiverLedger`]. This is to prevent that [`register`](Self::register)
    /// is called before [`is_not_registered`](Self::is_not_registered).
    type ValidUtxo;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`ReceiverLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Ledger Error
    type Error;

    /// Checks if the ledger already contains the `utxo` in its set of UTXOs.
    ///
    /// Existence of such a UTXO could indicate a possible double-spend.
    fn is_not_registered(&self, utxo: Utxo<C>) -> Result<Option<Self::ValidUtxo>, Self::Error>;

    /// Posts the `utxo` and `encrypted_asset` to the ledger, registering the asset.
    ///
    /// # Safety
    ///
    /// This function can only be called once we check that `utxo` is not already stored
    /// on the ledger. See [`is_not_registered`](Self::is_not_registered).
    fn register(
        &mut self,
        utxo: Self::ValidUtxo,
        encrypted_asset: EncryptedMessage<I>,
        super_key: &Self::SuperPostingKey,
    ) -> Result<(), Self::Error>;
}

/// Receiver Post Error
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "L::Error: Clone"),
    Copy(bound = "L::Error: Copy"),
    Debug(bound = "L::Error: Debug"),
    Eq(bound = "L::Error: Eq"),
    Hash(bound = "L::Error: Hash"),
    PartialEq(bound = "L::Error: PartialEq")
)]
pub enum ReceiverPostError<C, I, L>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
    L: ReceiverLedger<C, I>,
{
    /// Asset Registered Error
    ///
    /// The asset has already been registered with the ledger.
    AssetRegistered,

    /// Ledger Error
    LedgerError(L::Error),
}

/// Receiver Post
pub struct ReceiverPost<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// Encrypted [`Asset`]
    encrypted_asset: EncryptedMessage<I>,
}

impl<C, I> ReceiverPost<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Validates `self` on the receiver `ledger`.
    #[inline]
    pub fn validate<L>(
        self,
        ledger: &L,
    ) -> Result<ReceiverPostingKey<C, I, L>, ReceiverPostError<C, I, L>>
    where
        L: ReceiverLedger<C, I>,
    {
        Ok(ReceiverPostingKey {
            utxo: match ledger
                .is_not_registered(self.utxo)
                .map_err(ReceiverPostError::LedgerError)?
            {
                Some(key) => key,
                _ => return Err(ReceiverPostError::AssetRegistered),
            },
            encrypted_asset: self.encrypted_asset,
        })
    }
}

impl<C, I> From<Receiver<C, I>> for ReceiverPost<C, I>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    #[inline]
    fn from(receiver: Receiver<C, I>) -> Self {
        receiver.into_post()
    }
}

/// Receiver Posting Key
pub struct ReceiverPostingKey<C, I, L>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
    L: ReceiverLedger<C, I>,
{
    /// Utxo Posting Key
    utxo: L::ValidUtxo,

    /// Encrypted Asset
    encrypted_asset: EncryptedMessage<I>,
}

impl<C, I, L> ReceiverPostingKey<C, I, L>
where
    C: Configuration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
    L: ReceiverLedger<C, I>,
{
    /// Posts `self` to the receiver `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) -> Result<(), L::Error> {
        ledger.register(self.utxo, self.encrypted_asset, super_key)
    }
}

/// Constraint System Gadgets for Identities
pub mod constraint {
    use super::*;
    use manta_crypto::{
        constraint::{
            reflection::{HasAllocation, HasVariable, Var},
            Allocation, Constant, ConstraintSystem, Derived, Equal, Public, PublicOrSecret, Secret,
            Variable,
        },
        set::constraint::{ContainmentProofVar, VerifiedSetVariable},
    };

    /// [`Identity`] Constraint System Configuration
    pub trait Configuration: super::Configuration {
        /// Constraint System
        type ConstraintSystem: ConstraintSystem
            + HasVariable<AssetId, Mode = PublicOrSecret>
            + HasVariable<AssetBalance, Mode = PublicOrSecret>;

        /// Secret Key Variable
        type SecretKeyVar: Variable<Self::ConstraintSystem, Type = Self::SecretKey, Mode = Secret>;

        /// Pseudorandom Function Family Input Variable
        type PseudorandomFunctionFamilyInputVar: Variable<
            Self::ConstraintSystem,
            Type = <Self::PseudorandomFunctionFamily as PseudorandomFunctionFamily>::Input,
            Mode = Secret,
        >;

        /// Pseudorandom Function Family Output Variable
        type PseudorandomFunctionFamilyOutputVar: Variable<
                Self::ConstraintSystem,
                Type = <Self::PseudorandomFunctionFamily as PseudorandomFunctionFamily>::Output,
                Mode = PublicOrSecret,
            > + Equal<Self::ConstraintSystem>;

        /// Pseudorandom Function Family Variable
        type PseudorandomFunctionFamilyVar: PseudorandomFunctionFamily<
                Seed = Self::SecretKeyVar,
                Input = Self::PseudorandomFunctionFamilyInputVar,
                Output = Self::PseudorandomFunctionFamilyOutputVar,
            > + Variable<
                Self::ConstraintSystem,
                Type = Self::PseudorandomFunctionFamily,
                Mode = Constant,
            >;

        /// Commitment Scheme Randomness Variable
        type CommitmentSchemeRandomnessVar: Variable<
            Self::ConstraintSystem,
            Type = <Self::CommitmentScheme as CommitmentScheme>::Randomness,
            Mode = Secret,
        >;

        /// Commitment Scheme Output Variable
        type CommitmentSchemeOutputVar: Variable<
                Self::ConstraintSystem,
                Type = <Self::CommitmentScheme as CommitmentScheme>::Output,
                Mode = PublicOrSecret,
            > + Equal<Self::ConstraintSystem>;

        /// Commitment Scheme Variable
        type CommitmentSchemeVar: CommitmentScheme<
                Randomness = Self::CommitmentSchemeRandomnessVar,
                Output = Self::CommitmentSchemeOutputVar,
            > + CommitmentInput<PublicKeyVar<Self>>
            + CommitmentInput<VoidNumberGeneratorVar<Self>>
            + CommitmentInput<AssetVar<Self::ConstraintSystem>>
            + CommitmentInput<VoidNumberCommitmentVar<Self>>
            + Variable<Self::ConstraintSystem, Type = Self::CommitmentScheme, Mode = Constant>;
    }

    /// [`PseudorandomFunctionFamily::Input`] Variable Type
    type PseudorandomFunctionFamilyInputVar<C> =
        <C as Configuration>::PseudorandomFunctionFamilyInputVar;

    /// [`PseudorandomFunctionFamily::Output`] Variable Type
    type PseudorandomFunctionFamilyOutputVar<C> =
        <C as Configuration>::PseudorandomFunctionFamilyOutputVar;

    /// [`CommitmentScheme::Randomness`] Variable Type
    type CommitmentSchemeRandomnessVar<C> = <C as Configuration>::CommitmentSchemeRandomnessVar;

    /// [`CommitmentScheme::Output`] Variable Type
    type CommitmentSchemeOutputVar<C> = <C as Configuration>::CommitmentSchemeOutputVar;

    /// Secret Key Variable Type
    pub type SecretKeyVar<C> = <C as Configuration>::SecretKeyVar;

    /// Public Key Variable Type
    pub type PublicKeyVar<C> = PseudorandomFunctionFamilyOutputVar<C>;

    /// Void Number Generator Variable Type
    pub type VoidNumberGeneratorVar<C> = PseudorandomFunctionFamilyInputVar<C>;

    /// Void Number Variable Type
    pub type VoidNumberVar<C> = PseudorandomFunctionFamilyOutputVar<C>;

    ///  Void Number Commitment Randomness Variable Type
    pub type VoidNumberCommitmentRandomnessVar<C> = CommitmentSchemeRandomnessVar<C>;

    /// Void Number Commitment Variable Type
    pub type VoidNumberCommitmentVar<C> = CommitmentSchemeOutputVar<C>;

    /// UTXO Randomness Variable Type
    pub type UtxoRandomnessVar<C> = CommitmentSchemeRandomnessVar<C>;

    /// UTXO Variable Type
    pub type UtxoVar<C> = CommitmentSchemeOutputVar<C>;

    /// UTXO Containment Proof Variable Type
    pub type UtxoContainmentProofVar<C, S> =
        ContainmentProofVar<S, <C as Configuration>::ConstraintSystem>;

    /// Asset Parameters Variable
    pub struct AssetParametersVar<C>
    where
        C: Configuration,
    {
        /// Void Number Generator
        pub void_number_generator: VoidNumberGeneratorVar<C>,

        /// Void Number Commitment Randomness
        pub void_number_commitment_randomness: VoidNumberCommitmentRandomnessVar<C>,

        /// UTXO Randomness
        pub utxo_randomness: UtxoRandomnessVar<C>,
    }

    impl<C> AssetParametersVar<C>
    where
        C: Configuration,
    {
        /// Builds a new [`AssetParametersVar`] from parameter variables.
        #[inline]
        pub fn new(
            void_number_generator: VoidNumberGeneratorVar<C>,
            void_number_commitment_randomness: VoidNumberCommitmentRandomnessVar<C>,
            utxo_randomness: UtxoRandomnessVar<C>,
        ) -> Self {
            Self {
                void_number_generator,
                void_number_commitment_randomness,
                utxo_randomness,
            }
        }
    }

    impl<C> Variable<C::ConstraintSystem> for AssetParametersVar<C>
    where
        C: Configuration,
    {
        type Type = AssetParameters<C>;

        type Mode = Secret;

        #[inline]
        fn new(
            cs: &mut C::ConstraintSystem,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            match allocation {
                Allocation::Known(this, mode) => Self::new(
                    VoidNumberGeneratorVar::<C>::new_known(cs, &this.void_number_generator, mode),
                    VoidNumberCommitmentRandomnessVar::<C>::new_known(
                        cs,
                        &this.void_number_commitment_randomness,
                        mode,
                    ),
                    UtxoRandomnessVar::<C>::new_known(cs, &this.utxo_randomness, mode),
                ),
                Allocation::Unknown(mode) => Self::new(
                    VoidNumberGeneratorVar::<C>::new_unknown(cs, mode),
                    VoidNumberCommitmentRandomnessVar::<C>::new_unknown(cs, mode),
                    UtxoRandomnessVar::<C>::new_unknown(cs, mode),
                ),
            }
        }
    }

    impl<C> HasAllocation<C::ConstraintSystem> for AssetParameters<C>
    where
        C: Configuration,
    {
        type Variable = AssetParametersVar<C>;
        type Mode = Secret;
    }

    /// Sender Variable
    pub struct SenderVar<C, S>
    where
        C: Configuration,
        S: VerifiedSet<Item = Utxo<C>>,
        C::ConstraintSystem: HasVariable<S::Public> + HasVariable<S::Secret>,
    {
        /// Secret Key
        secret_key: SecretKeyVar<C>,

        /// Public Key
        public_key: PublicKeyVar<C>,

        /// Asset
        asset: AssetVar<C::ConstraintSystem>,

        /// Asset Parameters
        parameters: AssetParametersVar<C>,

        /// Void Number
        void_number: VoidNumberVar<C>,

        /// Void Number Commitment
        void_number_commitment: VoidNumberCommitmentVar<C>,

        /// Unspent Transaction Output
        utxo: UtxoVar<C>,

        /// UTXO Containment Proof
        utxo_containment_proof: UtxoContainmentProofVar<C, S>,
    }

    impl<C, S> SenderVar<C, S>
    where
        C: Configuration,
        S: VerifiedSet<Item = Utxo<C>>,
        C::ConstraintSystem: HasVariable<S::Public> + HasVariable<S::Secret>,
    {
        /// Checks if `self` is a well-formed sender and returns its asset.
        #[inline]
        pub fn get_well_formed_asset(
            self,
            cs: &mut C::ConstraintSystem,
            commitment_scheme: &C::CommitmentSchemeVar,
            utxo_set: &Var<S, C::ConstraintSystem>,
        ) -> AssetVar<C::ConstraintSystem>
        where
            S: HasAllocation<C::ConstraintSystem>,
            S::Variable: VerifiedSetVariable<C::ConstraintSystem, ItemVar = UtxoVar<C>>,
        {
            // Well-formed check:
            //
            // 1. pk = PRF(sk, 0)                  [public: (),     secret: (pk, sk)]
            // 2. vn = PRF(sk, rho)                [public: (vn),   secret: (sk, rho)]
            // 3. k = COM(pk || rho, r)            [public: (k),    secret: (pk, rho, r)]
            // 4. cm = COM(asset || k, s)          [public: (),     secret: (cm, asset, k, s)]
            // 5. is_path(cm, path, root) == true  [public: (root), secret: (cm, path)]
            //
            // FIXME: should `k` be private or not?

            // 1. Check public key:
            // ```
            // pk = PRF(sk, 0)
            // ```
            // where public: {}, secret: {pk, sk}.
            cs.assert_eq(
                &self.public_key,
                &C::PseudorandomFunctionFamilyVar::evaluate_zero(&self.secret_key),
            );

            // 2. Check void number:
            // ```
            // vn = PRF(sk, rho)
            // ```
            // where public: {vn}, secret: {sk, rho}.
            cs.assert_eq(
                &self.void_number,
                &C::PseudorandomFunctionFamilyVar::evaluate(
                    &self.secret_key,
                    &self.parameters.void_number_generator,
                ),
            );

            // 3. Check void number commitment:
            // ```
            // k = COM(pk || rho, r)
            // ```
            // where public: {k}, secret: {pk, rho, r}.
            cs.assert_eq(
                &self.void_number_commitment,
                &generate_void_number_commitment(
                    commitment_scheme,
                    &self.public_key,
                    &self.parameters.void_number_generator,
                    &self.parameters.void_number_commitment_randomness,
                ),
            );

            // 4. Check UTXO:
            // ```
            // cm = COM(asset || k, s)
            // ```
            // where public: {}, secret: {cm, asset, k, s}.
            cs.assert_eq(
                &self.utxo,
                &generate_utxo(
                    commitment_scheme,
                    &self.asset,
                    &self.void_number_commitment,
                    &self.parameters.utxo_randomness,
                ),
            );

            // 5. Check UTXO containment proof:
            // ```
            // is_path(cm, path, root) == true
            // ```
            // where public: {root}, secret: {cm, path}.
            self.utxo_containment_proof
                .assert_validity(utxo_set, &self.utxo, cs);

            self.asset
        }
    }

    impl<C, S> Variable<C::ConstraintSystem> for SenderVar<C, S>
    where
        C: Configuration,
        S: VerifiedSet<Item = Utxo<C>>,
        C::ConstraintSystem:
            HasVariable<S::Public, Mode = Public> + HasVariable<S::Secret, Mode = Secret>,
    {
        type Type = Sender<C, S>;

        type Mode = Derived;

        #[inline]
        fn new(
            cs: &mut C::ConstraintSystem,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            match allocation {
                Allocation::Known(this, mode) => Self {
                    secret_key: SecretKeyVar::<C>::new_known(cs, &this.secret_key, mode),
                    public_key: PublicKeyVar::<C>::new_known(cs, &this.public_key, Secret),
                    asset: this.asset.known(cs, mode),
                    parameters: this.parameters.known(cs, mode),
                    void_number: VoidNumberVar::<C>::new_known(cs, &this.void_number, Public),
                    void_number_commitment: VoidNumberCommitmentVar::<C>::new_known(
                        cs,
                        &this.void_number_commitment,
                        Public,
                    ),
                    utxo: UtxoVar::<C>::new_known(cs, &this.utxo, Secret),
                    utxo_containment_proof: this.utxo_containment_proof.known(cs, mode),
                },
                Allocation::Unknown(mode) => Self {
                    secret_key: SecretKeyVar::<C>::new_unknown(cs, mode),
                    public_key: PublicKeyVar::<C>::new_unknown(cs, Secret),
                    asset: Asset::unknown(cs, mode),
                    parameters: AssetParameters::unknown(cs, mode),
                    void_number: VoidNumberVar::<C>::new_unknown(cs, Public),
                    void_number_commitment: VoidNumberCommitmentVar::<C>::new_unknown(cs, Public),
                    utxo: UtxoVar::<C>::new_unknown(cs, Secret),
                    utxo_containment_proof: ContainmentProof::<S>::unknown(cs, mode),
                },
            }
        }
    }

    impl<C, S> HasAllocation<C::ConstraintSystem> for Sender<C, S>
    where
        C: Configuration,
        S: VerifiedSet<Item = Utxo<C>>,
        C::ConstraintSystem:
            HasVariable<S::Public, Mode = Public> + HasVariable<S::Secret, Mode = Secret>,
    {
        type Variable = SenderVar<C, S>;
        type Mode = Derived;
    }

    /// Receiver Variable
    pub struct ReceiverVar<C, I>
    where
        C: Configuration,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
    {
        /// Asset
        asset: AssetVar<C::ConstraintSystem>,

        /// UTXO Randomness
        utxo_randomness: UtxoRandomnessVar<C>,

        /// Void Number Commitment
        void_number_commitment: VoidNumberCommitmentVar<C>,

        /// Unspent Transaction Output
        utxo: UtxoVar<C>,

        /// Type Parameter Marker
        __: PhantomData<I>,
    }

    impl<C, I> ReceiverVar<C, I>
    where
        C: Configuration,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
    {
        /// Checks if `self` is a well-formed receiver and returns its asset.
        ///
        /// This [`ReceiverVar`] is well-formed whenever:
        /// ```text
        /// utxo = COM(asset || k, s)
        /// ```
        /// where `k` is `self.void_number_commitment` and `s` is `self.utxo_randomness`. In this
        /// equation we have `{ utxo } : Public`, `{ asset, k, s } : Secret`.
        #[inline]
        pub fn get_well_formed_asset(
            self,
            cs: &mut C::ConstraintSystem,
            commitment_scheme: &C::CommitmentSchemeVar,
        ) -> AssetVar<C::ConstraintSystem> {
            cs.assert_eq(
                &self.utxo,
                &generate_utxo(
                    commitment_scheme,
                    &self.asset,
                    &self.void_number_commitment,
                    &self.utxo_randomness,
                ),
            );
            self.asset
        }
    }

    impl<C, I> Variable<C::ConstraintSystem> for ReceiverVar<C, I>
    where
        C: Configuration,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
    {
        type Type = Receiver<C, I>;

        type Mode = Derived;

        #[inline]
        fn new(
            cs: &mut C::ConstraintSystem,
            allocation: Allocation<Self::Type, Self::Mode>,
        ) -> Self {
            match allocation {
                Allocation::Known(this, mode) => Self {
                    asset: AssetVar::new_known(cs, &this.asset, mode),
                    utxo_randomness: UtxoRandomnessVar::<C>::new_known(
                        cs,
                        &this.utxo_randomness,
                        mode,
                    ),
                    void_number_commitment: VoidNumberCommitmentVar::<C>::new_known(
                        cs,
                        &this.void_number_commitment,
                        Secret,
                    ),
                    utxo: UtxoVar::<C>::new_known(cs, &this.utxo, Public),
                    __: PhantomData,
                },
                Allocation::Unknown(mode) => Self {
                    asset: AssetVar::new_unknown(cs, mode),
                    utxo_randomness: UtxoRandomnessVar::<C>::new_unknown(cs, mode),
                    void_number_commitment: VoidNumberCommitmentVar::<C>::new_unknown(cs, Secret),
                    utxo: UtxoVar::<C>::new_unknown(cs, Public),
                    __: PhantomData,
                },
            }
        }
    }

    impl<C, I> HasAllocation<C::ConstraintSystem> for Receiver<C, I>
    where
        C: Configuration,
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
    {
        type Variable = ReceiverVar<C, I>;
        type Mode = Derived;
    }
}
