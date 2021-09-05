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

// FIXME: ensure secret keys cannot be made public by some API call

use crate::{
    asset::Asset,
    ledger::{self, IntoPost, Ledger, Post},
};
use core::{convert::Infallible, fmt::Debug, hash::Hash, marker::PhantomData};
use manta_codec::{ScaleDecode, ScaleEncode};
use manta_crypto::{
    concatenate,
    ies::{self, EncryptedMessage},
    set::ContainmentProof,
    CommitmentScheme, ConcatBytes, IntegratedEncryptionScheme, PseudorandomFunctionFamily,
    VerifiedSet,
};
use rand::{
    distributions::{Distribution, Standard},
    CryptoRng, Rng, RngCore, SeedableRng,
};

pub(crate) mod prelude {
    #[doc(inline)]
    pub use crate::account::{
        Identity, IdentityConfiguration, Receiver, SecretKeyGeneratorError, Sender, SenderError,
        ShieldedIdentity, Spend, SpendError, Utxo, VoidNumber,
    };
}

/// Secret Key Generator Trait
pub trait SecretKeyGenerator<SecretKey> {
    /// Key Generation Error
    type Error;

    /// Generates a new secret key.
    fn generate_key(&mut self) -> Result<SecretKey, Self::Error>;
}

/// [`Identity`] Configuration Trait
pub trait IdentityConfiguration {
    /// Secret Key Type
    type SecretKey: Clone;

    /// Secret Key Generator Type
    type SecretKeyGenerator: SecretKeyGenerator<Self::SecretKey>;

    /// Pseudorandom Function Family Type
    type PseudorandomFunctionFamily: PseudorandomFunctionFamily<Seed = Self::SecretKey>;

    /// Commitment Scheme Type
    type CommitmentScheme: CommitmentScheme;

    /// Seedable Cryptographic Random Number Generator Type
    type Rng: CryptoRng + RngCore + SeedableRng<Seed = Self::SecretKey>;
}

/// [`SecretKeyGenerator::Error`] Type Alias
pub type SecretKeyGeneratorError<C> =
    <<C as IdentityConfiguration>::SecretKeyGenerator as SecretKeyGenerator<
        <C as IdentityConfiguration>::SecretKey,
    >>::Error;

/// [`PseudorandomFunctionFamily::Input`] Type Alias
pub type PseudorandomFunctionFamilyInput<C> =
    <<C as IdentityConfiguration>::PseudorandomFunctionFamily as PseudorandomFunctionFamily>::Input;

/// [`PseudorandomFunctionFamily::Output`] Type Alias
pub type PseudorandomFunctionFamilyOutput<C> =
	<<C as IdentityConfiguration>::PseudorandomFunctionFamily as PseudorandomFunctionFamily>::Output;

/// [`CommitmentScheme::Randomness`] Type Alias
pub type CommitmentSchemeRandomness<C> =
    <<C as IdentityConfiguration>::CommitmentScheme as CommitmentScheme>::Randomness;

/// [`CommitmentScheme::Output`] Type Alias
pub type CommitmentSchemeOutput<C> =
    <<C as IdentityConfiguration>::CommitmentScheme as CommitmentScheme>::Output;

/// Secret Key Type Alias
pub type SecretKey<C> = <C as IdentityConfiguration>::SecretKey;

/// Public Key Type Alias
pub type PublicKey<C> = PseudorandomFunctionFamilyOutput<C>;

/// Void Number Generator Type Alias
pub type VoidNumberGenerator<C> = PseudorandomFunctionFamilyInput<C>;

/// Void Number Type Alias
pub type VoidNumber<C> = PseudorandomFunctionFamilyOutput<C>;

/// Void Number Commitment Randomness Type Alias
pub type VoidNumberCommitmentRandomness<C> = CommitmentSchemeRandomness<C>;

/// Void Number Commitment Type Alias
pub type VoidNumberCommitment<C> = CommitmentSchemeOutput<C>;

/// UTXO Randomness Type Alias
pub type UtxoRandomness<C> = CommitmentSchemeRandomness<C>;

/// UTXO Type Alias
pub type Utxo<C> = CommitmentSchemeOutput<C>;

/// Generates a [`VoidNumberCommitment`] from a given `public_key`, `void_number_generator`, and
/// `void_number_commitment_randomness`.
#[inline]
pub fn generate_void_number_commitment<C>(
    commitment_scheme: &C::CommitmentScheme,
    public_key: &PublicKey<C>,
    void_number_generator: &VoidNumberGenerator<C>,
    void_number_commitment_randomness: &VoidNumberCommitmentRandomness<C>,
) -> VoidNumberCommitment<C>
where
    C: IdentityConfiguration,
    PublicKey<C>: ConcatBytes,
    VoidNumberGenerator<C>: ConcatBytes,
{
    commitment_scheme.commit(
        concatenate!(public_key, void_number_generator),
        void_number_commitment_randomness,
    )
}

/// Generates a [`Utxo`] from a given `asset`, `void_number_commitment`, and `utxo_randomness`.
#[inline]
pub fn generate_utxo<C>(
    commitment_scheme: &C::CommitmentScheme,
    asset: &Asset,
    void_number_commitment: &VoidNumberCommitment<C>,
    utxo_randomness: &UtxoRandomness<C>,
) -> Utxo<C>
where
    C: IdentityConfiguration,
    VoidNumberCommitment<C>: ConcatBytes,
{
    commitment_scheme.commit(concatenate!(asset, void_number_commitment), utxo_randomness)
}

/// Public Parameters for using an [`Asset`]
#[derive(derivative::Derivative, ScaleDecode, ScaleEncode)]
#[derivative(
    Clone(
        bound = "VoidNumberGenerator<C>: Clone, VoidNumberCommitmentRandomness<C>: Clone, UtxoRandomness<C>: Copy"
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
    C: IdentityConfiguration,
{
    /// Void Number Generation Parameter
    pub void_number_generator: VoidNumberGenerator<C>,

    /// Void Number Commitment Randomness
    pub void_number_commitment_randomness: VoidNumberCommitmentRandomness<C>,

    /// UTXO Randomness
    pub utxo_randomness: UtxoRandomness<C>,
}

impl<C> AssetParameters<C>
where
    C: IdentityConfiguration,
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
    ) -> VoidNumberCommitment<C>
    where
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
    {
        generate_void_number_commitment::<C>(
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
    ) -> Utxo<C>
    where
        VoidNumberCommitment<C>: ConcatBytes,
    {
        generate_utxo::<C>(
            commitment_scheme,
            asset,
            void_number_commitment,
            &self.utxo_randomness,
        )
    }
}

impl<C> Distribution<AssetParameters<C>> for Standard
where
    C: IdentityConfiguration,
    Standard: Distribution<VoidNumberGenerator<C>>
        + Distribution<VoidNumberCommitmentRandomness<C>>
        + Distribution<UtxoRandomness<C>>,
{
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> AssetParameters<C> {
        AssetParameters::new(rng.gen(), rng.gen(), rng.gen())
    }
}

/// Account Identity
pub struct Identity<C>
where
    C: IdentityConfiguration,
{
    /// Secret Key
    secret_key: C::SecretKey,
}

impl<C> Identity<C>
where
    C: IdentityConfiguration,
{
    /// Generates a new `Identity` from a `C::SecretKey`.
    ///
    /// # API Note
    ///
    /// This function is intentionally private so that secret keys are not part of the
    /// public interface.
    #[inline]
    fn new(secret_key: C::SecretKey) -> Self {
        Self { secret_key }
    }

    /// Generates a new [`Identity`] from a secret key generation source.
    #[inline]
    pub fn generate(
        source: &mut C::SecretKeyGenerator,
    ) -> Result<Self, SecretKeyGeneratorError<C>> {
        source.generate_key().map(Self::new)
    }

    /// Generates the associated `C::Rng` and a `AssetParameters<C>` for this identity.
    ///
    /// # API Note
    ///
    /// This function is intentionally private so that random number generators are not part of
    /// the public interface. See [`Self::parameters`] for access to the associated
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
        let parameters = rng.gen();
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

    /// Generates the associated `C::Rng`, `AssetParameters<C>`, and `ies::KeyPair<I>` for
    /// this identity.
    ///
    /// # API Note
    ///
    /// This function is intentionally private so that random number generators are not part of
    /// the public interface. See [`Self::parameters_and_asset_keypair`] for access to the
    /// associated `parameters` and `asset_keypair`.
    ///
    /// # Implementation Note
    ///
    /// See [`Self::rng_and_parameters`].
    #[inline]
    fn rng_and_parameters_and_asset_keypair<I>(
        &self,
    ) -> (C::Rng, AssetParameters<C>, ies::KeyPair<I>)
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        let (mut rng, parameters) = self.rng_and_parameters();
        let asset_keypair = I::keygen(&mut rng);
        (rng, parameters, asset_keypair)
    }

    /// Generates [`AssetParameters`] and a [`KeyPair`](ies::KeyPair) for assets that are used by
    /// this identity.
    #[inline]
    fn parameters_and_asset_keypair<I>(&self) -> (AssetParameters<C>, ies::KeyPair<I>)
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        let (_, parameters, asset_keypair) = self.rng_and_parameters_and_asset_keypair::<I>();
        (parameters, asset_keypair)
    }

    /// Generates a [`KeyPair`](ies::KeyPair) for assets that are used by this identity.
    #[inline]
    fn asset_keypair<I>(&self) -> ies::KeyPair<I>
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        let (_, asset_keypair) = self.parameters_and_asset_keypair::<I>();
        asset_keypair
    }

    /// Returns the public key associated with this identity.
    #[inline]
    pub(crate) fn public_key(&self) -> PublicKey<C> {
        C::PseudorandomFunctionFamily::evaluate_zero(&self.secret_key)
    }

    /// Generates a new void number using the `void_number_generator` parameter.
    #[inline]
    pub(crate) fn void_number(
        &self,
        void_number_generator: &VoidNumberGenerator<C>,
    ) -> VoidNumber<C> {
        C::PseudorandomFunctionFamily::evaluate(&self.secret_key, void_number_generator)
    }

    /// Generates a new void number commitment using the `void_number_generator` and
    /// `void_number_commitment_randomness`.
    #[inline]
    pub(crate) fn void_number_commitment(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        parameters: &AssetParameters<C>,
    ) -> VoidNumberCommitment<C>
    where
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
    {
        parameters.void_number_commitment(commitment_scheme, &self.public_key())
    }

    /// Generates a [`Utxo`] for an `asset` using the `parameters`.
    #[inline]
    pub(crate) fn utxo(
        &self,
        commitment_scheme: &C::CommitmentScheme,
        asset: &Asset,
        parameters: &AssetParameters<C>,
    ) -> Utxo<C>
    where
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
        VoidNumberCommitment<C>: ConcatBytes,
    {
        parameters.utxo(
            commitment_scheme,
            asset,
            &self.void_number_commitment(commitment_scheme, parameters),
        )
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
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
        VoidNumberCommitment<C>: ConcatBytes,
    {
        let parameters = self.parameters();
        let utxo = self.utxo(commitment_scheme, &asset, &parameters);
        let utxo_containment_proof = utxo_set.get_containment_proof(&utxo)?;
        Ok(Sender {
            asset,
            void_number: self.void_number(&parameters.void_number_generator),
            parameters,
            utxo,
            utxo_containment_proof,
            identity: self,
        })
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`Sender`] from it.
    #[inline]
    pub fn generate_sender<S>(
        source: &mut C::SecretKeyGenerator,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        utxo_set: &S,
    ) -> Result<Sender<C, S>, SenderError<C, S>>
    where
        S: VerifiedSet<Item = Utxo<C>>,
        Standard: Distribution<AssetParameters<C>>,
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
        VoidNumberCommitment<C>: ConcatBytes,
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
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
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
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
    {
        let (parameters, asset_keypair) = self.parameters_and_asset_keypair::<I>();
        self.build_shielded_identity(commitment_scheme, parameters, asset_keypair.into_public())
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`ShieldedIdentity`] from it.
    #[inline]
    pub fn generate_shielded<I>(
        source: &mut C::SecretKeyGenerator,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<ShieldedIdentity<C, I>, SecretKeyGeneratorError<C>>
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
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
        Spend {
            asset_secret_key: self.asset_keypair::<I>().into_secret(),
            identity: self,
        }
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`Spend`] from it.
    #[inline]
    pub fn generate_spend<I>(
        source: &mut C::SecretKeyGenerator,
    ) -> Result<Spend<C, I>, SecretKeyGeneratorError<C>>
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
    {
        Ok(Self::generate(source)?.into_spend())
    }

    /// Builds a new [`ShieldedIdentity`]-[`Spend`] pair.
    #[inline]
    pub fn into_receiver<I>(
        self,
        commitment_scheme: &C::CommitmentScheme,
    ) -> (ShieldedIdentity<C, I>, Spend<C, I>)
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
    {
        let (parameters, asset_keypair) = self.parameters_and_asset_keypair::<I>();
        let (asset_public_key, asset_secret_key) = asset_keypair.into();
        (
            self.build_shielded_identity(commitment_scheme, parameters, asset_public_key),
            Spend::new(self, asset_secret_key),
        )
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`ShieldedIdentity`]-[`Spend`] pair from it.
    #[inline]
    pub fn generate_receiver<I>(
        source: &mut C::SecretKeyGenerator,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<(ShieldedIdentity<C, I>, Spend<C, I>), SecretKeyGeneratorError<C>>
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
    {
        Ok(Self::generate(source)?.into_receiver(commitment_scheme))
    }
}

impl<C> Distribution<Identity<C>> for Standard
where
    C: IdentityConfiguration,
    Standard: Distribution<C::SecretKey>,
{
    #[inline]
    fn sample<R: RngCore + ?Sized>(&self, rng: &mut R) -> Identity<C> {
        Identity::new(rng.gen())
    }
}

/// Shielded Identity
pub struct ShieldedIdentity<C, I>
where
    C: IdentityConfiguration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// UTXO Randomness
    pub utxo_randomness: UtxoRandomness<C>,

    /// Void Number Commitment
    pub void_number_commitment: VoidNumberCommitment<C>,

    /// Encrypted [`Asset`] Public Key
    pub asset_public_key: ies::PublicKey<I>,
}

impl<C, I> ShieldedIdentity<C, I>
where
    C: IdentityConfiguration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Builds a new [`ShieldedIdentity`] from `identity` and `commitment_scheme`.
    #[inline]
    pub fn from_identity(identity: Identity<C>, commitment_scheme: &C::CommitmentScheme) -> Self
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
    {
        identity.into_shielded(commitment_scheme)
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a
    /// [`ShieldedIdentity`] from it.
    #[inline]
    pub fn generate(
        source: &mut C::SecretKeyGenerator,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Result<Self, SecretKeyGeneratorError<C>>
    where
        I: IntegratedEncryptionScheme<Plaintext = Asset>,
        Standard: Distribution<AssetParameters<C>>,
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
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
        VoidNumberCommitment<C>: ConcatBytes,
    {
        let Self {
            utxo_randomness,
            void_number_commitment,
            asset_public_key,
        } = self;
        Ok(Receiver {
            encrypted_asset: asset_public_key.encrypt(asset, rng)?,
            utxo: generate_utxo::<C>(
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

/// [`Spend`] Error
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "I::Error: Clone, S::ContainmentError: Clone"),
    Copy(bound = "I::Error: Copy, S::ContainmentError: Copy"),
    Debug(bound = "I::Error: Debug, S::ContainmentError: Debug"),
    Eq(bound = "I::Error: Eq, S::ContainmentError: Eq"),
    Hash(bound = "I::Error: Hash, S::ContainmentError: Hash"),
    PartialEq(bound = "I::Error: PartialEq, S::ContainmentError: PartialEq")
)]
pub enum SpendError<C, I, S>
where
    C: IdentityConfiguration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
    S: VerifiedSet<Item = Utxo<C>>,
{
    /// Encryption Error
    EncryptionError(I::Error),

    /// Missing UTXO Containment Proof
    MissingUtxo(S::ContainmentError),

    /// Parameter Marker
    #[doc(hidden)]
    __(Infallible, PhantomData<C>),
}

/// Spending Information
pub struct Spend<C, I>
where
    C: IdentityConfiguration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Spender Identity
    identity: Identity<C>,

    /// Encrypted [`Asset`] Secret Key
    asset_secret_key: ies::SecretKey<I>,
}

impl<C, I> Spend<C, I>
where
    C: IdentityConfiguration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Generates a new `Spend` from an `Identity` and an `ies::SecretKey<I>`.
    ///
    /// # API Note
    ///
    /// This function is intentionally private so that secret keys are not part of the
    /// public interface.
    #[inline]
    fn new(identity: Identity<C>, asset_secret_key: ies::SecretKey<I>) -> Self {
        Self {
            identity,
            asset_secret_key,
        }
    }

    /// Builds a new [`ShieldedIdentity`] from an `identity`.
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
    pub fn generate(source: &mut C::SecretKeyGenerator) -> Result<Self, SecretKeyGeneratorError<C>>
    where
        Standard: Distribution<AssetParameters<C>>,
    {
        Identity::generate_spend(source)
    }

    /// Builds a new [`Sender`] for the given `encrypted_asset`.
    #[inline]
    pub fn into_sender<S>(
        self,
        commitment_scheme: &C::CommitmentScheme,
        encrypted_asset: EncryptedMessage<I>,
        utxo_set: &S,
    ) -> Result<Sender<C, S>, SpendError<C, I, S>>
    where
        S: VerifiedSet<Item = Utxo<C>>,
        Standard: Distribution<AssetParameters<C>>,
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
        VoidNumberCommitment<C>: ConcatBytes,
    {
        self.identity
            .into_sender(
                commitment_scheme,
                self.asset_secret_key
                    .decrypt(encrypted_asset)
                    .map_err(SpendError::EncryptionError)?,
                utxo_set,
            )
            .map_err(SpendError::MissingUtxo)
    }
}

impl<C, I> From<Identity<C>> for Spend<C, I>
where
    C: IdentityConfiguration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
    Standard: Distribution<AssetParameters<C>>,
{
    #[inline]
    fn from(identity: Identity<C>) -> Self {
        Self::from_identity(identity)
    }
}

/// Sender Error
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "SecretKeyGeneratorError<C>: Clone, S::ContainmentError: Clone"),
    Copy(bound = "SecretKeyGeneratorError<C>: Copy, S::ContainmentError: Copy"),
    Debug(bound = "SecretKeyGeneratorError<C>: Debug, S::ContainmentError: Debug"),
    Eq(bound = "SecretKeyGeneratorError<C>: Eq, S::ContainmentError: Eq"),
    Hash(bound = "SecretKeyGeneratorError<C>: Hash, S::ContainmentError: Hash"),
    PartialEq(bound = "SecretKeyGeneratorError<C>: PartialEq, S::ContainmentError: PartialEq")
)]
pub enum SenderError<C, S>
where
    C: IdentityConfiguration,
    S: VerifiedSet<Item = Utxo<C>>,
{
    /// Secret Key Generator Error
    SecretKeyError(SecretKeyGeneratorError<C>),

    /// Containment Error
    MissingUtxo(S::ContainmentError),
}

/// Sender
pub struct Sender<C, S>
where
    C: IdentityConfiguration,
    S: VerifiedSet<Item = Utxo<C>>,
{
    /// Sender Identity
    pub(crate) identity: Identity<C>,

    /// Asset
    pub asset: Asset,

    /// Asset Parameters
    pub parameters: AssetParameters<C>,

    /// Void Number
    pub void_number: VoidNumber<C>,

    /// Unspent Transaction Output
    pub utxo: Utxo<C>,

    /// UTXO Containment Proof
    pub utxo_containment_proof: ContainmentProof<S>,
}

impl<C, S> Sender<C, S>
where
    C: IdentityConfiguration,
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
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
        VoidNumberCommitment<C>: ConcatBytes,
    {
        identity.into_sender(commitment_scheme, asset, utxo_set)
    }

    /// Generates a new [`Identity`] from a secret key generation source and builds a new
    /// [`Sender`] from it.
    #[inline]
    pub fn generate(
        source: &mut C::SecretKeyGenerator,
        commitment_scheme: &C::CommitmentScheme,
        asset: Asset,
        utxo_set: &S,
    ) -> Result<Self, SenderError<C, S>>
    where
        Standard: Distribution<AssetParameters<C>>,
        PublicKey<C>: ConcatBytes,
        VoidNumberGenerator<C>: ConcatBytes,
        VoidNumberCommitment<C>: ConcatBytes,
    {
        Identity::generate_sender(source, commitment_scheme, asset, utxo_set)
    }
}

impl<C, S, L> IntoPost<L> for Sender<C, S>
where
    C: IdentityConfiguration,
    S: VerifiedSet<Item = Utxo<C>>,
    L: Ledger<VoidNumber = VoidNumber<C>, UtxoSet = S> + ?Sized,
{
    type IntoPost = SenderPost<C, S>;

    #[inline]
    fn into_post(self) -> Self::IntoPost {
        Self::IntoPost {
            void_number: self.void_number,
            utxo_containment_proof_public_input: self.utxo_containment_proof.public_input,
        }
    }
}

/// Sender Post
pub struct SenderPost<C, S>
where
    C: IdentityConfiguration,
    S: VerifiedSet<Item = Utxo<C>>,
{
    /// Void Number
    pub void_number: VoidNumber<C>,

    /// UTXO Containment Proof Public Input
    pub utxo_containment_proof_public_input: S::Public,
}

impl<C, S, L> Post<L> for SenderPost<C, S>
where
    C: IdentityConfiguration,
    S: VerifiedSet<Item = Utxo<C>>,
    L: Ledger<VoidNumber = VoidNumber<C>, UtxoSet = S> + ?Sized,
{
    #[inline]
    fn post(self, ledger: &mut L) -> Result<(), ledger::Error<L>> {
        ledger::try_post_void_number(ledger, self.void_number)?;
        ledger::check_utxo_containment_proof_public_input(
            ledger,
            self.utxo_containment_proof_public_input,
        )?;
        Ok(())
    }
}

/// Receiver
pub struct Receiver<C, I>
where
    C: IdentityConfiguration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Asset
    pub asset: Asset,

    /// UTXO Randomness
    pub utxo_randomness: UtxoRandomness<C>,

    /// Void Number Commitment
    pub void_number_commitment: VoidNumberCommitment<C>,

    /// Unspent Transaction Output
    pub utxo: Utxo<C>,

    /// Encrypted [`Asset`]
    pub encrypted_asset: EncryptedMessage<I>,
}

impl<C, I> Receiver<C, I>
where
    C: IdentityConfiguration,
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
        VoidNumberCommitment<C>: ConcatBytes,
    {
        identity.into_receiver(commitment_scheme, asset, rng)
    }
}

impl<C, I, L> IntoPost<L> for ReceiverPost<C, I>
where
    C: IdentityConfiguration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
    L: Ledger<Utxo = Utxo<C>, EncryptedAsset = EncryptedMessage<I>> + ?Sized,
{
    type IntoPost = ReceiverPost<C, I>;

    #[inline]
    fn into_post(self) -> Self::IntoPost {
        Self::IntoPost {
            utxo: self.utxo,
            encrypted_asset: self.encrypted_asset,
        }
    }
}

/// Receiver Post
pub struct ReceiverPost<C, I>
where
    C: IdentityConfiguration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
{
    /// Unspent Transaction Output
    pub utxo: Utxo<C>,

    /// Encrypted [`Asset`]
    pub encrypted_asset: EncryptedMessage<I>,
}

impl<C, I, L> Post<L> for ReceiverPost<C, I>
where
    C: IdentityConfiguration,
    I: IntegratedEncryptionScheme<Plaintext = Asset>,
    L: Ledger<Utxo = Utxo<C>, EncryptedAsset = EncryptedMessage<I>> + ?Sized,
{
    #[inline]
    fn post(self, ledger: &mut L) -> Result<(), ledger::Error<L>> {
        ledger::try_post_utxo(ledger, self.utxo)?;
        ledger::try_post_encrypted_asset(ledger, self.encrypted_asset)?;
        Ok(())
    }
}
