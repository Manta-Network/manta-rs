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

//! Sender and Receiver Identities

use core::marker::PhantomData;
use manta_crypto::{
    accumulator::{Accumulator, MembershipProof, Verifier},
    commitment::{CommitmentScheme, Input as CommitmentInput},
    encryption::{EncryptedMessage, HybridPublicKeyEncryptionScheme},
    key::KeyAgreementScheme,
};

/// Key Table
pub trait KeyTable<K>
where
    K: KeyAgreementScheme,
{
    /// Query Type
    type Query;

    /// Returns the key associated to `query`, generating a new key if `query` does not already
    /// correspond to an existing key.
    fn get(&mut self, query: Self::Query) -> &K::SecretKey;
}

/// Spending Key
pub struct SpendingKey<K, T>
where
    K: KeyAgreementScheme,
    T: KeyTable<K>,
{
    /// Spending Key
    spending_key: K::SecretKey,

    /// Viewing Key Table
    viewing_key_table: T,
}

impl<K, T> SpendingKey<K, T>
where
    K: KeyAgreementScheme,
    T: KeyTable<K>,
{
    /// Builds a new [`SpendingKey`] from `spending_key` and `viewing_key_table`.
    #[inline]
    pub fn new(spending_key: K::SecretKey, viewing_key_table: T) -> Self {
        Self {
            spending_key,
            viewing_key_table,
        }
    }

    /// Returns the receiving key for `self` with the viewing key located at the given `query` in
    /// the viewing key table.
    #[inline]
    pub fn receiving_key(&mut self, query: T::Query) -> ReceivingKey<K> {
        ReceivingKey {
            spend: K::derive(&self.spending_key),
            view: K::derive(self.viewing_key_table.get(query)),
        }
    }

    /// Prepares `self` for spending `asset` with the given `ephemeral_key`.
    #[inline]
    pub fn pre_sender<C>(
        &self,
        ephemeral_key: PublicKey<C>,
        asset: C::Asset,
        commitment_scheme: &C::CommitmentScheme,
    ) -> PreSender<C>
    where
        K::SecretKey: Clone,
        C: Configuration<KeyAgreementScheme = K>,
    {
        PreSender::new(
            self.spending_key.clone(),
            ephemeral_key,
            asset,
            commitment_scheme,
        )
    }
}

/// Receiving Key
pub struct ReceivingKey<K>
where
    K: KeyAgreementScheme,
{
    /// Spend Part of the Receiving Key
    pub spend: K::PublicKey,

    /// View Part of the Receiving Key
    pub view: K::PublicKey,
}

impl<K> ReceivingKey<K>
where
    K: KeyAgreementScheme,
{
    /// Prepares `self` for receiving `asset` with the given `ephemeral_key`.
    #[inline]
    pub fn into_receiver<C>(
        self,
        ephemeral_key: SecretKey<C>,
        asset: C::Asset,
        commitment_scheme: &C::CommitmentScheme,
    ) -> FullReceiver<C>
    where
        C: Configuration<KeyAgreementScheme = K>,
    {
        FullReceiver::new(
            self.spend,
            self.view,
            ephemeral_key,
            asset,
            commitment_scheme,
        )
    }
}

/// Identity Configuration
pub trait Configuration {
    /// Asset Type
    type Asset;

    /// Key Agreement Scheme Type
    type KeyAgreementScheme: KeyAgreementScheme;

    /// Commitment Scheme Type
    type CommitmentScheme: CommitmentScheme<Randomness = Trapdoor<Self>>
        + CommitmentInput<Self::Asset>
        + CommitmentInput<SecretKey<Self>>;
}

/// Secret Key Type
pub type SecretKey<C> = <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::SecretKey;

/// Public Key Type
pub type PublicKey<C> = <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::PublicKey;

/// Trapdoor Type
pub type Trapdoor<C> =
    <<C as Configuration>::KeyAgreementScheme as KeyAgreementScheme>::SharedSecret;

/// Commitment Scheme Output Type
pub type CommitmentSchemeOutput<C> =
    <<C as Configuration>::CommitmentScheme as CommitmentScheme>::Output;

/// Unspent Transaction Output Type
pub type Utxo<C> = CommitmentSchemeOutput<C>;

/// Void Number Type
pub type VoidNumber<C> = CommitmentSchemeOutput<C>;

/// Pre-Sender
pub struct PreSender<C>
where
    C: Configuration,
{
    /// Secret Spending Key
    spending_key: SecretKey<C>,

    /// Ephemeral Public Key
    ephemeral_key: PublicKey<C>,

    /// Asset
    asset: C::Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C> PreSender<C>
where
    C: Configuration,
{
    /// Builds a new [`PreSender`] for `spending_key` to spend `asset` with
    /// `ephemeral_key`.
    #[inline]
    pub fn new(
        spending_key: SecretKey<C>,
        ephemeral_key: PublicKey<C>,
        asset: C::Asset,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Self {
        let trapdoor = C::KeyAgreementScheme::agree(&spending_key, &ephemeral_key);
        Self {
            utxo: commitment_scheme.commit_one(&asset, &trapdoor),
            void_number: commitment_scheme.commit_one(&spending_key, &trapdoor),
            spending_key,
            ephemeral_key,
            asset,
        }
    }

    /// Inserts the [`Utxo`] corresponding to `self` into the `utxo_set` with the intention of
    /// returning a proof later by a call to [`get_proof`](Self::get_proof).
    #[inline]
    pub fn insert_utxo<S>(&self, utxo_set: &mut S) -> bool
    where
        S: Accumulator<Item = Utxo<C>>,
    {
        utxo_set.insert(&self.utxo)
    }

    /// Requests the membership proof of the [`Utxo`] corresponding to `self` from `utxo_set` to
    /// prepare the conversion from `self` into a [`Sender`].
    #[inline]
    pub fn get_proof<S>(&self, utxo_set: &S) -> Option<SenderProof<C, S::Verifier>>
    where
        S: Accumulator<Item = Utxo<C>>,
    {
        Some(SenderProof {
            utxo_membership_proof: utxo_set.prove(&self.utxo)?,
            __: PhantomData,
        })
    }

    /// Converts `self` into a [`Sender`] by attaching `proof` to it.
    ///
    /// # Note
    ///
    /// When using this method, be sure to check that [`SenderProof::can_upgrade`] returns `true`.
    /// Otherwise, using the sender returned here will most likely return an error when posting to
    /// the ledger.
    #[inline]
    pub fn upgrade<V>(self, proof: SenderProof<C, V>) -> Sender<C, V>
    where
        V: Verifier<Item = Utxo<C>> + ?Sized,
    {
        Sender {
            spending_key: self.spending_key,
            ephemeral_key: self.ephemeral_key,
            asset: self.asset,
            utxo_membership_proof: proof.utxo_membership_proof,
            void_number: self.void_number,
        }
    }

    /// Tries to convert `self` into a [`Sender`] by getting a proof from `utxo_set`.
    #[inline]
    pub fn try_upgrade<S>(self, utxo_set: &S) -> Option<Sender<C, S::Verifier>>
    where
        S: Accumulator<Item = Utxo<C>>,
    {
        Some(self.get_proof(utxo_set)?.upgrade(self))
    }
}

/// Sender Proof
///
/// This `struct` is created by the [`get_proof`](PreSender::get_proof) method on [`PreSender`].
/// See its documentation for more.
pub struct SenderProof<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>> + ?Sized,
{
    /// UTXO Membership Proof
    utxo_membership_proof: MembershipProof<V>,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C, V> SenderProof<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>> + ?Sized,
{
    /// Returns `true` if a [`PreSender`] could be upgraded using `self` given the `utxo_set`.
    #[inline]
    pub fn can_upgrade<S>(&self, utxo_set: &S) -> bool
    where
        S: Accumulator<Item = V::Item, Verifier = V>,
    {
        self.utxo_membership_proof.matching_output(utxo_set)
    }

    /// Upgrades the `pre_sender` to a [`Sender`] by attaching `self` to it.
    ///
    /// # Note
    ///
    /// When using this method, be sure to check that [`can_upgrade`](Self::can_upgrade) returns
    /// `true`. Otherwise, using the sender returned here will most likely return an error when
    /// posting to the ledger.
    #[inline]
    pub fn upgrade(self, pre_sender: PreSender<C>) -> Sender<C, V> {
        pre_sender.upgrade(self)
    }
}

/// Sender
pub struct Sender<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>> + ?Sized,
{
    /// Secret Spend Key
    spending_key: SecretKey<C>,

    /// Ephemeral Public Key
    ephemeral_key: PublicKey<C>,

    /// Asset
    asset: C::Asset,

    /// UTXO Membership Proof
    utxo_membership_proof: MembershipProof<V>,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C, V> Sender<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
{
    /// Reverts `self` back into a [`PreSender`].
    ///
    /// This method should be called if the [`Utxo`] membership proof attached to `self` was deemed
    /// invalid or had expired.
    #[inline]
    pub fn downgrade(self, commitment_scheme: &C::CommitmentScheme) -> PreSender<C> {
        PreSender {
            utxo: commitment_scheme.commit_one(
                &self.asset,
                &C::KeyAgreementScheme::agree(&self.spending_key, &self.ephemeral_key),
            ),
            spending_key: self.spending_key,
            ephemeral_key: self.ephemeral_key,
            asset: self.asset,
            void_number: self.void_number,
        }
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post(self) -> SenderPost<C, V> {
        SenderPost {
            utxo_accumulator_output: self.utxo_membership_proof.into_output(),
            void_number: self.void_number,
        }
    }
}

/// Sender Ledger
pub trait SenderLedger<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
{
    /// Valid [`VoidNumber`] Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`VoidNumber`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`has_matching_utxo_accumulator_output`](Self::has_matching_utxo_accumulator_output).
    type ValidVoidNumber;

    /// Valid UTXO Accumulator Output Posting Key
    ///
    /// # Safety
    ///
    /// This type must be some wrapper around [`S::Output`] which can only be constructed by this
    /// implementation of [`SenderLedger`]. This is to prevent that [`spend`](Self::spend) is
    /// called before [`is_unspent`](Self::is_unspent) and
    /// [`has_matching_utxo_accumulator_output`](Self::has_matching_utxo_accumulator_output).
    ///
    /// [`S::Output`]: Verifier::Output
    type ValidUtxoAccumulatorOutput;

    /// Super Posting Key
    ///
    /// Type that allows super-traits of [`SenderLedger`] to customize posting key behavior.
    type SuperPostingKey: Copy;

    /// Checks if the ledger already contains the `void_number` in its set of void numbers.
    ///
    /// Existence of such a void number could indicate a possible double-spend.
    fn is_unspent(&self, void_number: VoidNumber<C>) -> Option<Self::ValidVoidNumber>;

    /// Checks if `output` matches the current accumulated value of the UTXO set that is stored on
    /// the ledger.
    ///
    /// Failure to match the ledger state means that the sender was constructed under an invalid or
    /// older state of the ledger.
    fn has_matching_utxo_accumulator_output(
        &self,
        output: V::Output,
    ) -> Option<Self::ValidUtxoAccumulatorOutput>;

    /// Posts the `void_number` to the ledger, spending the asset.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `void_number` is not already stored on
    /// the ledger. See [`is_unspent`](Self::is_unspent).
    fn spend(
        &mut self,
        utxo_accumulator_output: Self::ValidUtxoAccumulatorOutput,
        void_number: Self::ValidVoidNumber,
        super_key: &Self::SuperPostingKey,
    );
}

/// Sender Post Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SenderPostError {
    /// Asset Spent Error
    ///
    /// The asset has already been spent.
    AssetSpent,

    /// Invalid UTXO Accumulator Error
    ///
    /// The sender was not constructed under the current state of the UTXO set.
    InvalidUtxoAccumulator,
}

/// Sender Post
pub struct SenderPost<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
{
    /// UTXO Accumulator Output
    utxo_accumulator_output: V::Output,

    /// Void Number
    void_number: VoidNumber<C>,
}

impl<C, V> SenderPost<C, V>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
{
    /// Validates `self` on the sender `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<SenderPostingKey<C, V, L>, SenderPostError>
    where
        L: SenderLedger<C, V>,
    {
        Ok(SenderPostingKey {
            utxo_accumulator_output: ledger
                .has_matching_utxo_accumulator_output(self.utxo_accumulator_output)
                .ok_or(SenderPostError::InvalidUtxoAccumulator)?,
            void_number: ledger
                .is_unspent(self.void_number)
                .ok_or(SenderPostError::AssetSpent)?,
        })
    }
}

/// Sender Posting Key
pub struct SenderPostingKey<C, V, L>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
    L: SenderLedger<C, V>,
{
    /// UTXO Accumulator Output Posting Key
    utxo_accumulator_output: L::ValidUtxoAccumulatorOutput,

    /// Void Number Posting Key
    void_number: L::ValidVoidNumber,
}

impl<C, V, L> SenderPostingKey<C, V, L>
where
    C: Configuration,
    V: Verifier<Item = Utxo<C>>,
    L: SenderLedger<C, V>,
{
    /// Posts `self` to the sender `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) {
        ledger.spend(self.utxo_accumulator_output, self.void_number, super_key);
    }
}

/// Receiver
pub struct Receiver<C>
where
    C: Configuration,
{
    /// Public Spending Key
    spending_key: PublicKey<C>,

    /// Ephemeral Secret Key
    ephemeral_key: SecretKey<C>,

    /// Asset
    asset: C::Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,
}

impl<C> Receiver<C>
where
    C: Configuration,
{
    /// Generates the [`Utxo`] for a [`Receiver`] with the given parameters.
    #[inline]
    fn generate_utxo(
        spending_key: &PublicKey<C>,
        ephemeral_key: &SecretKey<C>,
        asset: &C::Asset,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Utxo<C> {
        commitment_scheme.commit_one(
            asset,
            &C::KeyAgreementScheme::agree(ephemeral_key, spending_key),
        )
    }
}

/// Full Receiver
pub struct FullReceiver<C>
where
    C: Configuration,
{
    /// Public Spending Key
    spending_key: PublicKey<C>,

    /// Public Viewing Key
    viewing_key: PublicKey<C>,

    /// Ephemeral Secret Key
    ephemeral_key: SecretKey<C>,

    /// Asset
    asset: C::Asset,

    /// Unspent Transaction Output
    utxo: Utxo<C>,
}

impl<C> FullReceiver<C>
where
    C: Configuration,
{
    /// Builds a new [`Receiver`] for `spending_key` to receive `asset` with
    /// `ephemeral_key`.
    #[inline]
    pub fn new(
        spending_key: PublicKey<C>,
        viewing_key: PublicKey<C>,
        ephemeral_key: SecretKey<C>,
        asset: C::Asset,
        commitment_scheme: &C::CommitmentScheme,
    ) -> Self {
        Self {
            utxo: Receiver::<C>::generate_utxo(
                &spending_key,
                &ephemeral_key,
                &asset,
                commitment_scheme,
            ),
            spending_key,
            viewing_key,
            ephemeral_key,
            asset,
        }
    }

    /// Extracts the ledger posting data from `self`.
    #[inline]
    pub fn into_post<H>(self) -> ReceiverPost<C, H>
    where
        H: HybridPublicKeyEncryptionScheme<
            Plaintext = C::Asset,
            KeyAgreementScheme = C::KeyAgreementScheme,
        >,
    {
        ReceiverPost {
            utxo: self.utxo,
            note: EncryptedMessage::new(&self.viewing_key, self.ephemeral_key, self.asset),
        }
    }
}

/// Receiver Ledger
pub trait ReceiverLedger<C, H>
where
    C: Configuration,
    H: HybridPublicKeyEncryptionScheme<
        Plaintext = C::Asset,
        KeyAgreementScheme = C::KeyAgreementScheme,
    >,
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

    /// Checks if the ledger already contains the `utxo` in its set of UTXOs.
    ///
    /// Existence of such a UTXO could indicate a possible double-spend.
    fn is_not_registered(&self, utxo: Utxo<C>) -> Option<Self::ValidUtxo>;

    /// Posts the `utxo` and `encrypted_asset` to the ledger, registering the asset.
    ///
    /// # Safety
    ///
    /// This method can only be called once we check that `utxo` is not already stored on the
    /// ledger. See [`is_not_registered`](Self::is_not_registered).
    fn register(
        &mut self,
        utxo: Self::ValidUtxo,
        note: EncryptedMessage<H>,
        super_key: &Self::SuperPostingKey,
    );
}

/// Receiver Post Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReceiverPostError {
    /// Asset Registered Error
    ///
    /// The asset has already been registered with the ledger.
    AssetRegistered,
}

/// Receiver Post
pub struct ReceiverPost<C, H>
where
    C: Configuration,
    H: HybridPublicKeyEncryptionScheme<
        Plaintext = C::Asset,
        KeyAgreementScheme = C::KeyAgreementScheme,
    >,
{
    /// Unspent Transaction Output
    utxo: Utxo<C>,

    /// Encrypted Note
    note: EncryptedMessage<H>,
}

impl<C, H> ReceiverPost<C, H>
where
    C: Configuration,
    H: HybridPublicKeyEncryptionScheme<
        Plaintext = C::Asset,
        KeyAgreementScheme = C::KeyAgreementScheme,
    >,
{
    /// Validates `self` on the receiver `ledger`.
    #[inline]
    pub fn validate<L>(self, ledger: &L) -> Result<ReceiverPostingKey<C, H, L>, ReceiverPostError>
    where
        L: ReceiverLedger<C, H>,
    {
        Ok(ReceiverPostingKey {
            utxo: ledger
                .is_not_registered(self.utxo)
                .ok_or(ReceiverPostError::AssetRegistered)?,
            note: self.note,
        })
    }
}

/// Receiver Posting Key
pub struct ReceiverPostingKey<C, H, L>
where
    C: Configuration,
    H: HybridPublicKeyEncryptionScheme<
        Plaintext = C::Asset,
        KeyAgreementScheme = C::KeyAgreementScheme,
    >,
    L: ReceiverLedger<C, H>,
{
    /// UTXO Posting Key
    utxo: L::ValidUtxo,

    /// Encrypted Note
    note: EncryptedMessage<H>,
}

impl<C, H, L> ReceiverPostingKey<C, H, L>
where
    C: Configuration,
    H: HybridPublicKeyEncryptionScheme<
        Plaintext = C::Asset,
        KeyAgreementScheme = C::KeyAgreementScheme,
    >,
    L: ReceiverLedger<C, H>,
{
    /// Posts `self` to the receiver `ledger`.
    #[inline]
    pub fn post(self, super_key: &L::SuperPostingKey, ledger: &mut L) {
        ledger.register(self.utxo, self.note, super_key);
    }
}

/// Constraint System Gadgets for Identities
pub mod constraint {
    use super::*;
    use manta_crypto::constraint::{ConstraintSystem, Equal};

    impl<C, V> Sender<C, V>
    where
        C: Configuration,
        V: Verifier<Item = Utxo<C>> + ?Sized,
    {
        /// Returns the asset for `self`, checking if `self` is well-formed in the given constraint
        /// system `cs`.
        #[inline]
        pub fn get_well_formed_asset<CS>(
            self,
            commitment_scheme: &C::CommitmentScheme,
            utxo_set_verifier: &V,
            cs: &mut CS,
        ) -> C::Asset
        where
            CS: ConstraintSystem,
            CommitmentSchemeOutput<C>: Equal<CS>,
            V: Verifier<Verification = CS::Bool>,
        {
            let trapdoor = C::KeyAgreementScheme::agree(&self.spending_key, &self.ephemeral_key);
            cs.assert(self.utxo_membership_proof.verify(
                &commitment_scheme.commit_one(&self.asset, &trapdoor),
                utxo_set_verifier,
            ));
            cs.assert_eq(
                &self.void_number,
                &commitment_scheme.commit_one(&self.spending_key, &trapdoor),
            );
            self.asset
        }
    }

    impl<C> Receiver<C>
    where
        C: Configuration,
    {
        /// Returns the asset for `self`, checking if `self` is well-formed in the given constraint
        /// system `cs`.
        #[inline]
        pub fn get_well_formed_asset<CS>(
            self,
            commitment_scheme: &C::CommitmentScheme,
            cs: &mut CS,
        ) -> C::Asset
        where
            CS: ConstraintSystem,
            Utxo<C>: Equal<CS>,
        {
            cs.assert_eq(
                &self.utxo,
                &Self::generate_utxo(
                    &self.spending_key,
                    &self.ephemeral_key,
                    &self.asset,
                    commitment_scheme,
                ),
            );
            self.asset
        }
    }
}
