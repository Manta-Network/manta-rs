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

//! Hierarchical Key Derivation Schemes

use alloc::{vec, vec::Vec};
use core::{
    fmt::{self, Debug},
    hash::Hash,
    marker::PhantomData,
};
use manta_crypto::{
    key::KeyDerivationFunction,
    rand::{CryptoRng, RngCore, Sample},
};

/// Hierarchical Key Derivation Parameter Type
pub type IndexType = u32;

/// Hierarchical Key Derivation Parameter
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HierarchicalKeyDerivationParameter<M> {
    /// Index
    index: IndexType,

    /// Type Parameter Marker
    __: PhantomData<M>,
}

impl<M> HierarchicalKeyDerivationParameter<M> {
    /// Builds a new [`HierarchicalKeyDerivationParameter`] from `index`.
    #[inline]
    fn new(index: IndexType) -> Self {
        Self {
            index,
            __: PhantomData,
        }
    }

    /// Resets the index of `self` to zero.
    #[inline]
    fn reset(&mut self) {
        self.index = 0;
    }

    /// Increments the index of `self` by one unit.
    #[inline]
    fn increment(&mut self) {
        self.index += 1;
    }

    /// Returns the index of `self`.
    #[inline]
    pub fn index(&self) -> IndexType {
        self.index
    }
}

/// Implements the [`HierarchicalKeyDerivationParameter`] subtype for `$kind` and `$index`.
macro_rules! impl_index_kind {
    ($doc:expr, $fmt:expr, $kind:ident, $index:ident) => {
        #[doc = $doc]
        #[doc = "Kind"]
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $kind;

        #[doc = $doc]
        pub type $index = HierarchicalKeyDerivationParameter<$kind>;

        impl Debug for $index {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_tuple($fmt).field(&self.index).finish()
            }
        }
    };
}

impl_index_kind!("Account Index", "AccountIndex", AccountKind, AccountIndex);
impl_index_kind!("Spend Index", "SpendIndex", SpendKind, SpendIndex);
impl_index_kind!("View Index", "ViewIndex", ViewKind, ViewIndex);

/// Hierarchical Key Derivation Scheme
pub trait HierarchicalKeyDerivationScheme {
    /// Secret Key Type
    type SecretKey;

    /// Key Derivation Error Type
    type Error;

    /// Derives a secret key for `account` with `spend` and optional `view`.
    fn derive(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
        view: Option<ViewIndex>,
    ) -> Result<Self::SecretKey, Self::Error>;

    /// Derives a spend secret key for `account` using the `spend` index.
    #[inline]
    fn derive_spend(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
    ) -> Result<Self::SecretKey, Self::Error> {
        self.derive(account, spend, None)
    }

    /// Derives a view secret key for `account` using the `spend` and `view` indices.
    #[inline]
    fn derive_view(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
        view: ViewIndex,
    ) -> Result<Self::SecretKey, Self::Error> {
        self.derive(account, spend, Some(view))
    }

    /// Derives a spend-view pair of secret keys for `account` using the `spend` and `view` indices.
    #[inline]
    fn derive_pair(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
        view: ViewIndex,
    ) -> Result<SecretKeyPair<Self>, Self::Error> {
        Ok(SecretKeyPair::new(
            self.derive_spend(account, spend)?,
            self.derive_view(account, spend, view)?,
        ))
    }

    /// Maps `self` along a key derivation function.
    #[inline]
    fn map<K>(self) -> Map<Self, K>
    where
        Self: Sized,
        K: KeyDerivationFunction<Key = Self::SecretKey>,
    {
        Map::new(self)
    }
}

impl<H> HierarchicalKeyDerivationScheme for &H
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    type SecretKey = H::SecretKey;
    type Error = H::Error;

    #[inline]
    fn derive(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
        view: Option<ViewIndex>,
    ) -> Result<Self::SecretKey, Self::Error> {
        (*self).derive(account, spend, view)
    }

    #[inline]
    fn derive_spend(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
    ) -> Result<Self::SecretKey, Self::Error> {
        (*self).derive_spend(account, spend)
    }

    #[inline]
    fn derive_view(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
        view: ViewIndex,
    ) -> Result<Self::SecretKey, Self::Error> {
        (*self).derive_view(account, spend, view)
    }
}

/// Mapping Hierarchical Key Derivation Scheme
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Map<H, K>
where
    H: HierarchicalKeyDerivationScheme,
    K: KeyDerivationFunction<Key = H::SecretKey>,
{
    /// Base Derivation Scheme
    base: H,

    /// Type Parameter Marker
    __: PhantomData<K>,
}

impl<H, K> Map<H, K>
where
    H: HierarchicalKeyDerivationScheme,
    K: KeyDerivationFunction<Key = H::SecretKey>,
{
    /// Builds a new [`Map`] from `base`.
    #[inline]
    pub fn new(base: H) -> Self {
        Self {
            base,
            __: PhantomData,
        }
    }
}

impl<H, K> HierarchicalKeyDerivationScheme for Map<H, K>
where
    H: HierarchicalKeyDerivationScheme,
    K: KeyDerivationFunction<Key = H::SecretKey>,
{
    type SecretKey = K::Output;
    type Error = H::Error;

    #[inline]
    fn derive(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
        view: Option<ViewIndex>,
    ) -> Result<Self::SecretKey, Self::Error> {
        self.base
            .derive(account, spend, view)
            .map(move |k| K::derive(&k))
    }

    #[inline]
    fn derive_spend(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
    ) -> Result<Self::SecretKey, Self::Error> {
        self.base
            .derive_spend(account, spend)
            .map(move |k| K::derive(&k))
    }

    #[inline]
    fn derive_view(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
        view: ViewIndex,
    ) -> Result<Self::SecretKey, Self::Error> {
        self.base
            .derive_view(account, spend, view)
            .map(move |k| K::derive(&k))
    }
}

impl<H, K, D> Sample<D> for Map<H, K>
where
    H: HierarchicalKeyDerivationScheme + Sample<D>,
    K: KeyDerivationFunction<Key = H::SecretKey>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        Self::new(H::sample(distribution, rng))
    }
}

/// Hierarchical Key Derivation Secret Key Pair
pub struct SecretKeyPair<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Spend Part of the Key Pair
    pub spend: H::SecretKey,

    /// View Part of the Key Pair
    pub view: H::SecretKey,
}

impl<H> SecretKeyPair<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Builds a new [`SecretKeyPair`] from `spend` and `view`.
    #[inline]
    pub fn new(spend: H::SecretKey, view: H::SecretKey) -> Self {
        Self { spend, view }
    }
}

/// Error Type
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "H::Error: Clone"),
    Copy(bound = "H::Error: Copy"),
    Debug(bound = "H::Error: Debug"),
    Eq(bound = "H::Error: Eq"),
    Hash(bound = "H::Error: Hash"),
    PartialEq(bound = "H::Error: PartialEq")
)]
pub enum Error<H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Exceeded Current Maximum Spend Index
    ///
    /// See the [`increment_spend`](AccountMap::increment_spend) method on [`AccountMap`] for more.
    ExceedingCurrentMaximumSpendIndex,

    /// Exceeded Current Maximum View Index
    ///
    /// See the [`increment_view`](AccountMap::increment_view) method on [`AccountMap`] for more.
    ExceedingCurrentMaximumViewIndex,

    /// Key Derivation Error
    KeyDerivationError(H::Error),
}

/// Key Index Type
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct Index {
    /// Spend Part of the Key Index
    pub spend: SpendIndex,

    /// View Part of the Key Index
    pub view: ViewIndex,
}

impl Index {
    /// Builds a new [`Index`] using `spend` and `view`.
    #[inline]
    pub fn new(spend: SpendIndex, view: ViewIndex) -> Self {
        Self { spend, view }
    }
}

impl Debug for Index {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Index")
            .field("spend", &self.spend.index)
            .field("view", &self.view.index)
            .finish()
    }
}

/// Maximum Index Bounds
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MaxIndex {
    /// Maximum View Indices
    ///
    /// The maximum view indices are sorted in order of each spend index. Therefore, the maximum
    /// spend key is one less than the length of this vector.
    view: Vec<ViewIndex>,
}

impl MaxIndex {
    /// Returns the maximum spend index.
    #[inline]
    pub fn spend(&self) -> SpendIndex {
        SpendIndex::new((self.view.len() - 1) as u32)
    }

    /// Returns the set of maximum view indices for each spend key in the range given by
    /// [`spend`](Self::spend).
    ///
    /// # Note
    ///
    /// This array is always inhabited since there is always at least one spend key we can build and
    /// so its corresponding view key must have a maximal index.
    #[inline]
    pub fn view(&self) -> &[ViewIndex] {
        &self.view
    }

    /// Increments the maximum spend index.
    #[inline]
    fn increment_spend(&mut self) -> &Self {
        self.view.push(Default::default());
        &*self
    }

    /// Increments the maximum view index for the given `spend` index.
    #[inline]
    fn increment_view(&mut self, spend: SpendIndex) -> Option<&Self> {
        self.view.get_mut(spend.index() as usize)?.increment();
        Some(&*self)
    }
}

impl Default for MaxIndex {
    #[inline]
    fn default() -> Self {
        Self {
            view: vec![Default::default()],
        }
    }
}

/// Account Keys
#[derive(derivative::Derivative)]
#[derivative(
    Copy(bound = ""),
    Debug(bound = "H: Debug"),
    Eq(bound = "H: Eq"),
    Hash(bound = "H: Hash"),
    PartialEq(bound = "H: PartialEq")
)]
pub struct AccountKeys<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Hierarchical Key Derivation Scheme
    keys: &'h H,

    /// Account Index
    account: AccountIndex,

    /// Maximum Indices
    max_index: &'h MaxIndex,
}

impl<'h, H> AccountKeys<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Builds a new [`AccountKeys`] from `keys`, `account`, and `max_index`.
    #[inline]
    fn new(keys: &'h H, account: AccountIndex, max_index: &'h MaxIndex) -> Self {
        Self {
            keys,
            account,
            max_index,
        }
    }

    /// Performs the bounds check on `spend` and then runs `f`.
    #[inline]
    fn with_spend_bounds_check<T, F>(&self, spend: SpendIndex, f: F) -> Result<T, Error<H>>
    where
        F: FnOnce(&Self, SpendIndex) -> Result<T, H::Error>,
    {
        if spend <= self.max_index.spend() {
            f(self, spend).map_err(Error::KeyDerivationError)
        } else {
            Err(Error::ExceedingCurrentMaximumSpendIndex)
        }
    }

    /// Performs the bounds check on `view` and then runs `f`.
    #[inline]
    fn with_view_bounds_check<T, F>(
        &self,
        spend: SpendIndex,
        view: ViewIndex,
        f: F,
    ) -> Result<T, Error<H>>
    where
        F: FnOnce(&Self, SpendIndex, ViewIndex) -> Result<T, H::Error>,
    {
        if spend <= self.max_index.spend() {
            if view <= self.max_index.view[spend.index() as usize] {
                f(self, spend, view).map_err(Error::KeyDerivationError)
            } else {
                Err(Error::ExceedingCurrentMaximumViewIndex)
            }
        } else {
            Err(Error::ExceedingCurrentMaximumSpendIndex)
        }
    }

    /// Derives the spend key for this account at `spend` without performing bounds checks.
    #[inline]
    fn derive_spend(&self, spend: SpendIndex) -> Result<H::SecretKey, H::Error> {
        self.keys.derive_spend(self.account, spend)
    }

    /// Returns the default spend key for this account.
    #[inline]
    pub fn default_spend_key(&self) -> Result<H::SecretKey, H::Error> {
        self.derive_spend(Default::default())
    }

    /// Returns the spend key for this account at the `spend` index, if it does not exceed the
    /// maximum index.
    #[inline]
    pub fn spend_key(&self, spend: SpendIndex) -> Result<H::SecretKey, Error<H>> {
        self.with_spend_bounds_check(spend, Self::derive_spend)
    }

    /// Derives the view key for this account at the `spend` and `view` indices without performing
    /// bounds checks.
    #[inline]
    fn derive_view(&self, spend: SpendIndex, view: ViewIndex) -> Result<H::SecretKey, H::Error> {
        self.keys.derive_view(self.account, spend, view)
    }

    /// Returns the default view key for this account.
    #[inline]
    pub fn default_view_key(&self) -> Result<H::SecretKey, H::Error> {
        self.derive_view(Default::default(), Default::default())
    }

    /// Returns the view key for this account at `index`, if it does not exceed the maximum index.
    #[inline]
    pub fn view_key(&self, index: Index) -> Result<H::SecretKey, Error<H>> {
        self.view_key_with(index.spend, index.view)
    }

    /// Returns the view key for this account at the `spend` and `view` indices, if it does not
    /// exceed the maximum index.
    #[inline]
    pub fn view_key_with(
        &self,
        spend: SpendIndex,
        view: ViewIndex,
    ) -> Result<H::SecretKey, Error<H>> {
        self.with_view_bounds_check(spend, view, Self::derive_view)
    }

    /// Derives the secret key pair for this account at `spend` and `view` without performing bounds
    /// checks.
    #[inline]
    fn derive_pair(
        &self,
        spend: SpendIndex,
        view: ViewIndex,
    ) -> Result<SecretKeyPair<H>, H::Error> {
        self.keys.derive_pair(self.account, spend, view)
    }

    /// Returns the default secret key pair for this account.
    #[inline]
    pub fn default_keypair(&self) -> Result<SecretKeyPair<H>, H::Error> {
        self.derive_pair(Default::default(), Default::default())
    }

    /// Returns the key pair for this account at `index`, if it does not exceed the maximum index.
    #[inline]
    pub fn keypair(&self, index: Index) -> Result<SecretKeyPair<H>, Error<H>> {
        self.keypair_with(index.spend, index.view)
    }

    /// Returns the key pair for this account at the `spend` and `view` indices, if those indices
    /// do not exceed the maximum indices.
    #[inline]
    pub fn keypair_with(
        &self,
        spend: SpendIndex,
        view: ViewIndex,
    ) -> Result<SecretKeyPair<H>, Error<H>> {
        self.with_view_bounds_check(spend, view, Self::derive_pair)
    }

    /// Applies `f` to the view keys generated by `self` returning the first non-`None` result with
    /// it's key index and key attached, or returns an error if the key derivation failed.
    #[inline]
    pub fn find_index<T, F>(&self, mut f: F) -> Result<Option<ViewKeySelection<H, T>>, H::Error>
    where
        F: FnMut(&H::SecretKey) -> Option<T>,
    {
        let mut index = Index::default();
        loop {
            loop {
                match self.view_key(index) {
                    Ok(view_key) => {
                        if let Some(item) = f(&view_key) {
                            return Ok(Some(ViewKeySelection {
                                index,
                                keypair: SecretKeyPair::new(
                                    self.derive_spend(index.spend)?,
                                    view_key,
                                ),
                                item,
                            }));
                        }
                    }
                    Err(Error::ExceedingCurrentMaximumViewIndex) => break,
                    Err(Error::ExceedingCurrentMaximumSpendIndex) => return Ok(None),
                    Err(Error::KeyDerivationError(err)) => return Err(err),
                }
                index.view.increment();
            }
            index.spend.increment();
            index.view.reset();
        }
    }
}

// NOTE: We need this because `derivative::Derivative` doesn't derive this trait properly.
impl<'h, H> Clone for AccountKeys<'h, H>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    #[inline]
    fn clone(&self) -> Self {
        Self::new(self.keys, self.account, self.max_index)
    }
}

/// View Key Selection
pub struct ViewKeySelection<H, T>
where
    H: HierarchicalKeyDerivationScheme + ?Sized,
{
    /// Selection Index
    pub index: Index,

    /// Selection Key Pair
    pub keypair: SecretKeyPair<H>,

    /// Selection Item
    pub item: T,
}

/// Account Map Trait
pub trait AccountMap {
    /// Builds a new [`AccountMap`] with a starting account with default max indices.
    fn new() -> Self;

    /// Returns the maximum spend and view indices for `account`, if it exists.
    fn max_index(&self, account: AccountIndex) -> Option<&MaxIndex>;

    /// Adds a new account to the map, returning the new account parameter.
    fn create_account(&mut self) -> AccountIndex;

    /// Increments the maximum spend index for `account`, if it exists, returning the current
    /// maximum indices.
    fn increment_spend(&mut self, account: AccountIndex) -> Option<&MaxIndex>;

    /// Increments the maximum view index for `account`, if it exists, returning the current
    /// maximum indices.
    fn increment_view(&mut self, account: AccountIndex, spend: SpendIndex) -> Option<&MaxIndex>;
}

/// [`Vec`] Account Map Type
pub type VecAccountMap = Vec<MaxIndex>;

impl AccountMap for VecAccountMap {
    #[inline]
    fn new() -> Self {
        let mut this = Self::new();
        this.create_account();
        this
    }

    #[inline]
    fn max_index(&self, account: AccountIndex) -> Option<&MaxIndex> {
        self.get(account.index() as usize)
    }

    #[inline]
    fn create_account(&mut self) -> AccountIndex {
        let index = AccountIndex::new(
            self.len()
                .try_into()
                .expect("AccountIndex is not allowed to exceed IndexType::MAX."),
        );
        self.push(Default::default());
        index
    }

    #[inline]
    fn increment_spend(&mut self, account: AccountIndex) -> Option<&MaxIndex> {
        self.get_mut(account.index() as usize)
            .map(MaxIndex::increment_spend)
    }

    #[inline]
    fn increment_view(&mut self, account: AccountIndex, spend: SpendIndex) -> Option<&MaxIndex> {
        self.get_mut(account.index() as usize)
            .and_then(move |index| index.increment_view(spend))
    }
}

/// Account Table
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "H: Clone, M: Clone"),
    Copy(bound = "H: Copy, M: Copy"),
    Debug(bound = "H: Debug, M: Debug"),
    Eq(bound = "H: Eq, M: Eq"),
    Hash(bound = "H: Hash, M: Hash"),
    PartialEq(bound = "H: PartialEq, M: PartialEq")
)]
pub struct AccountTable<H, M = VecAccountMap>
where
    H: HierarchicalKeyDerivationScheme,
    M: AccountMap,
{
    /// Hierarchical Key Derivation Scheme
    keys: H,

    /// Account Map
    accounts: M,
}

impl<H, M> AccountTable<H, M>
where
    H: HierarchicalKeyDerivationScheme,
    M: AccountMap,
{
    /// Builds a new [`AccountTable`] using `keys` and the default account map.
    #[inline]
    pub fn new(keys: H) -> Self {
        Self::with_accounts(keys, M::new())
    }

    /// Builds a new [`AccountTable`] using `keys` and `accounts`.
    #[inline]
    pub fn with_accounts(keys: H, accounts: M) -> Self {
        Self { keys, accounts }
    }

    /// Returns the key associated to `account` if it exists, using `index` if it does not exceed
    /// the maximum index.
    #[inline]
    pub fn keypair(
        &self,
        account: AccountIndex,
        index: Index,
    ) -> Option<Result<SecretKeyPair<H>, Error<H>>> {
        self.keypair_with(account, index.spend, index.view)
    }

    /// Returns the key associated to `account` if it exists, using the `spend` and `view` indices
    /// if they do not exceed the maximum indices.
    #[inline]
    pub fn keypair_with(
        &self,
        account: AccountIndex,
        spend: SpendIndex,
        view: ViewIndex,
    ) -> Option<Result<SecretKeyPair<H>, Error<H>>> {
        self.get(account).map(move |k| k.keypair_with(spend, view))
    }

    /// Returns the account keys for `account` if it exists.
    #[inline]
    pub fn get(&self, account: AccountIndex) -> Option<AccountKeys<H>> {
        Some(AccountKeys::new(
            &self.keys,
            account,
            self.accounts.max_index(account)?,
        ))
    }

    /// Returns the account keys for the default account.
    #[inline]
    pub fn get_default(&self) -> AccountKeys<H> {
        self.get(Default::default()).unwrap()
    }

    /// Returns the maximum spend and view indices for `account`, if it exists.
    #[inline]
    pub fn max_index(&self, account: AccountIndex) -> Option<&MaxIndex> {
        self.accounts.max_index(account)
    }

    /// Adds a new account to the map, returning the new account parameter.
    #[inline]
    pub fn create_account(&mut self) -> AccountIndex {
        self.accounts.create_account()
    }

    /// Increments the maximum spend index for `account`, if it exists, returning the current
    /// maximum indices.
    #[inline]
    pub fn increment_spend(&mut self, account: AccountIndex) -> Option<&MaxIndex> {
        self.accounts.increment_spend(account)
    }

    /// Increments the maximum view index for `account`, if it exists, returning the current
    /// maximum indices.
    #[inline]
    pub fn increment_view(
        &mut self,
        account: AccountIndex,
        spend: SpendIndex,
    ) -> Option<&MaxIndex> {
        self.accounts.increment_view(account, spend)
    }

    /// Increments the spend index and returns the [`Index`] pair for the new spend index and its
    /// first view key.
    #[inline]
    pub fn next_index(&mut self, account: AccountIndex) -> Option<Index> {
        let max_index = self.increment_spend(account)?;
        Some(Index::new(max_index.spend(), Default::default()))
    }

    /// Increments the spend index and returns the [`SecretKeyPair`] for the new spend index and
    /// its first view key.
    #[inline]
    pub fn next(&mut self, account: AccountIndex) -> Option<Result<SecretKeyPair<H>, H::Error>> {
        let index = self.next_index(account)?;
        Some(self.keys.derive_pair(account, index.spend, index.view))
    }
}

impl<H, M> Default for AccountTable<H, M>
where
    H: Default + HierarchicalKeyDerivationScheme,
    M: AccountMap,
{
    #[inline]
    fn default() -> Self {
        Self::new(Default::default())
    }
}
