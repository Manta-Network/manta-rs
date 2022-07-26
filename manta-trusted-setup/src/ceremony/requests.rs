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
//! Registry for the ceremony.

use crate::{
    ceremony::{
        queue::{Identifier, Priority},
        signature,
        signature::SignatureScheme,
    },
    mpc,
    mpc::Types,
};
use core::{fmt::Debug, marker::PhantomData};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
/// Only for testing
pub struct RegisterRequest<P>
where
    P: Identifier + Priority + signature::HasPublicKey,
{
    /// The Participant to register
    pub participant: P,
}

#[derive(Debug, Deserialize, Serialize)]
///
pub struct JoinQueueRequest<P, S>
where
    P: Identifier + Priority + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
{
    participant: P,
    sig: S::Signature,
}

#[derive(Debug, Deserialize, Serialize)]
///
pub struct GetMpcRequest<P, S, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    ///
    pub participant: P,
    sig: S::Signature,
    __: PhantomData<V>,
}

#[derive(Debug, Deserialize, Serialize)]
/// TODO: Can't get the enum version to derive serde
pub struct GetMpcResponse<S, V>
where
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    // response: MpcResponse<V>,
    __: PhantomData<V>,
    ___: PhantomData<S>,
}

// TODO: delete when GetMpcResponse is fixed
impl<S, V> Default for GetMpcResponse<S, V>
where
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    fn default() -> Self {
        Self {
            __: PhantomData,
            ___: PhantomData,
        }
    }
}

#[derive(Debug)] //, Deserialize, Serialize)]
///
pub enum MpcResponse<V>
where
    V: mpc::Verify,
{
    ///
    QueuePosition,
    ///
    Mpc(V::State),
}

#[derive(Debug, Deserialize, Serialize)]
///
pub struct ContributeRequest<P, S, V>
where
    P: Identifier + signature::HasPublicKey<PublicKey = S::PublicKey>,
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    ///
    pub participant: P,
    ///
    pub transformed_state: V::State,
    ///
    pub proof: V::Proof,
    ///
    pub sig: S::Signature,
}
