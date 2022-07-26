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

use crate::ceremony::queue::Priority;
use crate::mpc::Types;
use crate::{
    ceremony::{queue::Identifier, signature, signature::SignatureScheme},
    mpc,
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
    P: Identifier,
    S: SignatureScheme,
{
    participant: P,
    sig: S::Signature,
}

#[derive(Debug, Deserialize, Serialize)]
///
pub struct GetMpcRequest<S, V>
where
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    sig: S::Signature,
    __: PhantomData<V>,
}

#[derive(Debug, Deserialize, Serialize)]
///
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

#[derive(Debug, Deserialize, Serialize)]
///
pub enum MpcResponse<V> 
where 
    V: mpc::Verify, {
    ///
    QueuePosition,
    ///
    Mpc(V::State),
}

#[derive(Debug, Deserialize, Serialize)]
///
pub struct ContributeRequest<S, V>
where
    S: SignatureScheme,
    V: mpc::Verify,
    V::State: signature::Verify<S>,
    V::Proof: signature::Verify<S>,
{
    state: V::State,
    proof: V::Proof,
    sig: S::Signature,
}

#[derive(Debug, Deserialize, Serialize)]
///
pub struct MpcSubstate<V> {
    __: PhantomData<V>,
}
