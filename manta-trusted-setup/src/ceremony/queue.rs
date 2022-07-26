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
//! Waiting queue for the ceremony.

use alloc::{collections::VecDeque, vec::Vec};
use manta_util::{
    into_array_unchecked,
    iter::{Finder, IteratorExt},
};

/// Priority
pub trait Priority {
    /// Get the priority value.
    fn priority(&self) -> usize;
}

/// Identifier
pub trait Identifier {
    /// Necessary information to identify the participant.
    type Identifier: PartialEq;
    /// Get the identifier.
    fn identifier(&self) -> Self::Identifier;
    /// Consume `self` and return the identifier.
    #[inline]
    fn into_identifier(self) -> Self::Identifier
    where
        Self: Sized,
    {
        self.identifier()
    }
}

#[derive(derivative::Derivative)]
#[derivative(Clone(bound = "T::Identifier: Clone"))]
/// First-in first-out queue of type `T::Identifier` with priority levels in range `0..N`.
/// Participants with higher priority are served first.
///
/// # Thread Safety
/// A mutex is required to access the queue.
pub struct Queue<T, const N: usize>([VecDeque<T::Identifier>; N])
where
    T: Priority + Identifier;

impl<T, const N: usize> Queue<T, N>
where
    T: Priority + Identifier,
{
    /// Creates a new empty [`Queue`].
    pub fn new() -> Self {
        Self(into_array_unchecked(
            (0..N).map(|_| VecDeque::new()).collect::<Vec<_>>(),
        ))
    }

    /// Adds participant identity to the queue.
    pub fn push(&mut self, participant: &T) {
        self.0
            .get_mut(participant.priority())
            .expect("Invalid priority value")
            .push_back(participant.identifier());
    }

    /// Checks if a participant is at the front of the queue.
    ///
    /// It is required that the priority of participant is the same as when it was added.
    pub fn is_front(&self, participant: &T) -> bool {
        let priority = participant.priority();
        if (priority + 1..N).rev().any(|p| !self.0[p].is_empty()) {
            return false;
        }
        self.0[priority].front() == Some(&participant.identifier())
    }

    /// Return the approximate position of the participant, or `None` if the participant is not in the queue.
    /// It is required that the priority of participant is the same as when it was added.
    pub fn position(&self, participant: &T) -> Option<usize> {
        let priority = participant.priority();
        let identifier = participant.identifier();
        assert!(priority < N, "invalid priority value");
        let num_participants_with_higher_priority =
            (priority..N).map(|p| self.0[p].len()).sum::<usize>();
        let num_participants_at_front =
            self.0[priority]
                .iter()
                .find_with(&mut Finder::new(0), |count, item| {
                    if item == &identifier {
                        Some(*count)
                    } else {
                        None
                    }
                })?;
        Some(num_participants_with_higher_priority + num_participants_at_front)
    }

    /// Removes the participant from the queue and returns its identifier.  
    /// It is required that the priority of participant is the same as when it was added.
    pub fn pop(&mut self) -> Option<T::Identifier> {
        for priority in (0..N).rev() {
            if let Some(identifier) = self.0[priority].pop_front() {
                return Some(identifier);
            }
        }
        None
    }

    /// Return the number of participants in the queue, also refered to as the length.
    pub fn len(&self) -> usize {
        self.0.iter().map(|v| v.len()).sum()
    }

    /// Returns `true` if the queue has no participants.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T, const N: usize> Default for Queue<T, N>
where
    T: Priority + Identifier,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    // TODO: add test for queue
}
