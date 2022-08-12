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

//! Waiting Queue

use alloc::{collections::VecDeque, vec::Vec};
use manta_util::{
    into_array_unchecked,
    iter::{Finder, IteratorExt},
};

/// Priority
pub trait Priority {
    /// Gets the priority value.
    fn priority(&self) -> usize;
}

/// Identifier
pub trait HasIdentifier {
    /// Identifier Type
    type Identifier: Ord + Clone;

    /// Gets the identifier.
    fn identifier(&self) -> Self::Identifier;
}

/// Queue with `N` priority levels where participants with higher priority level are served first
pub struct Queue<T, const N: usize>([VecDeque<T::Identifier>; N])
where
    T: Priority + HasIdentifier;

impl<T, const N: usize> Default for Queue<T, N>
where
    T: Priority + HasIdentifier,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Queue<T, N>
where
    T: Priority + HasIdentifier,
{
    /// Builds a new empty [`Queue`].
    #[inline]
    pub fn new() -> Self {
        Self(into_array_unchecked(
            (0..N).map(|_| VecDeque::new()).collect::<Vec<_>>(),
        ))
    }

    /// Pushes a participant to the queue.
    #[inline]
    pub fn push(&mut self, participant: &T) {
        self.0
            .get_mut(participant.priority())
            .expect("Should give valid priority.")
            .push_back(participant.identifier());
    }

    /// Checks if `participant` is at the front.
    #[inline]
    pub fn is_at_front(&self, participant: &T::Identifier) -> bool {
        for priority in (0..N).rev() {
            if self.0[priority].is_empty() {
                continue;
            }
            if self.0[priority].front() == Some(participant) {
                return true;
            }
            return false;
        }
        false
    }

    /// Gets the position of `participant`.
    #[inline]
    pub fn position(&self, participant: &T) -> Option<usize> {
        let priority = participant.priority();
        assert!(priority < N, "Should give a valid priority.");
        Some(
            (priority + 1..N).map(|p| self.0[p].len()).sum::<usize>()
                + self.0[priority]
                    .iter()
                    .find_with(&mut Finder::new(0), |count, item| {
                        if item == &participant.identifier() {
                            Some(*count)
                        } else {
                            *count += 1;
                            None
                        }
                    })?,
        )
    }

    /// Pops the participant at the front and returns its identifier.
    #[inline]
    pub fn pop(&mut self) -> Option<T::Identifier> {
        for priority in (0..N).rev() {
            println!("In pop(). Checked priority: {:?}", priority);
            if let Some(identifier) = self.0[priority].pop_front() {
                return Some(identifier);
            }
        }
        None
    }

    /// Returns the number of participants in the queue.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.iter().map(|v| v.len()).sum()
    }

    /// Checks whether the queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use alloc::string::{String, ToString};

    struct Item {
        id: String,
        priority: usize,
    }

    impl Priority for Item {
        fn priority(&self) -> usize {
            self.priority
        }
    }

    impl HasIdentifier for Item {
        type Identifier = String;
        fn identifier(&self) -> Self::Identifier {
            self.id.clone()
        }
    }

    /// Tests if queue is valid.
    #[test]
    fn queue_is_valid() {
        let mut queue = Queue::<Item, 2>::new();
        let mut participants = Vec::with_capacity(4);
        for participant in [("a", 0), ("b", 1), ("c", 0), ("d", 1)] {
            let item = Item {
                id: participant.0.to_string(),
                priority: participant.1,
            };
            queue.push(&item);
            participants.push(item);
        }
        assert_eq!(queue.len(), 4);
        let expected_order = [
            &participants[1],
            &participants[3],
            &participants[0],
            &participants[2],
        ];
        for i in 0..4 {
            assert_eq!(queue.position(&expected_order[i]), Some(i));
        }

        assert!(queue.is_at_front(&participants[1].id));
        assert_eq!(queue.pop().unwrap(), "b".to_string());
        assert!(!queue.is_at_front(&participants[1].id));
        assert!(queue.is_at_front(&participants[3].id));
        assert_eq!(queue.pop().unwrap(), "d".to_string());
        assert!(queue.is_at_front(&participants[0].id));
        assert_eq!(queue.pop().unwrap(), "a".to_string());
        assert_eq!(queue.pop().unwrap(), "c".to_string());
        assert_eq!(queue.pop(), None);
        assert_eq!(queue.len(), 0);
    }
}
