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

//! Manta Pay Simulation

use std::io;

/// Runs the Manta Pay simulation.
#[inline]
pub fn main() -> io::Result<()> {
    let directory = tempfile::tempdir()?;
    println!("[INFO] Temporary Directory: {:?}", directory);
    manta_pay::simulation::simulate(10, 10, directory.path());
    directory.close()?;
    Ok(())
}
