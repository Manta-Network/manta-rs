//! Given the json of contribution data extracted from the TS server logs, this
//! script matches each contribution to registration entries using the twitter handle
//! as the contribution's identifier. (In the future the server should produce logs with a more unique
//! identifier.) 
//! Due to multiple submissions from a participant, there are sometimes multiple matching registrations.
//! In this case the most recent one is marked as non-duplicate and all prior entries are marked as 
//! duplicates. A list of non-duplicate entries can therefore be extracted from the outputs by filtering
//! for "Duplicate = FALSE".

use core::fmt::Debug;
use csv::{Reader, WriterBuilder};
use manta_util::serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
};

/// Contribution data extractable from server logs
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "manta_util::serde", deny_unknown_fields)
)]
#[derive(Debug)]
pub struct Contribution {
    timestamp: String,
    participant: String,
    number: usize,
    hash: String,
}

fn main() {
    let path =
        "/Users/thomascnorton/Documents/Manta/manta-rs/manta-trusted-setup/data/contribution.json"
            .to_string();
    let reader = BufReader::new(File::open(path).expect("Unable to open contributions file"));
    let contributions: Vec<Contribution> = serde_json::from_reader(reader).unwrap();
    println!("Deserialized {:?} contributions", contributions.len());

    // Check that there are no missing records
    for (i, contribution) in contributions.iter().enumerate() {
        if contribution.number != i + 1 {
            println!("Gap at contribution number {:?}", contributions[i].number);
        }
    }

    // Check consistency with list of hashes computed while verifying transcript
    let hash_path =
        "/Users/thomascnorton/Documents/Manta/ceremony_hashes_22_12_29/contribution_hashes.txt"
            .to_string();
    let computed_hashes =
        BufReader::new(File::open(hash_path).expect("Unable to open hashes file")).lines();
    for (hash, contribution) in computed_hashes.zip(contributions.iter()) {
        let hash = hash.unwrap();
        let hash: Vec<&str> = hash.split(' ').collect();
        if hash[0] != contribution.hash {
            println!(
                "Mismatched hashes at contribution {:?}:",
                contribution.number
            );
            println!("Computed hash from verification: {hash:?}");
            println!("Hash extracted from server logs: {:}", contribution.hash);
        }
    }

    let mut output_1 = WriterBuilder::new().from_writer(
        File::create("/Users/thomascnorton/Desktop/contributor_registrations_1.csv")
            .expect("Unable to create output file"),
    );
    let mut output_2 = WriterBuilder::new().from_writer(
        File::create("/Users/thomascnorton/Desktop/contributor_registrations_2.csv")
            .expect("Unable to create output file"),
    );
    // This is inefficient but runs in about 2mins
    let now = std::time::Instant::now();
    let mut not_found = Vec::new();
    for contribution in contributions.iter() {
        let mut found = false;
        let mut matching_entries_1 = Vec::new();
        let mut matching_entries_2 = Vec::new();
        let registration_1_path =
            "/Users/thomascnorton/Desktop/ts_server_registry/ts_signup_1_full.csv".to_string();
        let mut reader_1 = Reader::from_reader(
            File::open(registration_1_path).expect("Unable to open registration file"),
        );
        let registration_2_path =
            "/Users/thomascnorton/Desktop/ts_server_registry/ts_signup_2_full.csv".to_string();
        let mut reader_2 = Reader::from_reader(
            File::open(registration_2_path).expect("Unable to open registration file"),
        );

        if !contribution.participant.is_empty() {
            for record in reader_1.records().flatten() {
                if record
                    .iter()
                    .skip(1)
                    .any(|field| field.contains(&contribution.participant))
                {
                    // record.push_field(&found.to_string());
                    // output_1.write_record(&record).expect("Unable to write");
                    matching_entries_1.push(record);
                    found = true;
                }
            }
            for record in reader_2.records().flatten() {
                if record
                    .iter()
                    .skip(1)
                    .any(|field| field.contains(&contribution.participant))
                {
                    // record.push_field(&found.to_string());
                    // output_2.write_record(&record).expect("Unable to write");
                    matching_entries_2.push(record);
                    found = true;
                }
            }
            if !found {
                println!("Did not find participant {:?}", contribution.participant);
                not_found.push(contribution);
            } else {
                // Want to mark most recent entry as non-duplicate and priors as duplicates
                let mut duplicate = false;
                for mut record in matching_entries_2.into_iter().rev() {
                    record.push_field(&duplicate.to_string());
                    output_2.write_record(&record).expect("Unable to write");
                    duplicate = true;
                }
                for mut record in matching_entries_1.into_iter().rev() {
                    record.push_field(&duplicate.to_string());
                    output_1.write_record(&record).expect("Unable to write");
                    duplicate = true;
                }
            }
        }
    }
    println!("Took {:?}", now.elapsed());
    println!(
        "Was unable to find info for {:?} contributions",
        not_found.len()
    );
    let not_found_output =
        File::create("/Users/thomascnorton/Desktop/not_found.json").expect("Unable to create file");
    serde_json::to_writer(not_found_output, &not_found).expect("Error serializing to json");
}
