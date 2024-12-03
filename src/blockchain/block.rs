use super::Error;
use super::OperationCode;
use super::Result;
use crate::blockchain::calculate_hash;
use crate::blockchain::OperationCode::{
    Accept, Endorse, Issue, Mint, RequestToAccept, RequestToPay, Sell,
};
use crate::constants::ACCEPTED_BY;
use crate::constants::ENDORSED_BY;
use crate::constants::ENDORSED_TO;
use crate::constants::REQ_TO_ACCEPT_BY;
use crate::constants::REQ_TO_PAY_BY;
use crate::constants::SOLD_BY;
use crate::constants::SOLD_TO;
use crate::service::bill_service::BillKeys;
use crate::service::contact_service::IdentityPublicData;
use crate::util;
use crate::{service::bill_service::BitcreditBill, util::rsa::decrypt_bytes};
use log::error;
use log::info;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::sign::Verifier;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Block {
    pub id: u64,
    pub bill_name: String,
    pub hash: String,
    pub timestamp: i64,
    pub data: String,
    pub previous_hash: String,
    pub signature: String,
    pub public_key: String,
    pub operation_code: OperationCode,
}

impl Block {
    /// Creates a new instance of the struct with the provided details, calculates the block hash,
    /// and generates a signature for the block.
    ///
    /// # Arguments
    ///
    /// - `id`: The unique identifier of the block (`u64`).
    /// - `previous_hash`: A `String` representing the hash of the previous block in the chain.
    /// - `data`: A `String` containing the data to be stored in the block.
    /// - `bill_name`: A `String` representing the name of the bill associated with the block.
    /// - `public_key`: A `String` containing the public RSA key in PEM format.
    /// - `operation_code`: An `OperationCode` indicating the operation type associated with the block.
    /// - `private_key`: A `String` containing the private RSA key in PEM format, used to sign the block.
    /// - `timestamp`: An `i64` timestamp representing the time the block was created.
    ///
    /// # Returns
    ///
    /// A new instance of the struct populated with the provided data, a calculated block hash,
    /// and a signature.
    ///
    pub fn new(
        id: u64,
        previous_hash: String,
        data: String,
        bill_name: String,
        public_key: String,
        operation_code: OperationCode,
        private_key: String,
        timestamp: i64,
    ) -> Result<Self> {
        let hash: String = mine_block(
            &id,
            &bill_name,
            &previous_hash,
            &data,
            &timestamp,
            &public_key,
            &operation_code,
        );
        let signature = signature(&hash, &private_key)?;

        Ok(Self {
            id,
            bill_name,
            hash,
            timestamp,
            previous_hash,
            signature,
            data,
            public_key,
            operation_code,
        })
    }

    fn get_decrypted_block_data(&self, bill_keys: &BillKeys) -> Result<String> {
        let key: Rsa<Private> = Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes())?;
        let bytes = hex::decode(&self.data)?;
        let decrypted_bytes = decrypt_bytes(&bytes, &key);
        let block_data_decrypted = String::from_utf8(decrypted_bytes)?;
        Ok(block_data_decrypted)
    }

    /// Extracts a list of unique node IDs involved in a block operation.
    ///
    /// # Parameters
    /// - `bill`: The bill
    /// - `bill_keys`: The bill's keys
    ///
    /// # Returns
    /// A `Vec<String>` containing the unique peer IDs involved in the block. Peer IDs are included
    /// only if they are non-empty.
    ///
    pub fn get_nodes_from_block(
        &self,
        bill: BitcreditBill,
        bill_keys: &BillKeys,
    ) -> Result<Vec<String>> {
        let mut nodes = HashSet::new();
        match self.operation_code {
            Issue => {
                let drawer_name = bill.drawer.peer_id;
                if !drawer_name.is_empty() {
                    nodes.insert(drawer_name);
                }

                let payee_name = bill.payee.peer_id;
                if !payee_name.is_empty() {
                    nodes.insert(payee_name);
                }

                let drawee_name = bill.drawee.peer_id;
                if !drawee_name.is_empty() {
                    nodes.insert(drawee_name);
                }
            }
            Endorse => {
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let endorsee: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, ENDORSED_TO).ok_or(
                        Error::InvalidBlockdata(String::from("Endorse: No endorsee found")),
                    )?,
                )?)?;
                let endorsee_node_id = endorsee.peer_id;
                if !endorsee_node_id.is_empty() {
                    nodes.insert(endorsee_node_id);
                }

                let endorser: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, ENDORSED_BY).ok_or(
                        Error::InvalidBlockdata(String::from("Endorse: No endorser found")),
                    )?,
                )?)?;
                let endorser_node_id = endorser.peer_id;
                if !endorser_node_id.is_empty() {
                    nodes.insert(endorser_node_id);
                }
            }
            Mint => {
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let mint: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, ENDORSED_TO)
                        .ok_or(Error::InvalidBlockdata(String::from("Mint: No mint found")))?,
                )?)?;
                let mint_node_id = mint.peer_id;
                if !mint_node_id.is_empty() {
                    nodes.insert(mint_node_id);
                }

                let minter: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, ENDORSED_BY).ok_or(
                        Error::InvalidBlockdata(String::from("Mint: No minter found")),
                    )?,
                )?)?;
                let minter_node_id = minter.peer_id;
                if !minter_node_id.is_empty() {
                    nodes.insert(minter_node_id);
                }
            }
            RequestToAccept => {
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let requester: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, REQ_TO_ACCEPT_BY).ok_or(
                        Error::InvalidBlockdata(String::from(
                            "Request to accept: No requester found",
                        )),
                    )?,
                )?)?;
                let requester_node_id = requester.peer_id;
                if !requester_node_id.is_empty() {
                    nodes.insert(requester_node_id);
                }
            }
            Accept => {
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let accepter: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, ACCEPTED_BY).ok_or(
                        Error::InvalidBlockdata(String::from("Accept: No accepter found")),
                    )?,
                )?)?;
                let accepter_node_id = accepter.peer_id;
                if !accepter_node_id.is_empty() {
                    nodes.insert(accepter_node_id);
                }
            }
            RequestToPay => {
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let requester: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, REQ_TO_PAY_BY).ok_or(
                        Error::InvalidBlockdata(String::from("Request to Pay: No requester found")),
                    )?,
                )?)?;
                let requester_node_id = requester.peer_id;
                if !requester_node_id.is_empty() {
                    nodes.insert(requester_node_id);
                }
            }
            Sell => {
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let buyer: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, SOLD_TO).ok_or(
                        Error::InvalidBlockdata(String::from("Sell: No buyer found")),
                    )?,
                )?)?;
                let buyer_node_id = buyer.peer_id;
                if !buyer_node_id.is_empty() {
                    nodes.insert(buyer_node_id);
                }

                let seller: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, SOLD_BY).ok_or(
                        Error::InvalidBlockdata(String::from("Sell: No seller found")),
                    )?,
                )?)?;
                let seller_node_id = seller.peer_id;
                if !seller_node_id.is_empty() {
                    nodes.insert(seller_node_id);
                }
            }
        }
        Ok(nodes.into_iter().collect())
    }

    /// Generates a human-readable history label for a bill based on the operation code.
    ///
    /// # Parameters
    /// - `bill`: The bill
    /// - `bill_keys`: The bill's keys
    ///
    /// # Returns
    /// A `String` representing the history label for the given bill.
    ///
    pub fn get_history_label(&self, bill: BitcreditBill, bill_keys: &BillKeys) -> Result<String> {
        match self.operation_code {
            Issue => {
                let time_of_issue = util::date::seconds(self.timestamp);
                if !bill.drawer.name.is_empty() {
                    Ok(format!(
                        "Bill issued by {} at {} in {}",
                        bill.drawer.name, time_of_issue, bill.place_of_drawing
                    ))
                } else if bill.to_payee {
                    Ok(format!(
                        "Bill issued by {} at {} in {}",
                        bill.payee.name, time_of_issue, bill.place_of_drawing
                    ))
                } else {
                    Ok(format!(
                        "Bill issued by {} at {} in {}",
                        bill.drawee.name, time_of_issue, bill.place_of_drawing
                    ))
                }
            }
            Endorse => {
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let endorser: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, ENDORSED_BY).ok_or(
                        Error::InvalidBlockdata(String::from("Endorse: No endorser found")),
                    )?,
                )?)?;

                Ok(format!("{}, {}", endorser.name, endorser.postal_address))
            }
            Mint => {
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let minter: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, ENDORSED_BY).ok_or(
                        Error::InvalidBlockdata(String::from("Mint: No minter found")),
                    )?,
                )?)?;

                Ok(format!("{}, {}", minter.name, minter.postal_address))
            }
            RequestToAccept => {
                let time_of_request_to_accept = util::date::seconds(self.timestamp);
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let requester: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, REQ_TO_ACCEPT_BY).ok_or(
                        Error::InvalidBlockdata(String::from(
                            "Request to accept: No requester found",
                        )),
                    )?,
                )?)?;

                Ok(format!(
                    "Bill requested to accept by {} at {} in {}",
                    requester.name, time_of_request_to_accept, requester.postal_address
                ))
            }
            Accept => {
                let time_of_accept = util::date::seconds(self.timestamp);
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let accepter: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, ACCEPTED_BY).ok_or(
                        Error::InvalidBlockdata(String::from("Accept: No accepter found")),
                    )?,
                )?)?;

                Ok(format!(
                    "Bill accepted by {} at {} in {}",
                    accepter.name, time_of_accept, accepter.postal_address
                ))
            }
            RequestToPay => {
                let time_of_request_to_pay = util::date::seconds(self.timestamp);
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let requester: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, REQ_TO_PAY_BY).ok_or(
                        Error::InvalidBlockdata(String::from("Request to pay: No requester found")),
                    )?,
                )?)?;

                Ok(format!(
                    "Bill requested to pay by {} at {} in {}",
                    requester.name, time_of_request_to_pay, requester.postal_address
                ))
            }
            Sell => {
                let block_data_decrypted = self.get_decrypted_block_data(bill_keys)?;

                let seller: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, SOLD_BY).ok_or(
                        Error::InvalidBlockdata(String::from("Sell: No seller found")),
                    )?,
                )?)?;

                Ok(format!("{}, {}", seller.name, seller.postal_address))
            }
        }
    }

    /// Verifies the signature of the data associated with the current object using the stored public key.
    ///
    /// This method checks if the signature matches the hash of the data, ensuring data integrity and authenticity.
    ///
    /// # Returns
    ///
    /// A `bool` indicating whether the signature is valid:
    /// - `true` if the signature is valid.
    /// - `false` if the signature is invalid.
    ///
    pub fn verify(&self) -> bool {
        match self.verify_internal() {
            Err(e) => {
                error!("Error while verifying block id {}: {e}", self.id);
                false
            }
            Ok(res) => res,
        }
    }

    fn verify_internal(&self) -> Result<bool> {
        let public_key_rsa = Rsa::public_key_from_pem(self.public_key.as_bytes())?;
        let verifier_key = PKey::from_rsa(public_key_rsa)?;

        let mut verifier = Verifier::new(MessageDigest::sha256(), verifier_key.as_ref())?;

        let data_to_check = self.hash.as_bytes();
        verifier.update(data_to_check)?;

        let signature_bytes = hex::decode(&self.signature)?;
        let res = verifier.verify(signature_bytes.as_slice())?;
        Ok(res)
    }
}

/// Mines a block by calculating its hash and returning the result as a hexadecimal string.
///
/// # Arguments
///
/// - `id`: A reference to the unique identifier (`u64`) of the block.
/// - `bill_name`: A reference to a string slice representing the name of the bill associated with the block.
/// - `previous_hash`: A reference to a string slice containing the hash of the previous block in the chain.
/// - `data`: A reference to a string slice containing the data to be stored in the block.
/// - `timestamp`: A reference to an `i64` timestamp indicating when the block is being mined.
/// - `public_key`: A reference to a string slice representing the public key associated with the block.
/// - `operation_code`: A reference to an `OperationCode` that specifies the operation associated with the block.
///
/// # Returns
///
/// A `String` containing the hexadecimal representation of the calculated block hash.
///
fn mine_block(
    id: &u64,
    bill_name: &str,
    previous_hash: &str,
    data: &str,
    timestamp: &i64,
    public_key: &str,
    operation_code: &OperationCode,
) -> String {
    let hash = calculate_hash(
        id,
        bill_name,
        previous_hash,
        data,
        timestamp,
        public_key,
        operation_code,
    );
    let binary_hash = hex::encode(&hash);
    info!(
        "mined! hash: {}, binary hash: {}",
        hex::encode(&hash),
        binary_hash
    );
    hex::encode(hash)
}

/// Signs a hash using a private RSA key and returns the resulting signature as a hexadecimal string
/// # Arguments
///
/// - `hash`: A string representing the data hash to be signed. This is typically the output of a hashing algorithm like SHA-256.
/// - `private_key_pem`: A string containing the private RSA key in PEM format. This key is used to generate the signature.
///
/// # Returns
///
/// A `String` containing the hexadecimal representation of the digital signature.
///
fn signature(hash: &str, private_key_pem: &str) -> Result<String> {
    let private_key_rsa = Rsa::private_key_from_pem(private_key_pem.as_bytes())?;
    let signer_key = PKey::from_rsa(private_key_rsa)?;

    let mut signer: Signer = Signer::new(MessageDigest::sha256(), signer_key.as_ref())?;

    let data_to_sign = hash.as_bytes();
    signer.update(data_to_sign)?;

    let signature: Vec<u8> = signer.sign_to_vec()?;
    let signature_readable = hex::encode(signature.as_slice());

    Ok(signature_readable)
}

fn extract_after_phrase(input: &str, phrase: &str) -> Option<String> {
    if let Some(start) = input.find(phrase) {
        let start_idx = start + phrase.len();
        if let Some(remaining) = input.get(start_idx..) {
            if let Some(end_idx) = remaining.find(' ') {
                return Some(remaining[..end_idx].to_string());
            } else {
                return Some(remaining.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn extract_after_phrase_basic() {
        assert_eq!(
            extract_after_phrase(
                "Endorsed by 123 endorsed to 456 amount: 5000",
                "Endorsed by "
            ),
            Some(String::from("123"))
        );
        assert_eq!(
            extract_after_phrase(
                "Endorsed by 123 endorsed to 456 amount: 5000",
                " endorsed to "
            ),
            Some(String::from("456"))
        );
        assert_eq!(
            extract_after_phrase("Endorsed by 123 endorsed to 456 amount: 5000", " amount: "),
            Some(String::from("5000"))
        );
        assert_eq!(
            extract_after_phrase(
                "Endorsed by 123 endorsed to 456 amount: 5000",
                " weird stuff "
            ),
            None
        );
    }
}
