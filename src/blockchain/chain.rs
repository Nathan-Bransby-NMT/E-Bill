use super::block::Block;
use super::calculate_hash;
use super::extract_after_phrase;
use super::Error;
use super::OperationCode;
use super::Result;
use crate::blockchain::OperationCode::{Endorse, Mint, Sell};
use crate::constants::AMOUNT;
use crate::constants::ENDORSED_TO;
use crate::constants::SOLD_BY;
use crate::constants::SOLD_TO;
use crate::external;
use crate::service::bill_service::BillKeys;
use crate::service::bill_service::BitcreditBill;
use crate::service::contact_service::IdentityPublicData;
use crate::util::rsa::decrypt_bytes;
use crate::CONFIG;
use borsh::from_slice;
use borsh_derive::BorshDeserialize;
use borsh_derive::BorshSerialize;
use log::error;
use log::warn;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Chain {
    pub blocks: Vec<Block>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Serialize, Deserialize, Clone)]
pub struct BlockForHistory {
    id: u64,
    text: String,
    bill_name: String,
}

impl Chain {
    pub fn new(first_block: Block) -> Self {
        let blocks = vec![first_block];

        Self { blocks }
    }

    pub fn to_pretty_printed_json(&self) -> Result<String> {
        let res = serde_json::to_string_pretty(&self)?;
        Ok(res)
    }

    /// Validates the integrity of the blockchain by checking the validity of each block in the chain.
    ///
    /// # Returns
    /// * `true` - If all blocks in the chain are valid.
    /// * `false` - If any block in the chain is found to be invalid.
    ///
    pub fn is_chain_valid(&self) -> bool {
        for i in 0..self.blocks.len() {
            if i == 0 {
                continue;
            }
            let first: &Block = &self.blocks[i - 1];
            let second: &Block = &self.blocks[i];
            if !is_block_valid(second, first) {
                return false;
            }
        }
        true
    }

    /// This function checks whether the provided `block` is valid by comparing it with the latest block
    /// in the current list of blocks. If the block is valid, it is added to the list and the function returns `true`.
    /// If the block is not valid, it logs an error and returns `false`.
    ///
    /// # Arguments
    /// * `block` - The `Block` to be added to the list.
    ///
    /// # Returns
    /// * `true` if the block is successfully added to the list.
    /// * `false` if the block is invalid and cannot be added.
    ///
    pub fn try_add_block(&mut self, block: Block) -> bool {
        let latest_block = self.blocks.last().expect("there is at least one block");
        if is_block_valid(&block, latest_block) {
            self.blocks.push(block);
            true
        } else {
            error!("could not add block - invalid");
            false
        }
    }
    /// Retrieves the latest (most recent) block in the blocks list.
    ///
    /// # Returns
    /// * A reference to the latest block in the blocks list.
    ///
    pub fn get_latest_block(&self) -> &Block {
        self.blocks.last().expect("there is at least one block")
    }

    /// Retrieves the first block in the blocks list.
    ///
    /// # Returns
    /// * A reference to the first block in the blocks list.
    ///
    pub fn get_first_block(&self) -> &Block {
        self.blocks.first().expect("there is at least one block")
    }

    /// Retrieves the last block with the specified operation code.
    /// # Arguments
    /// * `operation_code` - The `OperationCode` to search for in the blocks.
    ///
    /// # Returns
    /// * A reference to the last block with the specified operation code, or the first block if none is found.
    ///
    pub fn get_last_version_block_with_operation_code(
        &self,
        operation_code: OperationCode,
    ) -> &Block {
        let mut last_version_block: &Block = self.get_first_block();
        for block in &self.blocks {
            if block.operation_code == operation_code {
                last_version_block = block;
            }
        }
        last_version_block
    }

    /// Checks if there is any block with a given operation code in the current blocks list.
    ///
    /// # Arguments
    /// * `operation_code` - The `OperationCode` to search for within the blocks.
    ///
    /// # Returns
    /// * `true` if a block with the specified operation code exists in the blocks list, otherwise `false`.
    ///
    pub fn exist_block_with_operation_code(&self, operation_code: OperationCode) -> bool {
        for block in &self.blocks {
            if block.operation_code == operation_code {
                return true;
            }
        }
        false
    }

    pub fn has_been_endorsed_sold_or_minted(&self) -> bool {
        for block in &self.blocks {
            if block.operation_code == OperationCode::Mint {
                return true;
            }
            if block.operation_code == OperationCode::Sell {
                return true;
            }
            if block.operation_code == OperationCode::Endorse {
                return true;
            }
        }
        false
    }

    pub fn has_been_endorsed_or_sold(&self) -> bool {
        for block in &self.blocks {
            if block.operation_code == OperationCode::Sell {
                return true;
            }
            if block.operation_code == OperationCode::Endorse {
                return true;
            }
        }
        false
    }

    /// Retrieves the last version of the Bitcredit bill by decrypting and processing the relevant blocks.
    ///
    /// # Arguments
    /// * `bill_keys` - The keys for the bill.
    ///
    /// # Returns
    /// A `BitcreditBill` object containing the most recent version of the bill, including the payee, endorsee,
    /// and other associated information.
    ///
    pub async fn get_last_version_bill(&self, bill_keys: &BillKeys) -> Result<BitcreditBill> {
        let first_block = self.get_first_block();
        let decrypted_bytes = first_block.get_decrypted_block_bytes(bill_keys)?;
        let bill_first_version: BitcreditBill = from_slice(&decrypted_bytes)?;

        let mut last_endorsee = IdentityPublicData {
            peer_id: "".to_string(),
            name: "".to_string(),
            company: "".to_string(),
            bitcoin_public_key: "".to_string(),
            postal_address: "".to_string(),
            email: "".to_string(),
            rsa_public_key_pem: "".to_string(),
            nostr_npub: None,
            nostr_relay: None,
        };

        if self.blocks.len() > 1
            && (self.exist_block_with_operation_code(Endorse.clone())
                || self.exist_block_with_operation_code(Sell.clone())
                || self.exist_block_with_operation_code(Mint.clone()))
        {
            let last_version_block_endorse =
                self.get_last_version_block_with_operation_code(Endorse);
            let last_version_block_mint = self.get_last_version_block_with_operation_code(Mint);
            let last_version_block_sell = self.get_last_version_block_with_operation_code(Sell);
            let last_block = self.get_latest_block();

            let paid = Self::check_if_last_sell_block_is_paid(self, bill_keys).await;

            if (last_version_block_endorse.id < last_version_block_sell.id)
                && (last_version_block_mint.id < last_version_block_sell.id)
                && ((last_block.id > last_version_block_sell.id) || paid)
            {
                let block_data_decrypted =
                    last_version_block_sell.get_decrypted_block_data(bill_keys)?;
                let buyer: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, SOLD_TO).ok_or(
                        Error::InvalidBlockdata(String::from("Sell: No buyer found")),
                    )?,
                )?)?;

                last_endorsee = buyer;
            } else if self.exist_block_with_operation_code(Endorse.clone())
                && (last_version_block_endorse.id > last_version_block_mint.id)
            {
                let block_data_decrypted =
                    last_version_block_endorse.get_decrypted_block_data(bill_keys)?;
                let endorsee: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, ENDORSED_TO).ok_or(
                        Error::InvalidBlockdata(String::from("Endorse: No endorsee found")),
                    )?,
                )?)?;

                last_endorsee = endorsee;
            } else if self.exist_block_with_operation_code(Mint.clone())
                && (last_version_block_mint.id > last_version_block_endorse.id)
            {
                let block_data_decrypted =
                    last_version_block_mint.get_decrypted_block_data(bill_keys)?;
                let mint: IdentityPublicData = serde_json::from_slice(&hex::decode(
                    &extract_after_phrase(&block_data_decrypted, ENDORSED_TO)
                        .ok_or(Error::InvalidBlockdata(String::from("Mint: No mint found")))?,
                )?)?;

                last_endorsee = mint;
            }
        }

        let mut payee = bill_first_version.payee;

        if !last_endorsee.peer_id.is_empty() {
            payee = last_endorsee.clone();
        }

        Ok(BitcreditBill {
            name: bill_first_version.name,
            to_payee: bill_first_version.to_payee,
            bill_jurisdiction: bill_first_version.bill_jurisdiction,
            timestamp_at_drawing: bill_first_version.timestamp_at_drawing,
            drawee: bill_first_version.drawee,
            drawer: bill_first_version.drawer,
            payee: payee.clone(),
            endorsee: last_endorsee.clone(),
            place_of_drawing: bill_first_version.place_of_drawing,
            currency_code: bill_first_version.currency_code,
            amount_numbers: bill_first_version.amount_numbers,
            amounts_letters: bill_first_version.amounts_letters,
            maturity_date: bill_first_version.maturity_date,
            date_of_issue: bill_first_version.date_of_issue,
            compounding_interest_rate: bill_first_version.compounding_interest_rate,
            type_of_interest_calculation: bill_first_version.type_of_interest_calculation,
            place_of_payment: bill_first_version.place_of_payment,
            public_key: bill_first_version.public_key,
            private_key: bill_first_version.private_key,
            language: bill_first_version.language,
            files: bill_first_version.files,
        })
    }

    /// Checks if the payment for the latest sell block has been made, and returns relevant information about the buyer, seller, and the payment status.
    ///
    /// # Returns
    /// A tuple with the following information:
    /// - A boolean (`true` if payment is pending, `false` if already paid).
    /// - The identity data of the buyer (`IdentityPublicData`).
    /// - The identity data of the seller (`IdentityPublicData`).
    /// - A string representing the address to which the payment should be made.
    /// - The amount for the transaction (`u64`).
    ///
    pub async fn waiting_for_payment(
        &self,
        bill_keys: &BillKeys,
    ) -> Result<(bool, IdentityPublicData, IdentityPublicData, String, u64)> {
        let last_block = self.get_latest_block();
        let last_version_block_sell = self.get_last_version_block_with_operation_code(Sell);
        let identity_buyer = IdentityPublicData::new_empty();
        let identity_seller = IdentityPublicData::new_empty();

        if self.exist_block_with_operation_code(Sell.clone())
            && last_block.id == last_version_block_sell.id
        {
            let block_data_decrypted =
                last_version_block_sell.get_decrypted_block_data(bill_keys)?;

            let buyer: IdentityPublicData = serde_json::from_slice(&hex::decode(
                &extract_after_phrase(&block_data_decrypted, SOLD_TO).ok_or(
                    Error::InvalidBlockdata(String::from("Sell: No buyer found")),
                )?,
            )?)?;
            let seller: IdentityPublicData = serde_json::from_slice(&hex::decode(
                &extract_after_phrase(&block_data_decrypted, SOLD_BY).ok_or(
                    Error::InvalidBlockdata(String::from("Sell: No seller found")),
                )?,
            )?)?;

            let amount: u64 = extract_after_phrase(&block_data_decrypted, AMOUNT)
                .ok_or(Error::InvalidBlockdata(String::from(
                    "Sell: No amount found",
                )))?
                .parse()
                .map_err(|_| {
                    Error::InvalidBlockdata(String::from("Sell: Amount was no valid number"))
                })?;

            let bill = self.get_first_version_bill(bill_keys)?;

            let address_to_pay = Self::get_address_to_pay_for_block_sell(
                last_version_block_sell.clone(),
                bill,
                bill_keys,
            );

            let address_to_pay_for_async = address_to_pay.clone();

            let (paid, _amount) =
                external::bitcoin::check_if_paid(address_to_pay_for_async, amount).await;

            Ok((!paid, buyer, seller, address_to_pay, amount))
        } else {
            Ok((false, identity_buyer, identity_seller, String::new(), 0))
        }
    }

    /// This function checks if the payment deadline associated with the most recent sell block
    /// has passed.
    /// # Returns
    ///
    /// - `true` if the payment deadline for the last sell block has passed.
    /// - `false` if no sell block exists or the deadline has not passed.
    ///
    pub fn check_if_payment_deadline_has_passed(&self, current_timestamp: i64) -> bool {
        if self.exist_block_with_operation_code(Sell) {
            let last_version_block_sell = self.get_last_version_block_with_operation_code(Sell);
            let timestamp = last_version_block_sell.timestamp;

            let period: i64 = (86400 * 2) as i64; // 2 days deadline
            let difference = current_timestamp - timestamp;
            difference > period
        } else {
            false
        }
    }

    /// This function verifies whether the last block that involves a "Sell" operation
    /// has been paid. It decrypts the block's data to extract the amount and the recipient's payment address,
    /// then checks the payment status by querying an external Bitcoin service.
    ///
    /// # Returns
    ///
    /// `true` if the payment has been made, otherwise `false`. If no "Sell" block exists, it returns `false`.
    ///
    async fn check_if_last_sell_block_is_paid(&self, bill_keys: &BillKeys) -> bool {
        if self.exist_block_with_operation_code(Sell) {
            let last_version_block_sell = self.get_last_version_block_with_operation_code(Sell);

            let key: Rsa<Private> =
                Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
            let bytes = hex::decode(last_version_block_sell.data.clone()).unwrap();
            let decrypted_bytes = decrypt_bytes(&bytes, &key);
            let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

            let part_without_sold_to = block_data_decrypted
                .split(SOLD_TO)
                .collect::<Vec<&str>>()
                .get(1)
                .unwrap()
                .to_string();

            let part_with_seller_and_amount = part_without_sold_to
                .clone()
                .split(SOLD_BY)
                .collect::<Vec<&str>>()
                .get(1)
                .unwrap()
                .to_string();

            let amount: u64 = part_with_seller_and_amount
                .clone()
                .split(AMOUNT)
                .collect::<Vec<&str>>()
                .get(1)
                .unwrap()
                .to_string()
                .parse()
                .unwrap();

            let bill = self.get_first_version_bill(bill_keys).unwrap();

            let address_to_pay = Self::get_address_to_pay_for_block_sell(
                last_version_block_sell.clone(),
                bill,
                bill_keys,
            );

            external::bitcoin::check_if_paid(address_to_pay, amount)
                .await
                .0
        } else {
            false
        }
    }

    /// This function computes the Bitcoin payment address associated with a specific block sell.
    /// It decrypts and processes the data from the last version of the block sell, extracts
    /// relevant seller information, and combines public keys to generate the final payment address.
    ///
    /// # Parameters
    ///
    /// - `last_version_block_sell`: The most recent block sell version, containing encrypted
    ///   transaction data and the associated bill name.
    /// - `bill`: The `BitcreditBill` containing the public key associated with the transaction.
    ///
    /// # Returns
    ///
    /// A `String` representing the Bitcoin payment address (P2PKH format) for the transaction.
    ///
    fn get_address_to_pay_for_block_sell(
        last_version_block_sell: Block,
        bill: BitcreditBill,
        bill_keys: &BillKeys,
    ) -> String {
        let public_key_bill = bitcoin::PublicKey::from_str(&bill.public_key).unwrap();

        let key: Rsa<Private> =
            Rsa::private_key_from_pem(bill_keys.private_key_pem.as_bytes()).unwrap();
        let bytes = hex::decode(last_version_block_sell.data.clone()).unwrap();
        let decrypted_bytes = decrypt_bytes(&bytes, &key);
        let block_data_decrypted = String::from_utf8(decrypted_bytes).unwrap();

        let part_without_sold_to = block_data_decrypted
            .split(SOLD_TO)
            .collect::<Vec<&str>>()
            .get(1)
            .unwrap()
            .to_string();

        let part_with_seller_and_amount = part_without_sold_to
            .clone()
            .split(SOLD_BY)
            .collect::<Vec<&str>>()
            .get(1)
            .unwrap()
            .to_string();

        let part_with_seller = part_with_seller_and_amount
            .clone()
            .split(AMOUNT)
            .collect::<Vec<&str>>()
            .first()
            .unwrap()
            .to_string();

        let seller_bill_u8 = hex::decode(part_with_seller).unwrap();
        let seller_bill: IdentityPublicData = serde_json::from_slice(&seller_bill_u8).unwrap();

        let public_key_seller = seller_bill.bitcoin_public_key;
        let public_key_bill_seller = bitcoin::PublicKey::from_str(&public_key_seller).unwrap();

        let public_key_bill = public_key_bill
            .inner
            .combine(&public_key_bill_seller.inner)
            .unwrap();
        let pub_key_bill = bitcoin::PublicKey::new(public_key_bill);

        bitcoin::Address::p2pkh(pub_key_bill, CONFIG.bitcoin_network()).to_string()
    }

    /// This function extracts the first block's data, decrypts it using the private key
    /// associated with the bill, and then deserializes the decrypted data into a `BitcreditBill`
    /// object.
    ///
    /// # Arguments
    /// * `bill_keys` - The keys for the bill.
    ///
    /// # Returns
    ///
    /// * `BitcreditBill` - The first version of the bill
    ///
    pub fn get_first_version_bill(&self, bill_keys: &BillKeys) -> Result<BitcreditBill> {
        let first_block_data = &self.get_first_block();
        let decrypted_bytes = first_block_data.get_decrypted_block_bytes(bill_keys)?;
        let bill_first_version: BitcreditBill = from_slice(&decrypted_bytes)?;
        Ok(bill_first_version)
    }

    /// This function iterates over the list of blocks in the chain and returns the first block
    /// that matches the provided `id`. If no block is found with the given ID, the function
    /// returns a clone of the first block in the chain as a fallback.
    /// # Arguments
    ///
    /// * `id` - A `u64` representing the ID of the block to retrieve.
    ///
    /// # Returns
    ///
    /// * `Block` - The block corresponding to the given `id`, or the first block in the chain
    ///   if no match is found.
    ///
    pub fn get_block_by_id(&self, id: u64) -> Block {
        let mut block = self.get_first_block().clone();
        for b in &self.blocks {
            if b.id == id {
                block = b.clone();
            }
        }
        block
    }

    /// This function compares the latest block ID of the local chain with that
    /// of the `other_chain`. If the `other_chain` is ahead, it attempts to add missing
    /// blocks from the `other_chain` to the local chain. If the addition of a block
    /// fails or the resulting chain becomes invalid, the synchronization is aborted.
    ///
    /// # Parameters
    /// - `other_chain: Chain`  
    ///   The chain to compare and synchronize with.
    ///
    /// # Returns
    /// `bool` - whether the given chain needs to be persisted locally after this comparison
    ///
    pub fn compare_chain(&mut self, other_chain: Chain) -> bool {
        let local_chain_last_id = self.get_latest_block().id;
        let other_chain_last_id = other_chain.get_latest_block().id;
        let mut needs_to_persist = false;

        // if it's not the same id, and the local chain is shorter
        if !(local_chain_last_id.eq(&other_chain_last_id)
            || local_chain_last_id > other_chain_last_id)
        {
            let difference_in_id = other_chain_last_id - local_chain_last_id;
            for block_id in 1..difference_in_id + 1 {
                let block = other_chain.get_block_by_id(local_chain_last_id + block_id);
                let try_add_block = self.try_add_block(block);
                if try_add_block && self.is_chain_valid() {
                    needs_to_persist = true;
                    continue;
                } else {
                    return false;
                }
            }
        }
        needs_to_persist
    }

    /// This function iterates over all the blocks in the blockchain, extracts the nodes
    /// from each block, and compiles a unique list of non-empty nodes. Duplicate nodes
    /// are ignored.
    ///
    /// # Returns
    /// `Vec<String>`:  
    /// - A vector containing the unique identifiers of nodes associated with the bill.
    ///
    pub fn get_all_nodes_from_bill(&self, bill_keys: &BillKeys) -> Result<Vec<String>> {
        let mut nodes: Vec<String> = Vec::new();
        let bill = self.get_first_version_bill(bill_keys)?;

        for block in &self.blocks {
            let nodes_in_block = block.get_nodes_from_block(&bill, bill_keys)?;
            for node in nodes_in_block {
                if !node.is_empty() && !nodes.contains(&node) {
                    nodes.push(node);
                }
            }
        }
        Ok(nodes)
    }

    /// This function determines the drawer of the bill by evaluating the following conditions:
    /// 1. If the drawer's name is not empty, it directly returns the drawer.
    /// 2. If the bill is directed to the payee (`to_payee` is `true`), it assigns the payee as the drawer.
    /// 3. Otherwise, the drawee is assigned as the drawer.
    ///
    /// # Returns
    /// `IdentityPublicData`:  
    /// - The identity data of the drawer, payee, or drawee depending on the evaluated conditions.
    ///
    pub fn get_drawer(&self, bill_keys: &BillKeys) -> Result<IdentityPublicData> {
        let drawer: IdentityPublicData;
        let bill = self.get_first_version_bill(bill_keys)?;
        if !bill.drawer.name.is_empty() {
            drawer = bill.drawer.clone();
        } else if bill.to_payee {
            drawer = bill.payee.clone();
        } else {
            drawer = bill.drawee.clone();
        }
        Ok(drawer)
    }
}

/// This function performs a series of checks to ensure the integrity of the current block
/// in relation to the previous block in the blockchain. These checks include verifying
/// the hash chain, sequential IDs, hash validity, and block signature.
///
/// # Parameters
/// - `block`: A reference to the current `Block` that needs validation.
/// - `previous_block`: A reference to the previous `Block` in the chain for comparison.
///
/// # Returns
/// `bool`:
/// - `true` if the block is valid.
/// - `false` if any of the validation checks fail.
///
fn is_block_valid(block: &Block, previous_block: &Block) -> bool {
    if block.previous_hash != previous_block.hash {
        warn!("block with id: {} has wrong previous hash", block.id);
        return false;
    } else if block.id != &previous_block.id + 1 {
        warn!(
            "block with id: {} is not the next block after the latest: {}",
            block.id, previous_block.id
        );
        return false;
    } else if hex::encode(calculate_hash(
        &block.id,
        &block.bill_name,
        &block.previous_hash,
        &block.data,
        &block.timestamp,
        &block.public_key,
        &block.operation_code,
    )) != block.hash
    {
        warn!("block with id: {} has invalid hash", block.id);
        return false;
    } else if !block.verify() {
        warn!("block with id: {} has invalid signature", block.id);
        return false;
    }
    true
}
