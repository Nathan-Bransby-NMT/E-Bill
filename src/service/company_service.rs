use super::Result;
use crate::blockchain::company::{
    CompanyAddSignatoryBlockData, CompanyBlock, CompanyBlockchain, CompanyCreateBlockData,
    CompanyRemoveSignatoryBlockData, CompanyUpdateBlockData, SignatoryType,
};
use crate::blockchain::identity::{
    IdentityAddSignatoryBlockData, IdentityBlock, IdentityCreateCompanyBlockData,
    IdentityRemoveSignatoryBlockData,
};
use crate::blockchain::Blockchain;
use crate::persistence::company::{CompanyChainStoreApi, CompanyStoreApi};
use crate::persistence::identity::IdentityChainStoreApi;
use crate::util::BcrKeys;
use crate::{
    error,
    persistence::{file_upload::FileUploadStoreApi, identity::IdentityStoreApi, ContactStoreApi},
    util,
    web::data::File,
};
use async_trait::async_trait;
use borsh_derive::{self, BorshDeserialize, BorshSerialize};
use log::info;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[async_trait]
pub trait CompanyServiceApi: Send + Sync {
    /// Get a list of companies
    async fn get_list_of_companies(&self) -> Result<Vec<CompanyToReturn>>;

    /// Get a company by id
    async fn get_company_by_id(&self, id: &str) -> Result<CompanyToReturn>;

    /// Create a new company
    async fn create_company(
        &self,
        name: String,
        country_of_registration: String,
        city_of_registration: String,
        postal_address: String,
        email: String,
        registration_number: String,
        registration_date: String,
        proof_of_registration_file_upload_id: Option<String>,
        logo_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<CompanyToReturn>;

    /// Changes the given company fields for the given company, if they are set
    async fn edit_company(
        &self,
        id: &str,
        name: Option<String>,
        email: Option<String>,
        postal_address: Option<String>,
        logo_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<()>;

    /// Adds another signatory to the given company
    async fn add_signatory(
        &self,
        id: &str,
        signatory_node_id: String,
        timestamp: u64,
    ) -> Result<()>;

    /// Removes a signatory from the given company
    async fn remove_signatory(
        &self,
        id: &str,
        signatory_node_id: String,
        timestamp: u64,
    ) -> Result<()>;

    /// Encrypts and saves the given uploaded file, returning the file name, as well as the hash of
    /// the unencrypted file
    async fn encrypt_and_save_uploaded_file(
        &self,
        file_name: &str,
        file_bytes: &[u8],
        id: &str,
        public_key: &str,
    ) -> Result<File>;

    /// opens and decrypts the attached file from the given company
    async fn open_and_decrypt_file(
        &self,
        id: &str,
        file_name: &str,
        private_key: &str,
    ) -> Result<Vec<u8>>;
}

/// The company service is responsible for managing the companies
#[derive(Clone)]
pub struct CompanyService {
    store: Arc<dyn CompanyStoreApi>,
    file_upload_store: Arc<dyn FileUploadStoreApi>,
    identity_store: Arc<dyn IdentityStoreApi>,
    contact_store: Arc<dyn ContactStoreApi>,
    identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
    company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
}

impl CompanyService {
    pub fn new(
        store: Arc<dyn CompanyStoreApi>,
        file_upload_store: Arc<dyn FileUploadStoreApi>,
        identity_store: Arc<dyn IdentityStoreApi>,
        contact_store: Arc<dyn ContactStoreApi>,
        identity_blockchain_store: Arc<dyn IdentityChainStoreApi>,
        company_blockchain_store: Arc<dyn CompanyChainStoreApi>,
    ) -> Self {
        Self {
            store,
            file_upload_store,
            identity_store,
            contact_store,
            identity_blockchain_store,
            company_blockchain_store,
        }
    }

    async fn process_upload_file(
        &self,
        upload_id: &Option<String>,
        id: &str,
        public_key: &str,
    ) -> Result<Option<File>> {
        if let Some(upload_id) = upload_id {
            let files = self
                .file_upload_store
                .read_temp_upload_files(upload_id)
                .await?;
            if !files.is_empty() {
                let (file_name, file_bytes) = &files[0];
                let file = self
                    .encrypt_and_save_uploaded_file(file_name, file_bytes, id, public_key)
                    .await?;
                return Ok(Some(file));
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl CompanyServiceApi for CompanyService {
    async fn get_list_of_companies(&self) -> Result<Vec<CompanyToReturn>> {
        let results = self.store.get_all().await?;
        let companies: Vec<CompanyToReturn> = results
            .into_iter()
            .map(|(id, (company, keys))| CompanyToReturn::from(id, company, keys))
            .collect();
        Ok(companies)
    }

    async fn get_company_by_id(&self, id: &str) -> Result<CompanyToReturn> {
        if !self.store.exists(id).await {
            return Err(super::Error::Validation(format!(
                "No company with id: {id} found",
            )));
        }

        let company = self.store.get(id).await?;
        let keys = self.store.get_key_pair(id).await?;
        Ok(CompanyToReturn::from(id.to_owned(), company, keys))
    }

    async fn create_company(
        &self,
        name: String,
        country_of_registration: String,
        city_of_registration: String,
        postal_address: String,
        email: String,
        registration_number: String,
        registration_date: String,
        proof_of_registration_file_upload_id: Option<String>,
        logo_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<CompanyToReturn> {
        let keys = BcrKeys::new();
        let private_key = keys.get_private_key_string();
        let public_key = keys.get_public_key();

        let id = util::sha256_hash(public_key.as_bytes());

        let company_keys = CompanyKeys {
            private_key: private_key.to_string(),
            public_key: public_key.clone(),
        };

        let full_identity = self.identity_store.get_full().await?;

        let proof_of_registration_file = self
            .process_upload_file(&proof_of_registration_file_upload_id, &id, &public_key)
            .await?;

        let logo_file = self
            .process_upload_file(&logo_file_upload_id, &id, &public_key)
            .await?;

        self.store.save_key_pair(&id, &company_keys).await?;
        let company = Company {
            name,
            country_of_registration,
            city_of_registration,
            postal_address,
            email,
            registration_number,
            registration_date,
            proof_of_registration_file,
            logo_file,
            signatories: vec![full_identity.identity.node_id.clone()], // add caller as signatory
        };
        self.store.insert(&id, &company).await?;

        let company_to_return =
            CompanyToReturn::from(id.clone(), company.clone(), company_keys.clone());
        let company_chain = CompanyBlockchain::new(
            &CompanyCreateBlockData::from(company_to_return),
            &full_identity.key_pair,
            &company_keys,
            timestamp,
        )?;
        let create_company_block = company_chain.get_first_block();

        let previous_block = self.identity_blockchain_store.get_latest_block().await?;
        let new_block = IdentityBlock::create_block_for_create_company(
            &previous_block,
            &IdentityCreateCompanyBlockData {
                company_id: id.clone(),
                block_hash: create_company_block.hash.clone(),
            },
            &full_identity.key_pair,
            timestamp,
        )?;

        self.company_blockchain_store
            .add_block(&id, create_company_block)
            .await?;
        self.identity_blockchain_store.add_block(&new_block).await?;

        // clean up temporary file uploads, if there are any, logging any errors
        for upload_id in [proof_of_registration_file_upload_id, logo_file_upload_id]
            .iter()
            .flatten()
        {
            if let Err(e) = self
                .file_upload_store
                .remove_temp_upload_folder(upload_id)
                .await
            {
                error!("Error while cleaning up temporary file uploads for {upload_id}: {e}");
            }
        }

        Ok(CompanyToReturn::from(id, company, company_keys))
    }

    async fn edit_company(
        &self,
        id: &str,
        name: Option<String>,
        email: Option<String>,
        postal_address: Option<String>,
        logo_file_upload_id: Option<String>,
        timestamp: u64,
    ) -> Result<()> {
        if !self.store.exists(id).await {
            return Err(super::Error::Validation(format!(
                "No company with id: {id} found",
            )));
        }
        let full_identity = self.identity_store.get_full().await?;
        let node_id = full_identity.identity.node_id;
        let mut company = self.store.get(id).await?;
        let company_keys = self.store.get_key_pair(id).await?;

        if !company.signatories.contains(&node_id.to_string()) {
            return Err(super::Error::Validation(String::from(
                "Caller must be signatory for company",
            )));
        }

        if let Some(ref name_to_set) = name {
            company.name = name_to_set.clone();
        }
        if let Some(ref email_to_set) = email {
            company.email = email_to_set.clone();
        }
        if let Some(ref postal_address_to_set) = postal_address {
            company.postal_address = postal_address_to_set.clone();
        }
        let logo_file = self
            .process_upload_file(
                &logo_file_upload_id,
                id,
                &full_identity.key_pair.get_public_key(),
            )
            .await?;
        company.logo_file = logo_file;

        self.store.update(id, &company).await?;

        let previous_block = self.company_blockchain_store.get_latest_block(id).await?;
        let new_block = CompanyBlock::create_block_for_update(
            id.to_owned(),
            &previous_block,
            &CompanyUpdateBlockData {
                name,
                email,
                postal_address,
                logo_file_upload_id: logo_file_upload_id.clone(),
            },
            &full_identity.key_pair,
            &company_keys,
            timestamp,
        )?;
        self.company_blockchain_store
            .add_block(id, &new_block)
            .await?;

        if let Some(upload_id) = logo_file_upload_id {
            if let Err(e) = self
                .file_upload_store
                .remove_temp_upload_folder(&upload_id)
                .await
            {
                error!("Error while cleaning up temporary file uploads for {upload_id}: {e}");
            }
        }

        Ok(())
    }

    async fn add_signatory(
        &self,
        id: &str,
        signatory_node_id: String,
        timestamp: u64,
    ) -> Result<()> {
        if !self.store.exists(id).await {
            return Err(super::Error::Validation(format!(
                "No company with id: {id} found.",
            )));
        }
        let full_identity = self.identity_store.get_full().await?;
        let contacts = self.contact_store.get_map().await?;
        let is_in_contacts = contacts
            .iter()
            .any(|(_name, identity)| identity.node_id == signatory_node_id);
        if !is_in_contacts {
            return Err(super::Error::Validation(format!(
                "Node Id {signatory_node_id} is not in the contacts.",
            )));
        }

        let mut company = self.store.get(id).await?;
        let company_keys = self.store.get_key_pair(id).await?;
        if company.signatories.contains(&signatory_node_id) {
            return Err(super::Error::Validation(format!(
                "Node Id {signatory_node_id} is already a signatory.",
            )));
        }
        company.signatories.push(signatory_node_id.clone());
        self.store.update(id, &company).await?;

        let previous_block = self.company_blockchain_store.get_latest_block(id).await?;
        let new_block = CompanyBlock::create_block_for_add_signatory(
            id.to_owned(),
            &previous_block,
            &CompanyAddSignatoryBlockData {
                signatory: signatory_node_id.clone(),
                t: SignatoryType::Solo,
            },
            &full_identity.key_pair,
            &company_keys,
            &signatory_node_id,
            timestamp,
        )?;

        let previous_identity_block = self.identity_blockchain_store.get_latest_block().await?;
        let new_identity_block = IdentityBlock::create_block_for_add_signatory(
            &previous_identity_block,
            &IdentityAddSignatoryBlockData {
                company_id: id.to_owned(),
                block_hash: new_block.hash.clone(),
                block_id: new_block.id,
                signatory: signatory_node_id,
            },
            &full_identity.key_pair,
            timestamp,
        )?;
        self.company_blockchain_store
            .add_block(id, &new_block)
            .await?;
        self.identity_blockchain_store
            .add_block(&new_identity_block)
            .await?;

        Ok(())
    }

    async fn remove_signatory(
        &self,
        id: &str,
        signatory_node_id: String,
        timestamp: u64,
    ) -> Result<()> {
        if !self.store.exists(id).await {
            return Err(super::Error::Validation(format!(
                "No company with id: {id} found.",
            )));
        }

        let full_identity = self.identity_store.get_full().await?;
        let mut company = self.store.get(id).await?;
        let company_keys = self.store.get_key_pair(id).await?;
        if company.signatories.len() == 1 {
            return Err(super::Error::Validation(String::from(
                "Can't remove last signatory.",
            )));
        }
        if !company.signatories.contains(&signatory_node_id) {
            return Err(super::Error::Validation(format!(
                "Node id {signatory_node_id} is not a signatory.",
            )));
        }

        company.signatories.retain(|i| i != &signatory_node_id);
        self.store.update(id, &company).await?;

        if full_identity.identity.node_id == signatory_node_id {
            info!("Removing self from company {id}");
            let _ = self.file_upload_store.delete_attached_files(id).await;
            self.store.remove(id).await?;
        }

        let previous_block = self.company_blockchain_store.get_latest_block(id).await?;
        let new_block = CompanyBlock::create_block_for_remove_signatory(
            id.to_owned(),
            &previous_block,
            &CompanyRemoveSignatoryBlockData {
                signatory: signatory_node_id.clone(),
            },
            &full_identity.key_pair,
            &company_keys,
            timestamp,
        )?;

        let previous_identity_block = self.identity_blockchain_store.get_latest_block().await?;
        let new_identity_block = IdentityBlock::create_block_for_remove_signatory(
            &previous_identity_block,
            &IdentityRemoveSignatoryBlockData {
                company_id: id.to_owned(),
                block_hash: new_block.hash.clone(),
                block_id: new_block.id,
                signatory: signatory_node_id.clone(),
            },
            &full_identity.key_pair,
            timestamp,
        )?;

        self.company_blockchain_store
            .add_block(id, &new_block)
            .await?;
        self.identity_blockchain_store
            .add_block(&new_identity_block)
            .await?;

        if full_identity.identity.node_id == signatory_node_id {
            info!("Removed self from company {id} - deleting company chain");
            if let Err(e) = self.company_blockchain_store.remove(id).await {
                error!("Could not delete local company chain for {id}: {e}");
            }
        }

        Ok(())
    }

    async fn encrypt_and_save_uploaded_file(
        &self,
        file_name: &str,
        file_bytes: &[u8],
        id: &str,
        public_key: &str,
    ) -> Result<File> {
        let file_hash = util::sha256_hash(file_bytes);
        let encrypted = util::crypto::encrypt_ecies(file_bytes, public_key)?;
        self.file_upload_store
            .save_attached_file(&encrypted, id, file_name)
            .await?;
        info!("Saved company file {file_name} with hash {file_hash} for company {id}");
        Ok(File {
            name: file_name.to_owned(),
            hash: file_hash,
        })
    }

    async fn open_and_decrypt_file(
        &self,
        id: &str,
        file_name: &str,
        private_key: &str,
    ) -> Result<Vec<u8>> {
        let read_file = self
            .file_upload_store
            .open_attached_file(id, file_name)
            .await?;
        let decrypted = util::crypto::decrypt_ecies(&read_file, private_key)?;
        Ok(decrypted)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompanyToReturn {
    pub id: String,
    pub name: String,
    pub country_of_registration: String,
    pub city_of_registration: String,
    pub postal_address: String,
    pub email: String,
    pub registration_number: String,
    pub registration_date: String,
    pub proof_of_registration_file: Option<File>,
    pub logo_file: Option<File>,
    pub signatories: Vec<String>,
    pub public_key: String,
}

impl CompanyToReturn {
    pub fn from(id: String, company: Company, company_keys: CompanyKeys) -> CompanyToReturn {
        CompanyToReturn {
            id,
            name: company.name,
            country_of_registration: company.country_of_registration,
            city_of_registration: company.city_of_registration,
            postal_address: company.postal_address,
            email: company.email,
            registration_number: company.registration_number,
            registration_date: company.registration_date,
            proof_of_registration_file: company.proof_of_registration_file,
            logo_file: company.logo_file,
            signatories: company.signatories,
            public_key: company_keys.public_key,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Serialize, Deserialize, Clone)]
pub struct Company {
    pub name: String,
    pub country_of_registration: String,
    pub city_of_registration: String,
    pub postal_address: String,
    pub email: String,
    pub registration_number: String,
    pub registration_date: String,
    pub proof_of_registration_file: Option<File>,
    pub logo_file: Option<File>,
    pub signatories: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct CompanyPublicData {
    pub id: String,
    pub name: String,
    pub postal_address: String,
    pub email: String,
    pub public_key: String,
}

impl CompanyPublicData {
    pub fn from_all(id: String, company: Company, company_keys: CompanyKeys) -> CompanyPublicData {
        CompanyPublicData {
            id,
            name: company.name,
            postal_address: company.postal_address,
            email: company.email,
            public_key: company_keys.public_key,
        }
    }
}

impl From<CompanyToReturn> for CompanyPublicData {
    fn from(company: CompanyToReturn) -> Self {
        Self {
            id: company.id,
            name: company.name,
            postal_address: company.postal_address,
            email: company.email,
            public_key: company.public_key,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct CompanyKeys {
    pub private_key: String,
    pub public_key: String,
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        blockchain::{identity::IdentityBlockchain, Blockchain},
        persistence::{
            self,
            company::{MockCompanyChainStoreApi, MockCompanyStoreApi},
            contact::MockContactStoreApi,
            file_upload::MockFileUploadStoreApi,
            identity::{MockIdentityChainStoreApi, MockIdentityStoreApi},
        },
        service::{
            contact_service::IdentityPublicData,
            identity_service::{Identity, IdentityWithAll},
        },
        tests::test::{TEST_PRIVATE_KEY_SECP, TEST_PUB_KEY_SECP},
    };
    use mockall::predicate::{always, eq};
    use std::collections::HashMap;
    use util::BcrKeys;

    fn get_service(
        mock_storage: MockCompanyStoreApi,
        mock_file_upload_storage: MockFileUploadStoreApi,
        mock_identity_storage: MockIdentityStoreApi,
        mock_contacts_storage: MockContactStoreApi,
        mock_identity_chain_storage: MockIdentityChainStoreApi,
        mock_company_chain_storage: MockCompanyChainStoreApi,
    ) -> CompanyService {
        CompanyService::new(
            Arc::new(mock_storage),
            Arc::new(mock_file_upload_storage),
            Arc::new(mock_identity_storage),
            Arc::new(mock_contacts_storage),
            Arc::new(mock_identity_chain_storage),
            Arc::new(mock_company_chain_storage),
        )
    }

    fn get_storages() -> (
        MockCompanyStoreApi,
        MockFileUploadStoreApi,
        MockIdentityStoreApi,
        MockContactStoreApi,
        MockIdentityChainStoreApi,
        MockCompanyChainStoreApi,
    ) {
        (
            MockCompanyStoreApi::new(),
            MockFileUploadStoreApi::new(),
            MockIdentityStoreApi::new(),
            MockContactStoreApi::new(),
            MockIdentityChainStoreApi::new(),
            MockCompanyChainStoreApi::new(),
        )
    }

    pub fn get_baseline_company_data() -> (String, (Company, CompanyKeys)) {
        (
            "some_id".to_string(),
            (
                Company {
                    name: "some_name".to_string(),
                    country_of_registration: "AT".to_string(),
                    city_of_registration: "Vienna".to_string(),
                    postal_address: "some address".to_string(),
                    email: "company@example.com".to_string(),
                    registration_number: "some_number".to_string(),
                    registration_date: "2012-01-01".to_string(),
                    proof_of_registration_file: None,
                    logo_file: None,
                    signatories: vec![],
                },
                CompanyKeys {
                    private_key: TEST_PRIVATE_KEY_SECP.to_string(),
                    public_key: TEST_PUB_KEY_SECP.to_string(),
                },
            ),
        )
    }

    fn get_valid_company_block() -> CompanyBlock {
        let (id, (company, company_keys)) = get_baseline_company_data();
        let to_return = CompanyToReturn::from(id, company, company_keys.clone());

        CompanyBlockchain::new(
            &CompanyCreateBlockData::from(to_return),
            &BcrKeys::new(),
            &company_keys,
            1731593928,
        )
        .unwrap()
        .get_latest_block()
        .to_owned()
    }

    #[tokio::test]
    async fn get_list_of_companies_baseline() {
        let (
            mut storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_get_all().returning(|| {
            let mut map = HashMap::new();
            let company_data = get_baseline_company_data();
            map.insert(company_data.0, company_data.1);
            Ok(map)
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let res = service.get_list_of_companies().await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().len(), 1);
        assert_eq!(res.as_ref().unwrap()[0].id, "some_id".to_string());
        assert_eq!(
            res.as_ref().unwrap()[0].public_key,
            TEST_PUB_KEY_SECP.to_string()
        );
    }

    #[tokio::test]
    async fn get_list_of_companies_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_get_all().returning(|| {
            Err(persistence::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "test error",
            )))
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service.get_list_of_companies().await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn get_company_by_id_baseline() {
        let (
            mut storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage
            .expect_get()
            .returning(|_| Ok(get_baseline_company_data().1 .0));
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1 .1));
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let res = service.get_company_by_id("some_id").await;
        assert!(res.is_ok());
        assert_eq!(res.as_ref().unwrap().id, "some_id".to_string());
        assert_eq!(
            res.as_ref().unwrap().public_key,
            TEST_PUB_KEY_SECP.to_string()
        );
    }

    #[tokio::test]
    async fn get_company_by_id_fails_if_company_doesnt_exist() {
        let (
            mut storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service.get_company_by_id("some_id").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn get_company_by_id_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            Err(persistence::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "test error",
            )))
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service.get_company_by_id("some_id").await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn create_company_baseline() {
        let (
            mut storage,
            mut file_upload_store,
            mut identity_store,
            contact_store,
            mut identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        company_chain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        file_upload_store
            .expect_save_attached_file()
            .returning(|_, _, _| Ok(()));
        storage.expect_save_key_pair().returning(|_, _| Ok(()));
        storage.expect_insert().returning(|_, _| Ok(()));
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        file_upload_store
            .expect_read_temp_upload_files()
            .returning(|_| {
                Ok(vec![(
                    "some_file".to_string(),
                    "hello_world".as_bytes().to_vec(),
                )])
            });
        file_upload_store
            .expect_remove_temp_upload_folder()
            .returning(|_| Ok(()));
        identity_chain_store
            .expect_get_latest_block()
            .returning(|| {
                let identity = Identity::new_empty();
                Ok(
                    IdentityBlockchain::new(&identity.into(), &BcrKeys::new(), 1731593928)
                        .unwrap()
                        .get_latest_block()
                        .clone(),
                )
            });
        identity_chain_store
            .expect_add_block()
            .returning(|_| Ok(()));

        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let res = service
            .create_company(
                "name".to_string(),
                "AT".to_string(),
                "Vienna".to_string(),
                "some Address".to_string(),
                "company@example.com".to_string(),
                "some_number".to_string(),
                "2012-01-01".to_string(),
                Some("some_file_id".to_string()),
                Some("some_other_file_id".to_string()),
                1731593928,
            )
            .await;
        assert!(res.is_ok());
        assert!(!res.as_ref().unwrap().id.is_empty());
        assert_eq!(res.as_ref().unwrap().name, "name".to_string());
        assert_eq!(
            res.as_ref()
                .unwrap()
                .proof_of_registration_file
                .as_ref()
                .unwrap()
                .name,
            "some_file".to_string()
        );
        assert_eq!(
            res.as_ref().unwrap().logo_file.as_ref().unwrap().name,
            "some_file".to_string()
        );
        assert!(!res.as_ref().unwrap().public_key.is_empty());
    }

    #[tokio::test]
    async fn create_company_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_save_key_pair().returning(|_, _| Ok(()));
        storage.expect_insert().returning(|_, _| {
            Err(persistence::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "test error",
            )))
        });
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .create_company(
                "name".to_string(),
                "AT".to_string(),
                "Vienna".to_string(),
                "some Address".to_string(),
                "company@example.com".to_string(),
                "some_number".to_string(),
                "2012-01-01".to_string(),
                None,
                None,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn edit_company_baseline() {
        let keys = BcrKeys::new();
        let node_id = keys.get_public_key();
        let (
            mut storage,
            mut file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        company_chain_store
            .expect_get_latest_block()
            .returning(|_| Ok(get_valid_company_block()));
        company_chain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        let node_id_clone = node_id.clone();
        storage.expect_get().returning(move |_| {
            let mut data = get_baseline_company_data().1 .0;
            data.signatories = vec![node_id_clone.clone()];
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1 .1));
        storage.expect_exists().returning(|_| true);
        storage.expect_update().returning(|_, _| Ok(()));
        file_upload_store
            .expect_save_attached_file()
            .returning(|_, _, _| Ok(()));
        identity_store.expect_get_full().returning(move || {
            let mut identity = Identity::new_empty();
            identity.node_id = node_id.clone();
            Ok(IdentityWithAll {
                identity,
                key_pair: keys.clone(),
            })
        });
        file_upload_store
            .expect_read_temp_upload_files()
            .returning(|_| {
                Ok(vec![(
                    "some_file".to_string(),
                    "hello_world".as_bytes().to_vec(),
                )])
            });
        file_upload_store
            .expect_remove_temp_upload_folder()
            .returning(|_| Ok(()));
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                "some_id",
                Some("name".to_string()),
                Some("some Address".to_string()),
                Some("company@example.com".to_string()),
                Some("some_file_id".to_string()),
                1731593928,
            )
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn edit_company_fails_if_company_doesnt_exist() {
        let (
            mut storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                "some_id",
                Some("name".to_string()),
                Some("some Address".to_string()),
                Some("company@example.com".to_string()),
                None,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn edit_company_fails_if_caller_is_not_signatory() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1 .0;
            data.signatories = vec!["some_other_dude".to_string()];
            Ok(data)
        });
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                "some_id",
                Some("name".to_string()),
                Some("some Address".to_string()),
                Some("company@example.com".to_string()),
                None,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn edit_company_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        let keys = BcrKeys::new();
        let node_id = keys.get_public_key();
        let node_id_clone = node_id.clone();
        storage.expect_get().returning(move |_| {
            let mut data = get_baseline_company_data().1 .0;
            data.signatories = vec![node_id_clone.clone()];
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1 .1));
        storage.expect_exists().returning(|_| true);
        storage.expect_update().returning(|_, _| {
            Err(persistence::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "test error",
            )))
        });
        identity_store.expect_get_full().returning(move || {
            let mut identity = Identity::new_empty();
            identity.node_id = node_id.clone();
            Ok(IdentityWithAll {
                identity,
                key_pair: keys.clone(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .edit_company(
                "some_id",
                Some("name".to_string()),
                Some("some Address".to_string()),
                Some("company@example.com".to_string()),
                None,
                1731593928,
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_baseline() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            mut contact_store,
            mut identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        let signatory_keys = BcrKeys::new();
        let signatory_node_id = signatory_keys.get_public_key();
        storage.expect_exists().returning(|_| true);
        storage.expect_update().returning(|_, _| Ok(()));
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1 .1));
        company_chain_store
            .expect_get_latest_block()
            .returning(|_| Ok(get_valid_company_block()));
        company_chain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        let signatory_node_id_clone = signatory_node_id.clone();
        contact_store.expect_get_map().returning(move || {
            let mut map = HashMap::new();
            let mut identity = IdentityPublicData::new_empty();
            identity.node_id = signatory_node_id_clone.clone();
            map.insert("my best friend".to_string(), identity);
            Ok(map)
        });
        storage
            .expect_get()
            .returning(|_| Ok(get_baseline_company_data().1 .0));
        identity_store.expect_get_full().returning(|| {
            let keys = BcrKeys::new();
            let mut identity = Identity::new_empty();
            identity.node_id = keys.get_public_key();
            Ok(IdentityWithAll {
                identity,
                key_pair: keys,
            })
        });
        identity_chain_store
            .expect_get_latest_block()
            .returning(|| {
                let identity = Identity::new_empty();
                Ok(
                    IdentityBlockchain::new(&identity.into(), &BcrKeys::new(), 1731593928)
                        .unwrap()
                        .get_latest_block()
                        .clone(),
                )
            });
        identity_chain_store
            .expect_add_block()
            .returning(|_| Ok(()));
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory("some_id", signatory_node_id, 1731593928)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn add_signatory_fails_if_signatory_not_in_contacts() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            mut contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        contact_store
            .expect_get_map()
            .returning(|| Ok(HashMap::new()));
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory("some_id", "new_signatory_node_id".to_string(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_fails_if_company_doesnt_exist() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory("some_id", "new_signatory_node_id".to_string(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_fails_if_signatory_is_already_signatory() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            mut contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        contact_store.expect_get_map().returning(|| {
            let mut map = HashMap::new();
            let mut identity = IdentityPublicData::new_empty();
            identity.node_id = "new_signatory_node_id".to_string();
            map.insert("my best friend".to_string(), identity);
            Ok(map)
        });
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1 .0;
            data.signatories.push("new_signatory_node_id".to_string());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1 .1));
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory("some_id", "new_signatory_node_id".to_string(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn add_signatory_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            mut contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        contact_store.expect_get_map().returning(|| {
            let mut map = HashMap::new();
            let mut identity = IdentityPublicData::new_empty();
            identity.node_id = "new_signatory_node_id".to_string();
            map.insert("my best friend".to_string(), identity);
            Ok(map)
        });
        storage.expect_update().returning(|_, _| {
            Err(persistence::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "test error",
            )))
        });
        storage
            .expect_get()
            .returning(|_| Ok(get_baseline_company_data().1 .0));
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1 .1));
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .add_signatory("some_id", "new_signatory_node_id".to_string(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_baseline() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            mut identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        company_chain_store
            .expect_get_latest_block()
            .returning(|_| Ok(get_valid_company_block()));
        company_chain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1 .0;
            data.signatories.push("new_signatory_node_id".to_string());
            data.signatories
                .push("some_other_dude_or_dudette".to_string());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1 .1));
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        storage.expect_update().returning(|_, _| Ok(()));
        identity_chain_store
            .expect_get_latest_block()
            .returning(|| {
                let identity = Identity::new_empty();
                Ok(
                    IdentityBlockchain::new(&identity.into(), &BcrKeys::new(), 1731593928)
                        .unwrap()
                        .get_latest_block()
                        .clone(),
                )
            });
        identity_chain_store
            .expect_add_block()
            .returning(|_| Ok(()));
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory("some_id", "new_signatory_node_id".to_string(), 1731593928)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn remove_signatory_fails_if_company_doesnt_exist() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| false);
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory("some_id", "new_signatory_node_id".to_string(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_removing_self_removes_company() {
        let keys = BcrKeys::new();
        let (
            mut storage,
            mut file_upload_store,
            mut identity_store,
            contact_store,
            mut identity_chain_store,
            mut company_chain_store,
        ) = get_storages();
        company_chain_store
            .expect_get_latest_block()
            .returning(|_| Ok(get_valid_company_block()));
        company_chain_store
            .expect_add_block()
            .returning(|_, _| Ok(()));
        company_chain_store.expect_remove().returning(|_| Ok(()));
        file_upload_store
            .expect_delete_attached_files()
            .returning(|_| Ok(()));
        storage.expect_exists().returning(|_| true);
        let keys_clone = keys.clone();
        storage.expect_get().returning(move |_| {
            let mut data = get_baseline_company_data().1 .0;
            data.signatories.push("the founder".to_string());
            data.signatories.push(keys_clone.clone().get_public_key());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1 .1));
        let keys_clone_clone = keys.clone();
        identity_store.expect_get_full().returning(move || {
            let mut identity = Identity::new_empty();
            identity.node_id = keys_clone_clone.clone().get_public_key();
            Ok(IdentityWithAll {
                identity,
                key_pair: keys_clone_clone.clone(),
            })
        });
        storage.expect_update().returning(|_, _| Ok(()));
        storage.expect_remove().returning(|_| Ok(()));
        let keys_clone2 = keys.clone();
        identity_chain_store
            .expect_get_latest_block()
            .returning(move || {
                let identity = Identity::new_empty();
                Ok(
                    IdentityBlockchain::new(&identity.into(), &keys_clone2, 1731593928)
                        .unwrap()
                        .get_latest_block()
                        .clone(),
                )
            });
        identity_chain_store
            .expect_add_block()
            .returning(|_| Ok(()));
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory("some_id", keys.get_public_key(), 1731593928)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn remove_signatory_fails_if_signatory_is_not_in_company() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1 .0;
            data.signatories
                .push("some_other_dude_or_dudette".to_string());
            data.signatories.push("the_founder".to_string());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1 .1));
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory("some_id", "new_signatory_node_id".to_string(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_fails_on_last_signatory() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1 .0;
            data.signatories.push("the_founder".to_string());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1 .1));
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory("some_id", "new_signatory_node_id".to_string(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn remove_signatory_propagates_persistence_errors() {
        let (
            mut storage,
            file_upload_store,
            mut identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        storage.expect_exists().returning(|_| true);
        storage.expect_get().returning(|_| {
            let mut data = get_baseline_company_data().1 .0;
            data.signatories.push("new_signatory_node_id".to_string());
            data.signatories
                .push("some_other_dude_or_dudette".to_string());
            Ok(data)
        });
        storage
            .expect_get_key_pair()
            .returning(|_| Ok(get_baseline_company_data().1 .1));
        identity_store.expect_get_full().returning(|| {
            let identity = Identity::new_empty();
            Ok(IdentityWithAll {
                identity,
                key_pair: BcrKeys::new(),
            })
        });
        storage.expect_update().returning(|_, _| {
            Err(persistence::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "test error",
            )))
        });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );
        let res = service
            .remove_signatory("some_id", "new_signatory_node_id".to_string(), 1731593928)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn save_encrypt_open_decrypt_compare_hashes() {
        let company_id = "00000000-0000-0000-0000-000000000000";
        let file_name = "file_00000000-0000-0000-0000-000000000000.pdf";
        let file_bytes = String::from("hello world").as_bytes().to_vec();
        let expected_encrypted =
            util::crypto::encrypt_ecies(&file_bytes, TEST_PUB_KEY_SECP).unwrap();

        let (
            storage,
            mut file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        file_upload_store
            .expect_save_attached_file()
            .with(always(), eq(company_id), eq(file_name))
            .times(1)
            .returning(|_, _, _| Ok(()));

        file_upload_store
            .expect_open_attached_file()
            .with(eq(company_id), eq(file_name))
            .times(1)
            .returning(move |_, _| Ok(expected_encrypted.clone()));
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        let file = service
            .encrypt_and_save_uploaded_file(file_name, &file_bytes, company_id, TEST_PUB_KEY_SECP)
            .await
            .unwrap();
        assert_eq!(
            file.hash,
            String::from("DULfJyE3WQqNxy3ymuhAChyNR3yufT88pmqvAazKFMG4")
        );
        assert_eq!(file.name, String::from(file_name));

        let decrypted = service
            .open_and_decrypt_file(company_id, file_name, TEST_PRIVATE_KEY_SECP)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&decrypted).unwrap(), "hello world");
    }

    #[tokio::test]
    async fn save_encrypt_propagates_write_file_error() {
        let (
            storage,
            mut file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        file_upload_store
            .expect_save_attached_file()
            .returning(|_, _, _| {
                Err(persistence::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "test error",
                )))
            });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        assert!(service
            .encrypt_and_save_uploaded_file("file_name", &[], "test", TEST_PUB_KEY_SECP)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn open_decrypt_propagates_read_file_error() {
        let (
            storage,
            mut file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        ) = get_storages();
        file_upload_store
            .expect_open_attached_file()
            .returning(|_, _| {
                Err(persistence::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "test error",
                )))
            });
        let service = get_service(
            storage,
            file_upload_store,
            identity_store,
            contact_store,
            identity_chain_store,
            company_chain_store,
        );

        assert!(service
            .open_and_decrypt_file("test", "test", TEST_PRIVATE_KEY_SECP)
            .await
            .is_err());
    }
}
