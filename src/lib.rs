use std::hash::Hash;
use std::str::FromStr;

use derive_more::From;
use derive_more::Into;
use near_primitives_core::borsh::BorshSerialize;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use solders_macros::pyhash;
use solders_macros::EnumIntoPy;

use near_crypto::ED25519PublicKey;
use near_crypto::ED25519SecretKey;
use near_primitives_core::hash::CryptoHash;

use near_primitives::{
    account::{
        AccessKey as AccessKeyOriginal, AccessKeyPermission as AccessKeyPermissionOriginal,
        FunctionCallPermission as FunctionCallPermissionOriginal,
    },
    delegate_action::{
        DelegateAction as DelegateActionOriginal,
        SignedDelegateAction as SignedDelegateActionOriginal,
    },
    transaction::{
        Action as ActionOriginal, AddKeyAction as AddKeyActionOriginal,
        CreateAccountAction as CreateAccountActionOriginal,
        DeleteAccountAction as DeleteAccountActionOriginal,
        DeleteKeyAction as DeleteKeyActionOriginal,
        DeployContractAction as DeployContractActionOriginal,
        FunctionCallAction as FunctionCallActionOriginal,
        SignedTransaction as SignedTransactionOriginal, StakeAction as StakeActionOriginal,
        Transaction as TransactionOriginal, TransferAction as TransferActionOriginal,
    },
    types::{AccountId, Balance, Nonce},
};

use near_crypto::{PublicKey, Signature};

pub type LogEntry = String;

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AccessKey {
    #[pyo3(get, set)]
    pub nonce: u64,
    pub permission: AccessKeyPermission,
}

impl From<AccessKey> for AccessKeyOriginal {
    fn from(value: AccessKey) -> Self {
        Self {
            nonce: value.nonce,
            permission: value.permission.into(),
        }
    }
}

impl From<AccessKeyOriginal> for AccessKey {
    fn from(value: AccessKeyOriginal) -> Self {
        Self {
            nonce: value.nonce,
            permission: value.permission.into(),
        }
    }
}

#[pyclass]
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug, From, Into)]
pub struct FunctionCallPermission {
    pub allowance: Option<Balance>,
    pub receiver_id: String,
    pub method_names: Vec<String>,
}

use solders_traits::PyHash;
impl PyHash for FunctionCallPermission {}

#[pyhash]
#[pymethods]
impl FunctionCallPermission {
    #[new]
    pub fn new(receiver_id: String, method_names: Vec<String>, allowance: Option<Balance>) -> Self {
        FunctionCallPermission {
            allowance,
            receiver_id,
            method_names,
        }
    }
}
#[pyclass]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessKeyPermissionFieldless {
    FullAccess,
}

#[derive(PartialEq, Eq, Hash, Clone, Debug, FromPyObject, EnumIntoPy)]
pub enum AccessKeyPermission {
    FunctionCall(FunctionCallPermission),
    Fieldless(AccessKeyPermissionFieldless),
}

impl From<AccessKeyPermission> for AccessKeyPermissionOriginal {
    fn from(value: AccessKeyPermission) -> Self {
        match value {
            AccessKeyPermission::Fieldless(_) => AccessKeyPermissionOriginal::FullAccess,
            AccessKeyPermission::FunctionCall(value) => {
                AccessKeyPermissionOriginal::FunctionCall(FunctionCallPermissionOriginal {
                    allowance: value.allowance,
                    receiver_id: value.receiver_id,
                    method_names: value.method_names,
                })
            }
        }
    }
}

impl From<AccessKeyPermissionOriginal> for AccessKeyPermission {
    fn from(value: AccessKeyPermissionOriginal) -> Self {
        match value {
            AccessKeyPermissionOriginal::FullAccess => {
                AccessKeyPermission::Fieldless(AccessKeyPermissionFieldless::FullAccess)
            }
            AccessKeyPermissionOriginal::FunctionCall(value) => {
                AccessKeyPermission::FunctionCall(FunctionCallPermission {
                    allowance: value.allowance,
                    receiver_id: value.receiver_id,
                    method_names: value.method_names,
                })
            }
        }
    }
}

#[pymethods]
impl AccessKey {
    #[new]
    #[pyo3(signature = (nonce, permission))]
    fn new(nonce: u64, permission: AccessKeyPermission) -> AccessKey {
        AccessKey {
            nonce,
            permission: permission,
        }
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Transaction {
    #[pyo3(get, set)]
    pub signer_id: String,
    #[pyo3(get, set)]
    pub public_key: [u8; 32],
    #[pyo3(get, set)]
    pub nonce: u64,
    #[pyo3(get, set)]
    pub receiver_id: String,
    #[pyo3(get, set)]
    pub block_hash: [u8; 32],
    pub actions: Vec<Action>,
}

#[derive(PartialEq, Eq, Clone, Debug, FromPyObject)]
pub enum Action {
    CreateAccount(CreateAccountAction),
    DeployContract(DeployContractAction),
    FunctionCall(FunctionCallAction),
    Transfer(TransferAction),
    Stake(StakeAction),
    AddKey(AddKeyAction),
    DeleteKey(DeleteKeyAction),
    DeleteAccount(DeleteAccountAction),
    Delegate(SignedDelegateAction),
}

impl From<Action> for ActionOriginal {
    fn from(value: Action) -> Self {
        match value {
            Action::CreateAccount(x) => ActionOriginal::CreateAccount(x.into()),
            Action::DeployContract(x) => ActionOriginal::DeployContract(x.into()),
            Action::FunctionCall(x) => ActionOriginal::FunctionCall(x.into()),
            Action::Transfer(x) => ActionOriginal::Transfer(x.into()),
            Action::Stake(x) => ActionOriginal::Stake(x.into()),
            Action::AddKey(x) => ActionOriginal::AddKey(x.into()),
            Action::DeleteKey(x) => ActionOriginal::DeleteKey(x.into()),
            Action::DeleteAccount(x) => ActionOriginal::DeleteAccount(x.into()),
            Action::Delegate(x) => ActionOriginal::Delegate(x.into()),
        }
    }
}

impl From<ActionOriginal> for Action {
    fn from(value: ActionOriginal) -> Self {
        match value {
            ActionOriginal::CreateAccount(x) => Action::CreateAccount(x.into()),
            ActionOriginal::DeployContract(x) => Action::DeployContract(x.into()),
            ActionOriginal::FunctionCall(x) => Action::FunctionCall(x.into()),
            ActionOriginal::Transfer(x) => Action::Transfer(x.into()),
            ActionOriginal::Stake(x) => Action::Stake(x.into()),
            ActionOriginal::AddKey(x) => Action::AddKey(x.into()),
            ActionOriginal::DeleteKey(x) => Action::DeleteKey(x.into()),
            ActionOriginal::DeleteAccount(x) => Action::DeleteAccount(x.into()),
            ActionOriginal::Delegate(x) => Action::Delegate(x.into()),
        }
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SignedDelegateAction {
    #[pyo3(get, set)]
    pub delegate_action: DelegateAction,
    #[pyo3(get, set)]
    pub signature: [u8; 64],
}

impl From<SignedDelegateAction> for SignedDelegateActionOriginal {
    fn from(value: SignedDelegateAction) -> Self {
        Self {
            signature: Signature::ED25519(
                ed25519_dalek::Signature::from_bytes(&value.signature).unwrap(),
            ),
            delegate_action: value.delegate_action.into(),
        }
    }
}

impl From<SignedDelegateActionOriginal> for SignedDelegateAction {
    fn from(value: SignedDelegateActionOriginal) -> Self {
        let signature = match value.signature {
            Signature::SECP256K1(_) => panic!("SECP256K1 signature unsupported"),
            Signature::ED25519(signature) => signature.to_bytes(),
        };

        Self {
            signature,
            delegate_action: value.delegate_action.into(),
        }
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DelegateAction {
    #[pyo3(get, set)]
    pub sender_id: String,
    #[pyo3(get, set)]
    pub receiver_id: String,
    pub actions: Vec<Action>,
    #[pyo3(get, set)]
    pub nonce: Nonce,
    #[pyo3(get, set)]
    pub max_block_height: u64,
    #[pyo3(get, set)]
    pub public_key: [u8; 32],
}

impl From<DelegateAction> for DelegateActionOriginal {
    fn from(value: DelegateAction) -> Self {
        Self {
            sender_id: AccountId::from_str(value.sender_id.as_str()).unwrap(),
            receiver_id: AccountId::from_str(value.receiver_id.as_str()).unwrap(),
            actions: value
                .actions
                .into_iter()
                .map(|action| {
                    let original_action = ActionOriginal::from(action);
                    original_action
                        .try_into()
                        .expect("Deligate action not supported")
                })
                .collect(),
            nonce: value.nonce,
            max_block_height: value.max_block_height,
            public_key: PublicKey::ED25519(ED25519PublicKey(value.public_key)),
        }
    }
}

impl From<DelegateActionOriginal> for DelegateAction {
    fn from(value: DelegateActionOriginal) -> Self {
        let public_key = match value.public_key {
            PublicKey::SECP256K1(_) => panic!("512 bit elliptic curve unsupported!"),
            PublicKey::ED25519(value) => value.0,
        };

        Self {
            sender_id: value.sender_id.to_string(),
            receiver_id: value.sender_id.to_string(),
            actions: value
                .actions
                .into_iter()
                .map(|el| Action::from(ActionOriginal::from(el)))
                .collect(),
            nonce: value.nonce,
            max_block_height: value.max_block_height,
            public_key,
        }
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CreateAccountAction {}

impl From<CreateAccountActionOriginal> for CreateAccountAction {
    fn from(_: CreateAccountActionOriginal) -> Self {
        Self {}
    }
}

impl From<CreateAccountAction> for CreateAccountActionOriginal {
    fn from(_: CreateAccountAction) -> Self {
        Self {}
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]

pub struct DeployContractAction {
    #[pyo3(get, set)]
    pub code: Vec<u8>,
}

impl From<DeployContractAction> for DeployContractActionOriginal {
    fn from(value: DeployContractAction) -> Self {
        Self { code: value.code }
    }
}

impl From<DeployContractActionOriginal> for DeployContractAction {
    fn from(value: DeployContractActionOriginal) -> Self {
        Self { code: value.code }
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct FunctionCallAction {
    #[pyo3(get, set)]
    pub method_name: String,
    #[pyo3(get, set)]
    pub args: Vec<u8>,
    #[pyo3(get, set)]
    pub gas: u64,
    #[pyo3(get, set)]
    pub deposit: Balance,
}

impl From<FunctionCallAction> for FunctionCallActionOriginal {
    fn from(value: FunctionCallAction) -> Self {
        Self {
            method_name: value.method_name,
            args: value.args,
            gas: value.gas,
            deposit: value.deposit,
        }
    }
}

impl From<FunctionCallActionOriginal> for FunctionCallAction {
    fn from(value: FunctionCallActionOriginal) -> Self {
        Self {
            method_name: value.method_name,
            args: value.args,
            gas: value.gas,
            deposit: value.deposit,
        }
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct TransferAction {
    #[pyo3(get, set)]
    pub deposit: Balance,
}

impl From<TransferAction> for TransferActionOriginal {
    fn from(value: TransferAction) -> Self {
        Self {
            deposit: value.deposit,
        }
    }
}

impl From<TransferActionOriginal> for TransferAction {
    fn from(value: TransferActionOriginal) -> Self {
        Self {
            deposit: value.deposit,
        }
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct StakeAction {
    #[pyo3(get, set)]
    pub stake: Balance,
    #[pyo3(get, set)]
    pub public_key: [u8; 32],
}

impl From<StakeAction> for StakeActionOriginal {
    fn from(value: StakeAction) -> Self {
        Self {
            stake: value.stake,
            public_key: PublicKey::ED25519(ED25519PublicKey(value.public_key)),
        }
    }
}

impl From<StakeActionOriginal> for StakeAction {
    fn from(value: StakeActionOriginal) -> Self {
        let public_key = match value.public_key {
            PublicKey::SECP256K1(_) => panic!("512 bit elliptic curve unsupported!"),
            PublicKey::ED25519(value) => value.0,
        };

        Self {
            stake: value.stake,
            public_key,
        }
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AddKeyAction {
    #[pyo3(get, set)]
    pub public_key: [u8; 32],
    #[pyo3(get, set)]
    pub access_key: AccessKey,
}

impl From<AddKeyAction> for AddKeyActionOriginal {
    fn from(value: AddKeyAction) -> Self {
        let public_key = PublicKey::ED25519(ED25519PublicKey(value.public_key));
        Self {
            public_key,
            access_key: value.access_key.into(),
        }
    }
}

impl From<AddKeyActionOriginal> for AddKeyAction {
    fn from(value: AddKeyActionOriginal) -> Self {
        let public_key = match value.public_key {
            PublicKey::SECP256K1(_) => panic!("512 bit elliptic curve unsupported!"),
            PublicKey::ED25519(public_key) => public_key.0,
        };

        Self {
            public_key,
            access_key: value.access_key.into(),
        }
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DeleteKeyAction {
    #[pyo3(get, set)]
    pub public_key: [u8; 32],
}

impl From<DeleteKeyAction> for DeleteKeyActionOriginal {
    fn from(value: DeleteKeyAction) -> Self {
        Self {
            public_key: PublicKey::ED25519(ED25519PublicKey(value.public_key)),
        }
    }
}

impl From<DeleteKeyActionOriginal> for DeleteKeyAction {
    fn from(value: DeleteKeyActionOriginal) -> Self {
        let public_key = match value.public_key {
            PublicKey::SECP256K1(_) => panic!("512 bit elliptic curve unsupported!"),
            PublicKey::ED25519(public_key) => public_key.0,
        };

        Self { public_key }
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DeleteAccountAction {
    #[pyo3(get, set)]
    pub beneficiary_id: String,
}

impl From<DeleteAccountAction> for DeleteAccountActionOriginal {
    fn from(value: DeleteAccountAction) -> Self {
        Self {
            beneficiary_id: AccountId::from_str(&value.beneficiary_id).unwrap(),
        }
    }
}

impl From<DeleteAccountActionOriginal> for DeleteAccountAction {
    fn from(value: DeleteAccountActionOriginal) -> Self {
        Self {
            beneficiary_id: value.beneficiary_id.to_string(),
        }
    }
}

#[pymethods]
impl SignedDelegateAction {
    #[new]
    #[pyo3(signature = (delegate_action, signature))]
    fn new(delegate_action: DelegateAction, signature: [u8; 64]) -> SignedDelegateAction {
        SignedDelegateAction {
            delegate_action: delegate_action,
            signature: signature,
        }
    }
}

fn get_orig_transaction(in_tr: &Transaction) -> TransactionOriginal {
    let mut tr = TransactionOriginal::new(
        AccountId::from_str(&in_tr.signer_id.as_str()).unwrap(),
        PublicKey::ED25519(ED25519PublicKey(in_tr.public_key)),
        AccountId::from_str(&in_tr.receiver_id.as_str()).unwrap(),
        in_tr.nonce,
        CryptoHash(in_tr.block_hash),
    );

    let original_actions: Vec<ActionOriginal> = in_tr
        .actions
        .iter()
        .map(|action| {
            let action = action.clone();
            action.into()
        })
        .collect();
    tr.actions = original_actions;

    tr
}

use pyo3::types::PyBytes;

#[pymethods]
impl DelegateAction {
    #[new]
    #[pyo3(signature = (sender_id, receiver_id, actions, nonce, max_block_height, public_key))]
    pub fn new(
        sender_id: String,
        receiver_id: String,
        actions: Vec<Action>,
        nonce: Nonce,
        max_block_height: u64,
        public_key: [u8; 32],
    ) -> Self {
        DelegateAction {
            sender_id,
            receiver_id,
            actions,
            nonce,
            max_block_height,
            public_key,
        }
    }

    fn get_nep461_hash(&self) -> [u8; 32] {
        let action: DelegateActionOriginal = self.clone().into();
        *action.get_nep461_hash().as_bytes()
    }

    #[pyo3(text_signature = "() -> bytes")]
    fn serialize(&self) -> PyResult<Py<PyBytes>> {
        let action: DelegateActionOriginal = self.clone().into();
        let res = action.try_to_vec().unwrap().to_vec();
        let py = unsafe { Python::assume_gil_acquired() };
        let pybytes = PyBytes::new(py, &res);

        Ok(pybytes.into())
    }

    #[staticmethod]
    #[pyo3(signature = (bytes))]
    fn bytes_to_json(mut bytes: &[u8]) -> String {
        let bytes_mut: &mut &[u8] = &mut bytes;
        let action: DelegateActionOriginal =
            near_primitives::borsh::BorshDeserialize::deserialize(bytes_mut).unwrap();

        serde_json::to_string(&action).unwrap()
    }
}

#[pymethods]
impl CreateAccountAction {
    #[new]
    fn new() -> CreateAccountAction {
        CreateAccountAction {}
    }
}

#[pymethods]
impl DeployContractAction {
    #[new]
    #[pyo3(signature = (code))]
    fn new(code: Vec<u8>) -> DeployContractAction {
        DeployContractAction { code }
    }
}

#[pymethods]
impl FunctionCallAction {
    #[new]
    #[pyo3(signature = (method_name, args, gas = 0, deposit = 0))]
    fn new(method_name: &str, args: Vec<u8>, gas: u64, deposit: Balance) -> FunctionCallAction {
        FunctionCallAction {
            method_name: method_name.to_string(),
            args,
            gas,
            deposit,
        }
    }
}

#[pymethods]
impl TransferAction {
    #[new]
    #[pyo3(signature = (deposit))]
    fn new(deposit: u128) -> TransferAction {
        TransferAction { deposit }
    }
}

#[pymethods]
impl StakeAction {
    #[new]
    #[pyo3(signature = (stake, public_key))]
    fn new(stake: u128, public_key: [u8; 32]) -> StakeAction {
        StakeAction {
            stake,
            public_key: public_key,
        }
    }
}

#[pymethods]
impl AddKeyAction {
    #[new]
    #[pyo3(signature = (public_key, access_key))]
    fn new(public_key: [u8; 32], access_key: AccessKey) -> AddKeyAction {
        AddKeyAction {
            public_key: public_key,
            access_key,
        }
    }
}

#[pymethods]
impl DeleteKeyAction {
    #[new]
    #[pyo3(signature = (public_key))]
    fn new(public_key: [u8; 32]) -> DeleteKeyAction {
        DeleteKeyAction {
            public_key: public_key,
        }
    }
}

#[pymethods]
impl DeleteAccountAction {
    #[new]
    #[pyo3(signature = (beneficiary_id))]
    fn new(beneficiary_id: &str) -> DeleteAccountAction {
        DeleteAccountAction {
            beneficiary_id: beneficiary_id.to_string(),
        }
    }
}

#[pymethods]
impl Transaction {
    #[new]
    #[pyo3(signature = (signer_id, public_key, nonce, receiver_id, block_hash, actions))]
    fn new(
        signer_id: &str,
        public_key: [u8; 32],
        nonce: u64,
        receiver_id: &str,
        block_hash: [u8; 32],
        actions: Vec<Action>,
    ) -> Transaction {
        Transaction {
            signer_id: signer_id.to_string(),
            public_key: public_key,
            nonce,
            receiver_id: receiver_id.to_string(),
            block_hash: block_hash,
            actions,
        }
    }

    #[pyo3(signature = ())]
    fn get_hash(&self) -> Vec<u8> {
        let tr = get_orig_transaction(&self);
        return tr.get_hash_and_size().0.as_bytes().to_vec();
    }

    #[pyo3(signature = (secret_key))]
    fn to_vec(&self, secret_key: [u8; 64]) -> Vec<u8> {
        let tr = get_orig_transaction(&self);
        let key = near_crypto::SecretKey::ED25519(ED25519SecretKey(secret_key));
        let signer = near_crypto::InMemorySigner::from_secret_key(
            AccountId::from_str(&tr.signer_id.to_string()).unwrap(),
            key,
        );
        let strx = tr.sign(&signer);
        strx.try_to_vec().unwrap()
    }

    #[pyo3(signature = ())]
    fn serialize(&self) -> Vec<u8> {
        let tr = get_orig_transaction(&self);
        tr.try_to_vec().unwrap()
    }

    #[staticmethod]
    #[pyo3(signature = (bytes))]
    fn deserialize(mut bytes: &[u8]) -> Self {
        let bytes = &mut bytes;
        let original_tx: TransactionOriginal =
            near_primitives::borsh::BorshDeserialize::deserialize(bytes).unwrap();
        let public_key = match original_tx.public_key {
            PublicKey::SECP256K1(_) => panic!("512 bit elliptic curve unsupported!"),
            PublicKey::ED25519(public_key) => public_key.0,
        };

        Self {
            nonce: original_tx.nonce,
            signer_id: original_tx.signer_id.into(),
            public_key,
            receiver_id: original_tx.receiver_id.into(),
            block_hash: original_tx.block_hash.0,
            actions: original_tx.actions.into_iter().map(Action::from).collect(),
        }
    }
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
struct SignedTransaction {
    #[pyo3(get, set)]
    pub transaction: Transaction,
    #[pyo3(get, set)]
    pub signature: [u8; 64],
    #[pyo3(get, set)]
    pub hash: [u8; 32],
    #[pyo3(get, set)]
    pub size: u64,
}

impl From<SignedTransaction> for SignedTransactionOriginal {
    fn from(value: SignedTransaction) -> Self {
        let transaction = get_orig_transaction(&value.transaction);
        let signature =
            Signature::ED25519(ed25519_dalek::Signature::from_bytes(&value.signature).unwrap());

        // TODO: hash & size are private, this is only way to create. fix
        SignedTransactionOriginal::new(signature, transaction)
    }
}

#[pymethods]
impl SignedTransaction {
    #[new]
    #[pyo3(signature = (signature, transaction))]
    fn new(signature: [u8; 64], transaction: Transaction) -> Self {
        let original_tx = get_orig_transaction(&transaction);
        let original_signed_tx = SignedTransactionOriginal::new(
            Signature::ED25519(ed25519_dalek::Signature::from_bytes(&signature).unwrap()),
            original_tx,
        );

        Self {
            transaction,
            signature,
            hash: original_signed_tx.get_hash().0,
            size: original_signed_tx.get_size(),
        }
    }

    #[pyo3(signature = ())]
    fn serialize(&self) -> Vec<u8> {
        let original_signed_tx: SignedTransactionOriginal = self.clone().into();
        original_signed_tx.try_to_vec().unwrap()
    }
}

#[pymodule]
fn py_near_primitives(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Transaction>()?;

    m.add_class::<DeleteAccountAction>()?;
    m.add_class::<FunctionCallAction>()?;
    m.add_class::<DeployContractAction>()?;
    m.add_class::<CreateAccountAction>()?;
    m.add_class::<DelegateAction>()?;
    m.add_class::<SignedDelegateAction>()?;
    m.add_class::<DeleteKeyAction>()?;
    m.add_class::<AddKeyAction>()?;
    m.add_class::<StakeAction>()?;
    m.add_class::<TransferAction>()?;
    m.add_class::<AccessKey>()?;
    m.add_class::<AccessKeyPermissionFieldless>()?;
    m.add_class::<FunctionCallPermission>()?;
    m.add_class::<SignedTransaction>()?;
    Ok(())
}
