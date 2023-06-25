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
use near_primitives::delegate_action::NonDelegateAction;
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
        FunctionCallAction as FunctionCallActionOriginal, StakeAction as StakeActionOriginal,
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

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]

pub struct SignedDelegateAction {
    #[pyo3(get, set)]
    pub delegate_action: DelegateAction,
    #[pyo3(get, set)]
    pub signature: [u8; 64],
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

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]

pub struct CreateAccountAction {}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]

pub struct DeployContractAction {
    #[pyo3(get, set)]
    pub code: Vec<u8>,
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

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct TransferAction {
    #[pyo3(get, set)]
    pub deposit: Balance,
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct StakeAction {
    #[pyo3(get, set)]
    pub stake: Balance,
    #[pyo3(get, set)]
    pub public_key: [u8; 32],
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AddKeyAction {
    #[pyo3(get, set)]
    pub public_key: [u8; 32],
    #[pyo3(get, set)]
    pub access_key: AccessKey,
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DeleteKeyAction {
    #[pyo3(get, set)]
    pub public_key: [u8; 32],
}

#[pyclass]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DeleteAccountAction {
    #[pyo3(get, set)]
    pub beneficiary_id: String,
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

fn get_delegate_actions(da: DelegateAction) -> Vec<NonDelegateAction> {
    let mut dactions: Vec<NonDelegateAction> = Vec::new();
    for dac in da.actions {
        let delegate_action: ActionOriginal = match dac {
            Action::CreateAccount(..) => {
                ActionOriginal::CreateAccount(CreateAccountActionOriginal {})
            }
            Action::DeployContract(x) => {
                ActionOriginal::DeployContract(DeployContractActionOriginal { code: x.code })
            }
            Action::FunctionCall(x) => ActionOriginal::FunctionCall(FunctionCallActionOriginal {
                method_name: x.method_name,
                args: x.args,
                gas: x.gas,
                deposit: x.deposit,
            }),
            Action::Transfer(x) => {
                ActionOriginal::Transfer(TransferActionOriginal { deposit: x.deposit })
            }
            Action::Stake(x) => {
                let pk = PublicKey::ED25519(ED25519PublicKey(x.public_key));
                ActionOriginal::Stake(StakeActionOriginal {
                    stake: x.stake,
                    public_key: pk,
                })
            }
            Action::AddKey(x) => {
                let pk = PublicKey::ED25519(ED25519PublicKey(x.public_key));

                let ak = match x.access_key.permission {
                    AccessKeyPermission::Fieldless(..) => AccessKeyOriginal {
                        nonce: x.access_key.nonce,
                        permission: AccessKeyPermissionOriginal::FullAccess,
                    },
                    AccessKeyPermission::FunctionCall(fc) => AccessKeyOriginal {
                        nonce: x.access_key.nonce,
                        permission: AccessKeyPermissionOriginal::FunctionCall(
                            FunctionCallPermissionOriginal {
                                allowance: fc.allowance,
                                receiver_id: fc.receiver_id,
                                method_names: fc.method_names,
                            },
                        ),
                    },
                };
                ActionOriginal::AddKey(AddKeyActionOriginal {
                    public_key: pk,
                    access_key: ak,
                })
            }
            Action::DeleteKey(x) => {
                let pk = PublicKey::ED25519(ED25519PublicKey(x.public_key));
                ActionOriginal::DeleteKey(DeleteKeyActionOriginal { public_key: pk })
            }
            Action::DeleteAccount(x) => {
                ActionOriginal::DeleteAccount(DeleteAccountActionOriginal {
                    beneficiary_id: AccountId::from_str(x.beneficiary_id.as_str()).unwrap(),
                })
            }
            Action::Delegate(..) => {
                panic!("Deligate action not supported");
            }
        };
        dactions.push(delegate_action.try_into().unwrap());
    }
    dactions
}

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
        let pk = PublicKey::ED25519(ED25519PublicKey(self.public_key));

        let action = DelegateActionOriginal {
            sender_id: AccountId::from_str(self.sender_id.as_str()).unwrap(),
            receiver_id: AccountId::from_str(self.receiver_id.as_str()).unwrap(),
            actions: get_delegate_actions(self.clone()),
            nonce: self.nonce,
            max_block_height: self.max_block_height,
            public_key: pk,
        };
        return *action.get_nep461_hash().as_bytes();
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
use near_crypto::KeyType;

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

    #[pyo3(signature = (secret_key))]
    fn to_vec(&self, secret_key: [u8; 64]) -> Vec<u8> {
        let mut tr = TransactionOriginal::new(
            AccountId::from_str(&self.signer_id.as_str()).unwrap(),
            PublicKey::ED25519(ED25519PublicKey(self.public_key)),
            AccountId::from_str(&self.receiver_id.as_str()).unwrap(),
            self.nonce,
            CryptoHash(self.block_hash),
        );

        for aco in &self.actions {
            let ac = aco.clone();
            let action: ActionOriginal = match ac {
                Action::CreateAccount(..) => {
                    ActionOriginal::CreateAccount(CreateAccountActionOriginal {})
                }
                Action::DeployContract(x) => {
                    ActionOriginal::DeployContract(DeployContractActionOriginal { code: x.code })
                }
                Action::FunctionCall(x) => {
                    ActionOriginal::FunctionCall(FunctionCallActionOriginal {
                        method_name: x.method_name,
                        args: x.args,
                        gas: x.gas,
                        deposit: x.deposit,
                    })
                }
                Action::Transfer(x) => {
                    ActionOriginal::Transfer(TransferActionOriginal { deposit: x.deposit })
                }
                Action::Stake(x) => {
                    let pk = PublicKey::ED25519(ED25519PublicKey(x.public_key));
                    ActionOriginal::Stake(StakeActionOriginal {
                        stake: x.stake,
                        public_key: pk,
                    })
                }
                Action::AddKey(x) => {
                    let pk = PublicKey::ED25519(ED25519PublicKey(x.public_key));

                    let ak = match x.access_key.permission {
                        AccessKeyPermission::Fieldless(..) => AccessKeyOriginal {
                            nonce: x.access_key.nonce,
                            permission: AccessKeyPermissionOriginal::FullAccess,
                        },
                        AccessKeyPermission::FunctionCall(fc) => AccessKeyOriginal {
                            nonce: x.access_key.nonce,
                            permission: AccessKeyPermissionOriginal::FunctionCall(
                                FunctionCallPermissionOriginal {
                                    allowance: fc.allowance,
                                    receiver_id: fc.receiver_id,
                                    method_names: fc.method_names,
                                },
                            ),
                        },
                    };
                    ActionOriginal::AddKey(AddKeyActionOriginal {
                        public_key: pk,
                        access_key: ak,
                    })
                }
                Action::DeleteKey(x) => {
                    let pk = PublicKey::ED25519(ED25519PublicKey(x.public_key));
                    ActionOriginal::DeleteKey(DeleteKeyActionOriginal { public_key: pk })
                }
                Action::DeleteAccount(x) => {
                    ActionOriginal::DeleteAccount(DeleteAccountActionOriginal {
                        beneficiary_id: AccountId::from_str(x.beneficiary_id.as_str()).unwrap(),
                    })
                }
                Action::Delegate(x) => {
                    let pk = PublicKey::ED25519(ED25519PublicKey(x.delegate_action.public_key));

                    let da = DelegateActionOriginal {
                        sender_id: AccountId::from_str(x.delegate_action.sender_id.as_str())
                            .unwrap(),

                        receiver_id: AccountId::from_str(x.delegate_action.receiver_id.as_str())
                            .unwrap(),

                        actions: get_delegate_actions(x.delegate_action.clone()),
                        nonce: x.delegate_action.nonce,
                        max_block_height: x.delegate_action.max_block_height,
                        public_key: pk,
                    };

                    let signature = Signature::from_parts(KeyType::ED25519, &x.signature).unwrap();
                    let delegate_action = SignedDelegateActionOriginal {
                        delegate_action: da,
                        signature: signature,
                    };
                    if !delegate_action.verify() {
                        panic!("Incorrect deligate sign")
                    }
                    let action = ActionOriginal::Delegate(delegate_action);
                    action
                }
            };
            tr.actions.push(action);
        }

        let key = near_crypto::SecretKey::ED25519(ED25519SecretKey(secret_key));
        let signer = near_crypto::InMemorySigner::from_secret_key(
            AccountId::from_str(&tr.signer_id.to_string()).unwrap(),
            key,
        );

        let strx = tr.sign(&signer);
        strx.try_to_vec().unwrap()
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
    Ok(())
}
