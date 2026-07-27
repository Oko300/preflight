use odra::prelude::*;
use odra::casper_types::U512;
use odra::ContractRef;
use crate::policy_registry::AgentPolicyRegistryContractRef;
use crate::reputation_ledger::ReputationLedgerContractRef;

#[odra::odra_type]
pub struct EvalResult {
    pub approved: bool,
    pub reason: String,
    pub risk_score: u8,
}

#[odra::event]
pub struct ActionEvaluated {
    pub agent_id: String,
    pub action_type: String,
    pub target_contract: String,
    pub value: U512,
    pub approved: bool,
    pub reason: String,
}

#[odra::odra_error]
pub enum GuardError {
    PolicyRegistryNotSet = 1,
    ReputationLedgerNotSet = 2,
    AgentNotRegistered = 3,
    AgentIsInactive = 4,
    UnauthorizedOwner = 5,
}

#[odra::module(
    events = [ActionEvaluated],
    errors = GuardError
)]
pub struct PreFlightGuard {
    policy_registry: Var<Address>,
    reputation_ledger: Var<Address>,
    owner: Var<Address>,
    global_contract_allowlist: Mapping<String, bool>,
    eval_counter: Var<u64>,
}

#[odra::module]
impl PreFlightGuard {
    pub fn init(&mut self) {
        self.owner.set(self.env().caller());
        self.eval_counter.set(0u64);
    }

    pub fn set_policy_registry(&mut self, address: Address) {
        self.assert_owner();
        self.policy_registry.set(address);
    }

    pub fn set_reputation_ledger(&mut self, address: Address) {
        self.assert_owner();
        self.reputation_ledger.set(address);
    }

    pub fn add_to_global_allowlist(&mut self, contract_hash: String) {
        self.assert_owner();
        self.global_contract_allowlist.set(&contract_hash, true);
    }

    pub fn remove_from_global_allowlist(&mut self, contract_hash: String) {
        self.assert_owner();
        self.global_contract_allowlist.set(&contract_hash, false);
    }

    pub fn evaluate_action(
        &mut self,
        agent_id: String,
        action_type: String,
        target_contract: String,
        value: U512,
        risk_score: u8,
    ) -> EvalResult {
        let registry_addr = self
            .policy_registry
            .get()
            .unwrap_or_revert_with(&self.env(), GuardError::PolicyRegistryNotSet);

        let registry_ref = AgentPolicyRegistryContractRef::new(self.env(), registry_addr);
        let policy = match registry_ref.get_policy(&agent_id) {
            Some(p) => p,
            None => self.env().revert(GuardError::AgentNotRegistered),
        };

        if !policy.is_active {
            return self.record_and_return(
                agent_id,
                action_type,
                target_contract,
                false,
                "AGENT_INACTIVE",
                risk_score,
            );
        }

        if value > policy.spend_cap_per_tx {
            return self.record_and_return(
                agent_id,
                action_type,
                target_contract,
                false,
                "EXCEEDS_SPEND_CAP",
                risk_score,
            );
        }

        let is_allowed = self
            .global_contract_allowlist
            .get(&target_contract)
            .unwrap_or(false);
        if !is_allowed {
            return self.record_and_return(
                agent_id,
                action_type,
                target_contract,
                false,
                "TARGET_NOT_ALLOWLISTED",
                risk_score,
            );
        }

        if risk_score > 75 {
            return self.record_and_return(
                agent_id,
                action_type,
                target_contract,
                false,
                "RISK_SCORE_TOO_HIGH",
                risk_score,
            );
        }

        self.record_and_return(
            agent_id,
            action_type,
            target_contract,
            true,
            "APPROVED",
            risk_score,
        )
    }

    pub fn is_contract_allowed(&self, contract_hash: &String) -> bool {
        self.global_contract_allowlist
            .get(contract_hash)
            .unwrap_or(false)
    }

    pub fn get_eval_counter(&self) -> u64 {
        self.eval_counter.get_or_default()
    }
}

impl PreFlightGuard {
    fn assert_owner(&self) {
        let caller = self.env().caller();
        if self.owner.get_or_revert_with(GuardError::UnauthorizedOwner) != caller {
            self.env().revert(GuardError::UnauthorizedOwner);
        }
    }

    fn record_and_return(
        &mut self,
        agent_id: String,
        action_type: String,
        target_contract: String,
        approved: bool,
        reason: &str,
        risk_score: u8,
    ) -> EvalResult {
        let counter = self.eval_counter.get_or_default();
        let action_hash = format!("{}:{}:{}", agent_id, counter, action_type);
        self.eval_counter.set(counter + 1);

        self.env().emit_event(ActionEvaluated {
            agent_id: agent_id.clone(),
            action_type,
            target_contract,
            value: U512::zero(),
            approved,
            reason: reason.to_string(),
        });

        if let Some(ledger_addr) = self.reputation_ledger.get() {
            let mut ledger_ref = ReputationLedgerContractRef::new(self.env(), ledger_addr);
            ledger_ref.record_evaluation(agent_id, action_hash, approved);
        }

        EvalResult {
            approved,
            reason: reason.to_string(),
            risk_score,
        }
    }
}