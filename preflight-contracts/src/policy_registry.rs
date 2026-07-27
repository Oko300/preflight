use odra::prelude::*;
use odra::casper_types::U512;

#[odra::event]
pub struct AgentRegistered {
    pub agent_id: String,
    pub owner: Address,
    pub spend_cap_per_tx: U512,
}

#[odra::event]
pub struct AgentKilled {
    pub agent_id: String,
    pub killed_by: Address,
}

#[odra::odra_error]
pub enum PolicyError {
    AgentAlreadyExists = 1,
    AgentNotFound = 2,
    UnauthorizedKillSwitch = 3,
    AgentIsDead = 4,
}

#[odra::odra_type]
pub struct AgentPolicy {
    pub owner: Address,
    pub spend_cap_per_tx: U512,
    pub daily_spend_limit: U512,
    pub is_active: bool,
}

#[odra::module(
    events = [AgentRegistered, AgentKilled],
    errors = PolicyError
)]
pub struct AgentPolicyRegistry {
    policies: Mapping<String, AgentPolicy>,
    owner: Var<Address>,
}

#[odra::module]
impl AgentPolicyRegistry {
    pub fn init(&mut self) {
        self.owner.set(self.env().caller());
    }

    pub fn register_agent(
        &mut self,
        agent_id: String,
        spend_cap_per_tx: U512,
        daily_spend_limit: U512,
    ) {
        if self.policies.get(&agent_id).is_some() {
            self.env().revert(PolicyError::AgentAlreadyExists);
        }
        let caller = self.env().caller();
        let policy = AgentPolicy {
            owner: caller,
            spend_cap_per_tx,
            daily_spend_limit,
            is_active: true,
        };
        self.policies.set(&agent_id, policy);
        self.env().emit_event(AgentRegistered {
            agent_id,
            owner: caller,
            spend_cap_per_tx,
        });
    }

    pub fn kill_agent(&mut self, agent_id: String) {
        let mut policy = self
            .policies
            .get(&agent_id)
            .unwrap_or_revert_with(&self.env(), PolicyError::AgentNotFound);
        let caller = self.env().caller();
        if policy.owner != caller {
            self.env().revert(PolicyError::UnauthorizedKillSwitch);
        }
        policy.is_active = false;
        self.policies.set(&agent_id, policy);
        self.env().emit_event(AgentKilled {
            agent_id,
            killed_by: caller,
        });
    }

    pub fn get_policy(&self, agent_id: &String) -> Option<AgentPolicy> {
        self.policies.get(agent_id)
    }

    pub fn is_agent_active(&self, agent_id: &String) -> bool {
        match self.policies.get(agent_id) {
            Some(policy) => policy.is_active,
            None => false,
        }
    }
}

