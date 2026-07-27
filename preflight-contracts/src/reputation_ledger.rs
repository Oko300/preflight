use odra::prelude::*;

#[odra::event]
pub struct EvaluationRecorded {
    pub agent_id: String,
    pub action_hash: String,
    pub was_approved: bool,
    pub new_score: u32,
}

#[odra::odra_error]
pub enum ReputationError {
    UnauthorizedCaller = 1,
    AgentNotFound = 2,
}

#[odra::module(
    events = [EvaluationRecorded],
    errors = ReputationError
)]
pub struct ReputationLedger {
    scores: Mapping<String, u32>,
    total_evals: Mapping<String, u32>,
    approved_count: Mapping<String, u32>,
    authorized_writer: Var<Address>,
    owner: Var<Address>,
}

#[odra::module]
impl ReputationLedger {
    pub fn init(&mut self) {
        self.owner.set(self.env().caller());
    }

    pub fn set_authorized_writer(&mut self, writer: Address) {
        let caller = self.env().caller();
        if self.owner.get_or_revert_with(ReputationError::UnauthorizedCaller) != caller {
            self.env().revert(ReputationError::UnauthorizedCaller);
        }
        self.authorized_writer.set(writer);
    }

    pub fn record_evaluation(
        &mut self,
        agent_id: String,
        action_hash: String,
        was_approved: bool,
    ) {
        let caller = self.env().caller();
        if let Some(writer) = self.authorized_writer.get() {
            if writer != caller {
                self.env().revert(ReputationError::UnauthorizedCaller);
            }
        } else {
            self.env().revert(ReputationError::UnauthorizedCaller);
        }

        let total = self.total_evals.get_or_default(&agent_id);
        self.total_evals.set(&agent_id, total + 1);

        let current_score = self.scores.get(&agent_id).unwrap_or(100u32);
        let new_score = if was_approved {
            (current_score + 1).min(200)
        } else {
            current_score.saturating_sub(10)
        };
        self.scores.set(&agent_id, new_score);

        if was_approved {
            let approved = self.approved_count.get_or_default(&agent_id);
            self.approved_count.set(&agent_id, approved + 1);
        }

        self.env().emit_event(EvaluationRecorded {
            agent_id,
            action_hash,
            was_approved,
            new_score,
        });
    }

    pub fn get_score(&self, agent_id: &String) -> u32 {
        self.scores.get(agent_id).unwrap_or(100u32)
    }

    pub fn get_total_evaluations(&self, agent_id: &String) -> u32 {
        self.total_evals.get_or_default(agent_id)
    }

    pub fn get_approved_count(&self, agent_id: &String) -> u32 {
        self.approved_count.get_or_default(agent_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odra::host::{Deployer, NoArgs};

    #[test]
    fn test_initial_score_is_100() {
        let env = odra_test::env();
        let contract = ReputationLedger::deploy(&env, NoArgs);
        assert_eq!(contract.get_score(&"agent-1".to_string()), 100u32);
    }

    #[test]
    fn test_approved_increases_score() {
        let env = odra_test::env();
        let mut contract = ReputationLedger::deploy(&env, NoArgs);
        let writer = env.get_account(1);
        contract.set_authorized_writer(writer);
        env.set_caller(writer);
        contract.record_evaluation("agent-1".to_string(), "hash-1".to_string(), true);
        assert_eq!(contract.get_score(&"agent-1".to_string()), 101u32);
    }

    #[test]
    fn test_blocked_decreases_score() {
        let env = odra_test::env();
        let mut contract = ReputationLedger::deploy(&env, NoArgs);
        let writer = env.get_account(1);
        contract.set_authorized_writer(writer);
        env.set_caller(writer);
        contract.record_evaluation("agent-1".to_string(), "hash-1".to_string(), false);
        assert_eq!(contract.get_score(&"agent-1".to_string()), 90u32);
    }
}