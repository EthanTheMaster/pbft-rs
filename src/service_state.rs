use crate::kernel::{Digestible, DigestResult, ServiceOperation};

// High level representation of user service state
// Records a sequence of operations to perform against a *deterministic* state machine
// All operations recorded come from some provided type O
#[derive(Clone)]
pub struct ServiceState<O>
    where O: ServiceOperation
{
    log: Vec<O>,
}

impl<O> ServiceState<O>
    where O: ServiceOperation
{
    pub fn broadcast_finality(&mut self, op: O) {
        self.log.push(op);
    }

    pub fn log(&self) -> &Vec<O> {
        &self.log
    }
}

// TODO: Add efficient state transfer mechanism

impl<O> Default for ServiceState<O>
    where O: ServiceOperation
{
    fn default() -> Self {
        ServiceState {
            log: Vec::new()
        }
    }
}

impl<O> Digestible for ServiceState<O>
    where O: ServiceOperation
{
    fn digest(&self) -> DigestResult {
        // TODO: Implement digest
        vec![]
    }
}