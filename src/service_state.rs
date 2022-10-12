// High level representation of user service state
// Records a sequence of operations to perform against a *deterministic* state machine
// All operations recorded come from some provided type O
pub struct ServiceState<O> {
    log: Vec<O>,
}

impl<O> ServiceState<O> {
    pub fn broadcast_finality(&mut self, op: O) {
        self.log.push(op);
    }
}

// TODO: Add efficient state transfer mechanism

impl<O> Default for ServiceState<O> {
    fn default() -> Self {
        ServiceState {
            log: Vec::new()
        }
    }
}