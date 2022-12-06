use rand::Rng;
use crate::kernel::{CheckpointSummary, PBFTEvent, PrepTriple, ViewChange};
use crate::pbft_replica::ServiceOperation;
use crate::service_state::{StateTransferRequest, StateTransferResponse};

const IMPERSONATION_PROBABILITY: f64 = 0.03;

// Implement functions to randomly perturb protocol data to simulate a malfunctioning replica
impl PrepTriple {
    pub fn mutate(&mut self) {
        if rand::random() {
            self.sequence_number = rand::random();
        }
        if rand::random() {
            self.digest = rand::random();
        }
        if rand::random() {
            self.view = rand::random();
        }
    }
}

impl CheckpointSummary {
    pub fn mutate(&mut self) {
        if rand::random() {
            self.sequence_number = rand::random();
        }
        if rand::random() {
            self.service_state_summary.log_length = rand::random();
        }
        if rand::random() {
            self.service_state_summary.log_digest = rand::random();
        }
    }
}

impl ViewChange {
    pub fn mutate(&mut self) {
        if rand::thread_rng().gen_bool(IMPERSONATION_PROBABILITY) {
            self.from = rand::random();
        }
        if rand::random() {
            self.view = rand::random();
        }
        if rand::random() {
            self.log_low_mark = rand::random();
        }
        for checkpoint in self.checkpoints.iter_mut() {
            checkpoint.mutate();
        }
        self.prepared = self.prepared.iter().filter_map(|prep| {
            if rand::random() {
                let mut p = prep.clone();
                p.mutate();
                Some(p)
            } else {
                None
            }
        }).collect();
        self.preprepared = self.prepared.iter().filter_map(|prep| {
            if rand::random() {
                let mut p = prep.clone();
                p.mutate();
                Some(p)
            } else {
                None
            }
        }).collect();
    }
}

impl<O> PBFTEvent<O> where O: ServiceOperation {
    pub fn mutate(&mut self) {
        match self {
            PBFTEvent::Request(_) => {
                // Do nothing
            }
            PBFTEvent::PrePrepare { from, data, .. } => {
                if rand::thread_rng().gen_bool(IMPERSONATION_PROBABILITY) {
                    *from = rand::random();
                }
                data.mutate();
            }
            PBFTEvent::Prepare { from, data } => {
                if rand::thread_rng().gen_bool(IMPERSONATION_PROBABILITY) {
                    *from = rand::random();
                }
                data.mutate();
            }
            PBFTEvent::Commit { from, data } => {
                if rand::thread_rng().gen_bool(IMPERSONATION_PROBABILITY) {
                    *from = rand::random();
                }
                data.mutate();
            }
            PBFTEvent::Checkpoint { from, data } => {
                if rand::thread_rng().gen_bool(IMPERSONATION_PROBABILITY) {
                    *from = rand::random();
                }
                data.mutate();
            }
            PBFTEvent::ViewChange(data) => {
                data.mutate();
            }
            PBFTEvent::NewView(data) => {
                if rand::thread_rng().gen_bool(IMPERSONATION_PROBABILITY) {
                    data.from = rand::random();
                }
                if rand::random() {
                    data.view = rand::random();
                }
                data.selected_checkpoint.mutate();
                for msg in data.selected_messages.iter_mut() {
                    match msg {
                        None => {
                            if rand::random() {
                                *msg = Some(PrepTriple {
                                    sequence_number: rand::random(),
                                    digest: rand::random(),
                                    view: rand::random()
                                });
                            }
                        }
                        Some(msg) => {
                            msg.mutate();
                        }
                    }
                }
            }
            PBFTEvent::StateTransferRequest(req) => {
                match req {
                    StateTransferRequest::ViewChangeDigestProof { from, sequence_number, digest } => {
                        if rand::thread_rng().gen_bool(IMPERSONATION_PROBABILITY) {
                            *from = rand::random();
                        }
                        if rand::random() {
                            *sequence_number = rand::random();
                        }
                        if rand::random() {
                            *digest = rand::random();
                        }
                    }
                    StateTransferRequest::ServiceStateItemProof { from, log_length, log_item_index } => {
                        if rand::thread_rng().gen_bool(IMPERSONATION_PROBABILITY) {
                            *from = rand::random();
                        }
                        if rand::random() {
                            *log_length = rand::random();
                        }
                        if rand::random() {
                            *log_item_index = rand::random();
                        }

                    }
                }
            }
            PBFTEvent::StateTransferResponse(res) => {
                match res {
                    StateTransferResponse::ViewChangeDigestProof { sequence_number, .. } => {
                        if rand::random() {
                            *sequence_number = rand::random();
                        }
                    }
                    StateTransferResponse::ServiceStateItemProof { log_length, log_item_index, merkle_proof, .. } => {
                        if rand::random() {
                            *log_length = rand::random();
                        }
                        if rand::random() {
                            *log_item_index = rand::random();
                        }
                        if rand::random() {
                            merkle_proof.items = merkle_proof.items.iter()
                                .map(|_| {
                                    rand::random()
                                })
                                .collect();
                        }
                        if rand::random() {
                            merkle_proof.right_boundary = rand::random();
                        }
                        if rand::random() {
                            for hash in merkle_proof.internal_hashes.values_mut() {
                                *hash = rand::random();
                            }
                        }
                    }
                }
            }
        }
    }
}