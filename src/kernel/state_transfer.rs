use crate::kernel::*;
use crate::merkle_tree::{MerkleIndex, MerkleTree};
use crate::pbft_replica::ServiceOperation;

impl<O> PBFTState<O>
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    pub fn synchronize_up_to_checkpoint(&mut self, checkpoint_summary: &CheckpointSummary) {
        // TODO: Do less naive synchronization
        let current_log_length = self.current_state.log().len();
        self.known_service_state_digests.insert(
            checkpoint_summary.service_state_summary.log_length,
            (checkpoint_summary.sequence_number, checkpoint_summary.service_state_summary.log_digest)
        );

        for n in current_log_length..checkpoint_summary.service_state_summary.log_length {
            self.communication_proxy.broadcast(PBFTEvent::StateTransferRequest(StateTransferRequest::ServiceStateItemProof {
                from: self.my_index,
                log_length: checkpoint_summary.service_state_summary.log_length,
                log_item_index: n,
            }))
        }
    }

    pub fn process_state_transfer_request(&mut self, req: StateTransferRequest) {
        // Attempt to answer the request
        match req {
            StateTransferRequest::ViewChangeDigestProof { from, sequence_number, digest } => {
                // Attempt to find an operation matching the requested digest
                if let Some(operation) = self.find_op_with_digest(&digest) {
                    // Found an operation satisfying the requested digest
                    self.communication_proxy.send(from, PBFTEvent::StateTransferResponse(StateTransferResponse::ViewChangeDigestProof {
                        sequence_number,
                        operation,
                    }));
                }
            }
            StateTransferRequest::ServiceStateItemProof { from, log_length, log_item_index } => {
                if let Some(op) = self.current_state.log().get(log_item_index as usize) {
                    // Requester presumable has validated that the checkpoint is valid so there should be a committed message
                    // at the requested sequence_number <= checkpoint_number
                    // TODO: Send more than one operation for efficiency
                    let merkle_proof = self.current_state().construct_membership_proof(&HashSet::from([log_item_index as MerkleIndex]), log_length);
                    if merkle_proof.is_none() {
                        // It was not possible creating a proof
                        return;
                    }
                    let merkle_proof = merkle_proof.unwrap();
                    self.communication_proxy.send(from, PBFTEvent::StateTransferResponse(StateTransferResponse::ServiceStateItemProof {
                        log_length,
                        log_item_index,
                        operation: op.clone(),
                        merkle_proof,
                    }));
                }
            }
        }
    }

    pub fn process_state_transfer_response(&mut self, res: StateTransferResponse<O>) {
        match res {
            StateTransferResponse::ViewChangeDigestProof { sequence_number, operation } => {
                // Check that the response is relevant to the current view change
                if let Some(digest) = self.requested_digests.get(&(sequence_number, self.view)) {
                    if !operation.digest().eq(digest) {
                        // Peer may be responding to a request digest from a past view
                        debug!("Peer {}: Dropping state transfer request with incorrect digest.", self.my_index);
                        return;
                    }

                    // In the current view, this replica attempted to resolve the operation associated
                    // with a digest. If the replica already has in its record the corresponding operation
                    // there is no point in prepreparing/preparing this newly found operation. This
                    // also prevents spamming the message log with duplicate operations.
                    //
                    // This simply records the newly found operation in the message log so that it can
                    // be found in the future.
                    if self.find_op_with_digest(digest).is_none() {
                        let data = PrepTriple {
                            sequence_number,
                            digest: *digest,
                            view: self.view,
                        };
                        self.message_log.push(PBFTEvent::PrePrepare {
                            from: self.primary(self.view),
                            data: data.clone(),
                            request: RequestPayload { op: operation, op_digest: *digest },
                        });

                        if !self.is_primary(self.my_index) {
                            let prepare = PBFTEvent::Prepare {
                                from: self.my_index,
                                data: data.clone(),
                            };
                            self.message_log.push(prepare.clone());
                            self.communication_proxy.broadcast(prepare);
                        }

                        if !self.is_view_active {
                            // The response comes back while this replica is synchronizing with other for view change
                            // and this replica does not know the operation associated with the digest.
                            //
                            // Enough information may have accumulated to perform view change
                            self.attempt_view_change();
                        } else {
                            self.attempt_commit_send(&data);
                        }
                    }
                }
            }
            StateTransferResponse::ServiceStateItemProof { log_length, log_item_index, operation, merkle_proof } => {
                if log_item_index >= log_length {
                    // Ignore messages outside the log slice in question
                    return;
                }

                if let Some((_checkpoint_number, service_state_digest)) = self.known_service_state_digests.get(&log_length) {
                    let is_proof_valid = MerkleTree::is_valid_proof(service_state_digest, &merkle_proof);
                    if !is_proof_valid {
                        // Ignore invalid proofs
                        warn!("Peer {}: Received invalid merkle proof!", self.my_index);
                        return;
                    }
                    let op_digest = operation.digest();
                    let is_operation_proven = merkle_proof.items.iter().any(|(i, d)| {
                        (*i as usize) == log_item_index && op_digest == *d
                    });
                    if !is_operation_proven {
                        // The operation provided never appeared in the membership proof
                        warn!("Peer {}: Received valid merkle proof but provided operation is not present in the proof!", self.my_index);
                        return;
                    }


                    self.current_state.insert_operation(log_item_index, operation);
                    debug!("Peer {}: Inserted log item {}/{}.", self.my_index, log_item_index, log_length - 1);

                    // Immediately after inserting this operation we synchronized the service state up to a known checkpoint
                    if let Some((checkpoint_number, _)) = self.known_service_state_digests.get(&self.current_state.log().len()) {
                        if self.last_executed >= *checkpoint_number {
                            // For safety ensure that we are moving forward in the sequence number
                            return;
                        }

                        self.last_executed = *checkpoint_number;
                        self.create_checkpoint();
                    }
                }
            }
        }
    }
}
