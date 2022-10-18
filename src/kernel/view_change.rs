use crate::kernel::*;

// Helper function to convert wrapped view change into a view change
fn convert_to_view_change<O: ServiceOperation>(event: &WrappedPBFTEvent<O>) -> &ViewChange {
    match &event.event {
        PBFTEvent::ViewChange(data) => { data }
        _ => { panic!("Cannot convert to view change!") }
    }
}

impl<O> PBFTState<O>
    where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{

    pub fn process_view_change(&mut self, view_change: WrappedPBFTEvent<O>) {
        let data = match &view_change.event {
            PBFTEvent::ViewChange(data) => { data }
            _ => {
                warn!("Attempted to process a wrapped event that is not a view change!");
                return;
            }
        };

        if self.primary(data.view) != self.my_index {
            // TODO: Activate timeout after hearing a quorum of view changes in the same current view
            // TODO: Perform a view change when a weak certificate has been made for a strictly higher view
            debug!("Peer {}: Dropping view change as not primary.", self.my_index);
            return;
        }

        if self.view() > data.view {
            debug!("Peer {}: Dropping view change as currently in higher view.", self.my_index);
            return;
        }

        if self.view_change_log.iter().map(convert_to_view_change).any(|change| {
            (change.from, change.view) == (data.from, data.view)
        }) {
            debug!("Peer {}: Dropping view change as already received from change from peer.", self.my_index);
            return;
        }

        // Check that the data in view change is correct
        if !data.prepared.iter().all(|prep| {
            let (n, v) = (prep.sequence_number, prep.view);
            v < data.view
                && data.log_low_mark < n
                && n <= data.log_low_mark + self.sequence_window_length
        }) {
            debug!("Peer {}: Received view change from peer {} with malformed prepared field!", self.my_index, data.from);
            return;
        }
        if !data.preprepared.iter().all(|prep| {
            let (n, v) = (prep.sequence_number, prep.view);
            v < data.view
                && data.log_low_mark < n
                && n <= data.log_low_mark + self.sequence_window_length
        }) {
            debug!("Peer {}: Received view change from peer {} with malformed preprepared field!", self.my_index, data.from);
            return;
        }


        // All preconditions passed
        self.view_change_log.push(view_change);
        self.attempt_new_view();
    }

    pub fn attempt_new_view(&mut self) {
        // Find all view changes relevant to the current view that this replica is a primary of so
        // that this replica can broadcast a new view change
        let view_changes_iter = self.view_change_log.iter()
            .map(convert_to_view_change)
            .filter(|change| change.view == self.view);

        // Compute the selected checkpoint
        let selected_checkpoint = view_changes_iter.clone()
            .flat_map(|change| change.checkpoints.iter())
            .filter(|candidate| self.is_valid_selected_checkpoint(view_changes_iter.clone(), *candidate))
            .max_by_key(|checkpoint_digest| checkpoint_digest.sequence_number);

        if selected_checkpoint.is_none() {
            // It is not possible to create a new view
            return;
        }

        let selected_checkpoint = selected_checkpoint.unwrap().clone();
        let selected_log_low = selected_checkpoint.sequence_number;

        // Select requests for the new view
        let mut selected_messages = vec![];
        for n in selected_log_low + 1..=selected_log_low + self.sequence_window_length {
            // Attempt to select any previously committed message at sequence number n
            // Look at all prepared messages at the sequence number n
            let committed_msg = view_changes_iter.clone()
                .flat_map(|change| {
                    // Get all prepared messages with sequence number at the target n
                    change.prepared.iter()
                        .filter(|prep| prep.sequence_number == n)
                })
                .find(|candidate| {
                    self.is_justified_by_a1(view_changes_iter.clone(), candidate)
                        && self.is_justified_by_a2(view_changes_iter.clone(), candidate)
                });
            // We were able to select a message!
            if let Some(prep) = committed_msg {
                selected_messages.push(Some(prep.clone()));
                continue;
            }

            if self.is_condition_b_viable(view_changes_iter.clone(), n) {
                // Condition B holds so add a no-op operation
                selected_messages.push(None);
            } else {
                // No message can be selected
                return;
            }
        }

        // View change is possible
        // Package all the view changes received as a collection of proofs
        let view_change_proofs = self.view_change_log.iter()
            .map(|e| {
                e.witness()
            })
            .cloned()
            .collect();
        let new_view = NewView {
            from: self.my_index,
            view: self.view,
            view_change_proofs,
            selected_checkpoint,
            selected_messages,
        };
        self.process_new_view(new_view.clone());
        self.communication_proxy.broadcast(PBFTEvent::NewView(new_view));
        debug!("Peer {}: Generated new view proof for view {}.", self.my_index, self.view);
    }

    pub fn process_new_view(&mut self, data: NewView) {
        // TODO: Collect garbage on old view data in both the manager and PBFT state
        if data.view == 0 {
            debug!("Peer {}: Dropping new view for view 0", self.my_index);
            return;
        }
        if data.view < self.view {
            debug!("Peer {}: Dropping new view for a previous view.", self.my_index);
            return;
        }
        if self.primary(data.view) != data.from {
            info!("Peer {}: Dropping new view (view = {}) from peer {} who is not the primary.", self.my_index, data.view, data.from);
            return;
        }
        if self.new_view_log.contains_key(&data.view) {
            // Ignore a view we already have
            return;
        }

        // Validate the view change data to ensure proof is not malformed
        let wrapped_view_changes = data.view_change_proofs.iter()
            .map(|payload| {
                self.communication_proxy.validate_signed_payload(payload.clone())
            })
            .collect::<Vec<Result<WrappedPBFTEvent<O>, _>>>();

        let valid_view_change_proofs = wrapped_view_changes.iter()
            .all(|result| {
                match result {
                    Ok(e) => {
                        matches!(&e.event, PBFTEvent::ViewChange(_))
                    }
                    Err(_) => {
                        // The signed payload could not be properly validated
                        false
                    }
                }
            });

        if !valid_view_change_proofs {
            info!("Peer {}: Dropping new view (view = {}) from peer {} who provided invalid new view proofs.", self.my_index, data.view, data.from);
            return;
        }

        // Convert all the proofs into view changes now that they have all been confirmed to be valid
        let wrapped_view_changes = wrapped_view_changes.into_iter()
            .map(|r| {
                r.unwrap()
            })
            .collect::<Vec<WrappedPBFTEvent<O>>>();
        let view_changes_iter = wrapped_view_changes.iter().map(convert_to_view_change);

        let num_viewchangers = view_changes_iter.clone()
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len();

        if num_viewchangers < data.view_change_proofs.len() {
            // This check probably does not affect safety of view change protocol but it is a good sanity check to include.
            // Nobody should be submitting two different view change.
            info!("Peer {}: Dropping new view (view = {}) from peer {} who included a double voter!.", self.my_index, data.view, data.from);
            return;
        }

        // Validate selected checkpoint
        if !self.is_valid_selected_checkpoint(view_changes_iter.clone(), &data.selected_checkpoint) {
            info!("Peer {}: Dropping new view (view = {}) from peer {} with invalid log low mark.", self.my_index, data.view, data.from);
            return;
        }

        // Validate selected requests
        if data.selected_messages.len() != self.sequence_window_length as usize {
            info!("Peer {}: Dropping new view (view = {}) from peer {} with not enough selected requests.", self.my_index, data.view, data.from);
            return;
        }

        let h = data.selected_checkpoint.sequence_number;
        for n in h + 1..=h + self.sequence_window_length {
            let selected_message = data.selected_messages.get((n - h - 1) as usize);
            if selected_message.is_none() {
                // This should be impossible
                info!("Peer {}: Dropping new view (view = {}) from peer {} with not enough selected requests.", self.my_index, data.view, data.from);
                return;
            }
            let selected_message = selected_message.unwrap();
            match selected_message {
                None => {
                    if !self.is_condition_b_viable(view_changes_iter.clone(), n) {
                        info!("Peer {}: Dropping new view (view = {}) from peer {} who chose an invalid noop request.", self.my_index, data.view, data.from);
                        return;
                    }
                }
                Some(chosen_prep) => {
                    if chosen_prep.sequence_number != n {
                        info!("Peer {}: Dropping new view (view = {}) from peer {} who chose a request with incorrect sequence number.", self.my_index, data.view, data.from);
                        return;
                    }

                    let chosen_from_prepared = view_changes_iter.clone()
                        .any(|change| {
                            change.prepared.contains(chosen_prep)
                        });

                    if !chosen_from_prepared {
                        info!("Peer {}: Dropping new view (view = {}) from peer {} who chose a request not among those prepared.", self.my_index, data.view, data.from);
                        return;
                    }

                    // Check condition A1
                    if !self.is_justified_by_a1(view_changes_iter.clone(), chosen_prep) {
                        info!("Peer {}: Dropping new view (view = {}) from peer {} who chose a request unsupported by a quorum.", self.my_index, data.view, data.from);
                        return;
                    }

                    // Check condition A2
                    if !self.is_justified_by_a2(view_changes_iter.clone(), chosen_prep) {
                        info!("Peer {}: Dropping new view (view = {}) from peer {} who chose a request unsupported by a weak certificate.", self.my_index, data.view, data.from);
                        return;
                    }
                }
            }
        }

        // The new view message received is valid
        debug!("Peer {}: Accepted new view for view {}.", self.my_index, data.view);
        self.new_view_log.insert(data.view, data);

        self.attempt_view_change();
    }

    pub fn attempt_view_change(&mut self) {
        if self.is_view_active {
            // Don't view change while in an active view
            return;
        }
        if self.new_view_log.get(&self.view).is_none() {
            // Can't view change. No valid new view message has been received for this view
            return;
        }

        let new_view = self.new_view_log.get(&self.view).unwrap();
        let h = self.log_low_mark();
        if h < new_view.selected_checkpoint.sequence_number {
            debug!("Peer {}: Cannot view change because log low mark is behind.", self.my_index);
            // Attempt to synchronize up to the new view selected checkpoint
            self.synchronize_up_to_checkpoint(&new_view.selected_checkpoint.clone());
            return;
        }
        debug!("Peer {}: Synchronized up to checkpoint for view change!.", self.my_index);

        for selected_message in new_view.selected_messages.iter() {
            match selected_message {
                None => {
                    // All replica have the noop operation
                    continue;
                }
                Some(selected_message) => {
                    match self.find_op_with_digest(&selected_message.digest) {
                        None => {
                            // No such message has been found attempt to synchronize
                            self.requested_digests.insert((selected_message.sequence_number, new_view.view), selected_message.digest.clone());
                            self.communication_proxy.broadcast(PBFTEvent::StateTransferRequest(StateTransferRequest::ViewChangeDigestProof {
                                from: self.my_index,
                                sequence_number: selected_message.sequence_number,
                                digest: selected_message.digest.clone(),
                            }));
                            // TODO: Improve this to obtain many proofs in parallel without generating a lot of traffic
                            // Exit because the replica is not synchronized on the digests
                            return;
                        },
                        Some(op) => {
                            // Check that the message has been prepared and prepared in this view
                            let is_preprepared = self.message_log().iter().any(|e| {
                                if let PBFTEvent::PrePrepare {data, ..} = e {
                                    (data.sequence_number, data.view) == (selected_message.sequence_number, self.view)
                                } else {
                                    false
                                }
                            });
                            let is_prepared = self.message_log().iter().any(|e| {
                                if let PBFTEvent::Prepare {data, ..} = e {
                                    (data.sequence_number, data.view) == (selected_message.sequence_number, self.view)
                                } else {
                                    false
                                }
                            });

                            let data = PrepTriple {
                                sequence_number: selected_message.sequence_number,
                                digest: selected_message.digest.clone(),
                                view: self.view
                            };
                            if !is_preprepared {
                                self.message_log.push(PBFTEvent::PrePrepare {
                                    from: self.primary(new_view.view),
                                    data: data.clone(),
                                    request: RequestPayload { op, op_digest: data.digest.clone() },
                                });
                            }
                            if !is_prepared && self.primary(new_view.view) != self.my_index {
                                let prepare = PBFTEvent::Prepare {
                                    from: self.my_index,
                                    data: data.clone(),
                                };
                                self.message_log.push(prepare.clone());
                                self.communication_proxy.broadcast(prepare)
                            }
                        }
                    }
                }
            }
        }
        debug!("Peer {}: Synchronized! Moving into the new view...", self.my_index);
        // All non noop operations have been preprepared and prepared (if applicable).
        // Preprepare and prepare all noops;
        let noop = O::noop();
        let noop_digest = noop.digest();
        for (i, _) in new_view.selected_messages.iter().enumerate().filter(|(_i, m)| m.is_none()) {
            let n = h + i as SequenceNumber + 1;
            let data = PrepTriple {
                sequence_number: n,
                digest: noop_digest.clone(),
                view: new_view.view,
            };
            self.message_log.push(PBFTEvent::PrePrepare {
                from: self.primary(new_view.view),
                data: data.clone(),
                request: RequestPayload { op: noop.clone(), op_digest: noop_digest.clone() },
            });
            if self.primary(new_view.view) != self.my_index {
                let prepare = PBFTEvent::Prepare {
                    from: self.my_index,
                    data: data.clone(),
                };
                self.message_log.push(prepare.clone());
                self.communication_proxy.broadcast(prepare)
            }
        }

        // All messages have been synchronized
        self.is_view_active = true;

        let synchronized_preps = self.message_log.iter()
            .filter_map(|e| {
                match e {
                    PBFTEvent::PrePrepare { data, .. } => { Some(data) }
                    PBFTEvent::Prepare { data, .. } => { Some(data) }
                    _ => { None }
                }
            })
            .filter(|data| data.view == self.view)
            .collect::<HashSet<&PrepTriple>>();

        // Satisfy the borrow checker by cloning all the synchronized preps
        let synchronized_preps = synchronized_preps.into_iter().cloned().collect::<HashSet<PrepTriple>>();
        // Introduction of new preprepare and prepare could enable a commit
        for prep in synchronized_preps {
            self.attempt_commit_send(&prep);
        }

        self.sequence_number = self.message_log.iter().filter_map(|e| {
            if let PBFTEvent::PrePrepare {data, ..} = e {
                Some(data.sequence_number)
            } else {
                None
            }
        }).max().unwrap_or(0);

        // We just moved into a new view so trash all data less than the current one.
        self.new_view_log.retain(|v, _| *v > self.view);
        self.requested_digests = Default::default();
        info!("Peer {}: Successfully moved into view {}.", self.my_index, self.view);
    }

    pub fn is_valid_selected_checkpoint<'a, I: Iterator<Item=&'a ViewChange> + Clone>(&self, view_changes: I, candidate: &CheckpointSummary) -> bool {
        let is_stable = view_changes.clone()
            .filter(|change| change.log_low_mark <= candidate.sequence_number)
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len() >= self.quorum_size() as usize;

        if !is_stable {
            return false;
        }

        // Check liveliness
        view_changes
            .filter(|change| change.checkpoints.contains(candidate))
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len() >= self.weak_certificate_size() as usize
    }

    pub fn is_justified_by_a1<'a, I: Iterator<Item=&'a ViewChange>>(&self, view_changes: I, candidate: &PrepTriple) -> bool {
        let n = candidate.sequence_number;
        let v = candidate.view;

        // Fig 4 Condition A1 of PBFT paper
        view_changes
            .filter(|change| {
                change.log_low_mark < n
                    && change.prepared.iter()
                    .filter(|prep| prep.sequence_number == n)
                    .all(|other| {
                        other.view < v || (other.view, &other.digest) == (v, &candidate.digest)
                    })
            })
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len() >= self.quorum_size() as usize
    }

    pub fn is_justified_by_a2<'a, I: Iterator<Item=&'a ViewChange>>(&self, view_changes: I, candidate: &PrepTriple) -> bool {
        let n = candidate.sequence_number;
        // Fig 4 Condition A2 of PBFT paper
        view_changes
            .filter(|change| {
                change.preprepared.iter()
                    .any(|other| {
                        (other.sequence_number, &other.digest) == (n, &candidate.digest)
                            && other.view >= candidate.view
                    })
            })
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len() >= self.weak_certificate_size() as usize
    }

    pub fn is_condition_b_viable<'a, I: Iterator<Item=&'a ViewChange>>(&self, view_changes: I, sequence_number: SequenceNumber) -> bool {
        let n = sequence_number;
        // Check Fig 4 Condition B
        view_changes
            .filter(|change| {
                change.log_low_mark < n
                    && change.prepared.iter().all(|other| other.sequence_number != n)
            })
            .map(|change| change.from)
            .collect::<HashSet<PeerIndex>>()
            .len() >= self.quorum_size() as usize
    }
}