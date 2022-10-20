use crate::kernel::*;
use crate::kernel::view_change_manager::create_execution_watchdog;

impl<O> PBFTState<O>
where O: ServiceOperation + Serialize + DeserializeOwned + std::marker::Send + 'static
{
    pub fn check_preprepared(&mut self, data: &PrepTriple) -> bool {
        let is_preprepared_before = self.preprepared
            .get(&data.sequence_number)
            .map_or(false, |digest_map| {
                digest_map
                    .get(&data.digest)
                    .map_or(false, |v| *v == data.view)
            });
        if is_preprepared_before {
            return true;
        }

        let res = self.message_log.iter().any(|e| {
            if let PBFTEvent::PrePrepare { data: other_data, .. } = e {
                data.eq(other_data)
            } else {
                false
            }
        });

        if res {
            // Save this result to speed up future queries
            match self.preprepared.get_mut(&data.sequence_number) {
                None => {
                    let mut digest_map = HashMap::new();
                    digest_map.insert(data.digest, data.view);
                    self.preprepared.insert(data.sequence_number, digest_map);
                }
                Some(digest_map) => {
                    match digest_map.get(&data.digest) {
                        None => {
                            digest_map.insert(data.digest, data.view);
                        }
                        Some(other_view) => {
                            if data.view > *other_view {
                                digest_map.insert(data.digest, data.view);
                            } else {
                                // Validate that preprepared only holds the most recent preprepared message
                                // If the views are equal, then either the digests are equal or not.
                                // In the former case, we should have short circuited at the start.
                                // In the latter case, a safety violation occurred where two different
                                // messages have been preprepared in the same (sequence_number, view).
                                panic!("Preprepare safety violation has been detected.");
                            }
                        }
                    }
                }
            }
        }

        res
    }

    pub fn check_prepared(&mut self, data: &PrepTriple) -> bool {
        let is_prepared_before = self.prepared
            .get(&data.sequence_number)
            .map_or(false, |other_data| {
                (&data.digest, data.view) == (&other_data.digest, other_data.view)
            });
        if is_prepared_before {
            return true;
        }

        // Count the number peers we have heard execute a prepare
        let certificate_size = self.message_log.iter()
            .filter(|e| {
                if let PBFTEvent::Prepare { data: other_data, .. } = e {
                    data.eq(other_data)
                } else {
                    false
                }
            })
            .map(|e| {
                if let PBFTEvent::Prepare { from, .. } = e {
                    return *from;
                }
                panic!("Impossible case.")
            })
            .collect::<HashSet<PeerIndex>>()
            .len();

        // The replica that sent preprepare is guaranteed to not be in the certificate
        // by sending/receiving prepare precondition (which is why there is a -1).
        // Certificate proves a quorum of replicas have *preprepared* (either send a preprepare or prepare)
        // the message and it is now virtually impossible for two different messages to be prepared at the current
        // view/sequence_number pair.
        let res = self.check_preprepared(data) && certificate_size as PeerIndex >= self.quorum_size() - 1;
        if res {
            // Save this result to speed up future queries
            match self.prepared.get(&data.sequence_number) {
                None => {
                    self.prepared.insert(data.sequence_number, data.clone());
                }
                Some(other_data) => {
                    if data.view > other_data.view {
                        self.prepared.insert(data.sequence_number, data.clone());
                    } else {
                        // Validate that prepared only holds the most recent prepared message
                        // If the views are equal, then either the digests are equal or not.
                        // In the former case, we should have short circuited at the start.
                        // In the latter case, a safety violation occurred where two different
                        // messages have been prepared in the same (sequence_number, view).
                        panic!("Prepare safety violation has been detected. Old: {:?}, New: {:?}", other_data, data);
                    }
                }
            }
        }

        res
    }

    pub fn check_committed(&mut self, data: &PrepTriple) -> bool {
        // Count the number peers we have heard send a commit
        let certificate_size = self.message_log.iter()
            .filter(|e| {
                if let PBFTEvent::Commit { data: other_data, .. } = e {
                    data.eq(other_data)
                } else {
                    false
                }
            })
            .map(|e| {
                if let PBFTEvent::Commit { from, .. } = e {
                    return *from;
                }
                panic!("Impossible case.")
            })
            .collect::<HashSet<PeerIndex>>()
            .len();

        // Message has been prepared and quorum has sent commit. It is now impossible for a different message
        // to commit in any view at this sequence number!
        self.check_prepared(data) && certificate_size as PeerIndex >= self.quorum_size()
    }

    pub fn process_request(&mut self, payload: RequestPayload<O>) {
        debug!("Peer {}: Received request: {:?}", self.my_index, payload);
        create_execution_watchdog(
            self.view_change_manager.clone(),
            self.current_state.log().len(),
            self.view,
            self.execution_timeout
        );

        // As the primary, this replica is responsible for initiating a preprepare request
        if self.is_primary(self.my_index)
            && self.is_view_active
        {
            let proposed_sequence_number = self.sequence_number + 1;
            if !self.is_sequence_number_in_window(proposed_sequence_number) {
                debug!("Peer {}: Dropping the request, the message log is too full!", self.my_index);
                return;
            }

            let request_digest = payload.op_digest;

            let data = PrepTriple {
                view: self.view,
                sequence_number: proposed_sequence_number,
                digest: request_digest,
            };
            let preprepare = PBFTEvent::PrePrepare {
                from: self.my_index,
                data: data.clone(),
                request: payload,
            };
            self.message_log.push(preprepare.clone());
            // Update bookkeeping
            let _ = self.check_preprepared(&data);
            // TODO: Keep broadcasting preprepare until view change or committed
            self.communication_proxy.broadcast(preprepare);

            self.sequence_number += 1;
        }
    }

    pub fn process_preprepare(&mut self, from: PeerIndex, data: PrepTriple, request: RequestPayload<O>) {
        // Validate event
        if data.view != self.view {
            // Ignore preprepare from different views
            return;
        }
        if !self.is_primary(from) {
            // Byzantine peer detected
            info!("Peer {}: Received invalid preprepare from peer {}, who is not the primary! 🚨", self.my_index, from);
            return;
        }

        let preprepare: PBFTEvent<O> = PBFTEvent::PrePrepare {
            from,
            data: data.clone(),
            request,
        };
        if !self.is_sequence_number_in_window(data.sequence_number) {
            debug!("Peer {}: Ignoring preprepare because log is currently too full. {:?}", self.my_index, preprepare);
            return;
        }
        if !self.is_view_active {
            debug!("Peer {}: Ignoring preprepare because view is currently not active. {:?}", self.my_index, preprepare);
            return;
        }
        if self.message_log.iter().any(|e| {
            if let PBFTEvent::PrePrepare { data: other_data, .. } = e {
                (data.view, data.sequence_number) == (other_data.view, other_data.sequence_number)
            } else {
                false
            }
        }) {
            debug!("Peer {}: Ignoring this preprepare because there is already a preprepare for view={}, sequence_number={}", self.my_index, data.view, data.sequence_number);
            return;
        }

        // All preconditions passed, record this preprepare which also contains a request
        debug!("Peer {}: Got preprepare: {:?}", self.my_index, preprepare);
        self.message_log.push(preprepare);

        // Attempt to send a prepare if possible
        if !self.is_primary(self.my_index) {
            let prepare = PBFTEvent::Prepare {
                from: self.my_index,
                data: data.clone(),
            };
            self.message_log.push(prepare.clone());
            self.communication_proxy.broadcast(prepare);
        }

        // Introduction of this preprepare and prepare may be enough to achieve quorum
        //
        // This call also updates book keeping for the P and Q sets by calling
        // check_prepared() who then calls check_preprepared().
        self.attempt_commit_send(&data);
    }

    pub fn process_prepare(&mut self, from: PeerIndex, data: PrepTriple) {
        if data.view != self.view {
            debug!("Peer {}: Ignoring prepare from a different view. {:?}", self.my_index, data);
            return;
        }
        if self.is_primary(from) {
            info!("Peer {}: Received invalid prepare from primary. {:?} 🚨", self.my_index, data);
            return;
        }
        if !self.is_sequence_number_in_window(data.sequence_number) {
            debug!("Peer {}: Ignoring prepare because message log is too full. {:?}", self.my_index, data);
            return;
        }
        // Preconditions are satisfied
        let prepare = PBFTEvent::Prepare {
            from,
            data: data.clone(),
        };
        debug!("Peer {}: Received prepare. {:?}", self.my_index, prepare);
        self.message_log.push(prepare);

        // Introduction of this prepare may be enough to achieve quorum
        //
        // This call also updates book keeping for the P and Q sets by calling
        // check_prepared() who then calls check_preprepared().
        self.attempt_commit_send(&data);
    }

    pub fn attempt_commit_send(&mut self, data: &PrepTriple) {
        let has_committed_before = self.message_log.iter().any(|e| {
            if let PBFTEvent::Commit { from, data: other_data } = e {
                (self.my_index, data.view, data.sequence_number) == (*from, other_data.view, other_data.sequence_number)
            } else {
                false
            }
        });

        if has_committed_before {
            // debug!("Peer {}: Attempted to send commit, but will not commit again. {:?}", self.my_index, data);
            return;
        }

        if !self.check_prepared(data) {
            // debug!("Peer {}: Attempted to send commit, but quorum has not been achieved. {:?}", self.my_index, data);
            return;
        }

        // All preconditions passed
        debug!("Peer {}: Sending commit for {:?}", self.my_index, data);
        let commit = PBFTEvent::Commit {
            from: self.my_index,
            data: data.clone(),
        };
        self.message_log.push(commit.clone());
        self.communication_proxy.broadcast(commit);

        // Introduction of commit may be enough to achieve commit quorum
        self.attempt_execute(data);
    }

    pub fn process_commit(&mut self, from: PeerIndex, data: PrepTriple) {
        if self.view != data.view {
            // Ignore commit not in current view
            return;
        }
        if !self.is_sequence_number_in_window(data.sequence_number) {
            debug!("Peer {}: Ignoring prepare because message log is too full. {:?}", self.my_index, data);
            return;
        }
        // Preconditions passed
        let commit = PBFTEvent::Commit {
            from,
            data: data.clone(),
        };
        self.message_log.push(commit);

        // Introduction of commit may be enough to achieve commit quorum
        self.attempt_execute(&data);
    }

    pub fn create_checkpoint(&mut self) {
        // Only create checkpoints at certain intervals
        if self.last_executed % self.checkpoint_interval != 0 {
            return;
        }

        let current_state_summary = self.current_state.summarize();
        let data = CheckpointSummary {
            sequence_number: self.last_executed,
            service_state_summary: current_state_summary,
        };
        let checkpoint_event = PBFTEvent::Checkpoint {
            from: self.my_index,
            data: data.clone()
        };
        self.message_log.push(checkpoint_event.clone());
        self.communication_proxy.broadcast(checkpoint_event);
        debug!("Peer {}: Created checkpoint at {}.", self.my_index, self.last_executed);

        self.checkpoints.push(CheckpointSummary {
            sequence_number: self.last_executed,
            service_state_summary: self.current_state.summarize(),
        });

        self.collect_garbage(&data);
    }

    pub fn process_checkpoint(&mut self, from: PeerIndex, data: CheckpointSummary) {
        if !self.is_sequence_number_in_window(data.sequence_number) {
            debug!("Peer {}: Ignoring checkpoint at {} because message log is too full.", self.my_index, data.sequence_number);
        }

        self.message_log.push(PBFTEvent::Checkpoint {
            from,
            data: CheckpointSummary {
                sequence_number: data.sequence_number,
                service_state_summary: data.service_state_summary.clone(),
            },
        });
        debug!("Peer {}: Received checkpoint at {}.", self.my_index, self.last_executed);
        self.collect_garbage(&data);
    }
}