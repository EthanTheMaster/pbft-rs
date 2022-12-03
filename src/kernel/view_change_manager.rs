use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch::{channel, Receiver, Sender};
use tokio::time::sleep;
use crate::kernel::*;

pub type AtomicViewChangeManager = Arc<Mutex<ViewChangeManager>>;

#[derive(Debug)]
pub struct ViewChangeManager {
    // The length of time that this replica will stay in a view before moving forward to keep rotating primaries
    view_stay_timeout: Duration,

    // Fields that summarizes the last seen state of the PBFT replica
    last_seen_primary: PeerIndex,
    last_seen_view: ViewstampId,
    last_seen_active_view: bool,
    last_seen_log_length: usize,

    // This value represents what the manager would like the replica to transition into
    requested_view_change: ViewstampId,
    // Channel to alert of view change requests
    requested_view_change_tx: Sender<ViewstampId>,
    requested_view_change_rx: Receiver<ViewstampId>
}

impl ViewChangeManager {
    pub fn new(view_stay_timeout: Duration) -> AtomicViewChangeManager {
        let (tx, rx) = channel(0);
        let manager = ViewChangeManager {
            view_stay_timeout,
            last_seen_primary: 0,
            last_seen_view: 0,
            last_seen_active_view: true,
            last_seen_log_length: 0,
            requested_view_change: 0,
            requested_view_change_tx: tx,
            requested_view_change_rx: rx
        };
        let res = Arc::new(Mutex::new(manager));

        // Now that the replica is (successfully) initialized into view 0, schedule a view change into
        // the next view, view 1.
        schedule_view_change_timeout(res.clone(), 1, view_stay_timeout);

        res
    }

    pub fn requested_view_change_rx(&self) -> Receiver<ViewstampId> {
        self.requested_view_change_rx.clone()
    }

    fn alert_requested_view_change(&mut self, new_view: ViewstampId) {
        // Ensure the requested views always strictly increase
        if new_view > self.requested_view_change {
            self.requested_view_change = new_view;
            let _ = self.requested_view_change_tx.send(new_view);
        }
    }

}

// Transaction that atomically alters the last seen PBFT state
pub fn atomic_update_state(
    manager: AtomicViewChangeManager,
    last_seen_primary: PeerIndex,
    last_seen_view: ViewstampId,
    last_seen_active_view: bool,
    last_seen_log_length: usize
) -> bool
{
    let manager_clone = manager.clone();
    let manager = manager.lock();
    match manager {
        Ok(mut manager) => {
            // The PBFT replica has just updated its state from an inactive view to an active view.
            // We now need to schedule a view change for the future.
            if !manager.last_seen_active_view && last_seen_active_view {
                schedule_view_change_timeout(manager_clone, last_seen_view + 1, manager.view_stay_timeout);
            }

            // Atomically update the state of the replica
            manager.last_seen_primary = last_seen_primary;
            manager.last_seen_view = last_seen_view;
            manager.last_seen_active_view = last_seen_active_view;
            manager.last_seen_log_length = last_seen_log_length;
            true
        }
        Err(_) => {
            warn!("Failed to obtain lock on view change manager.");
            false
        }
    }
}

// Establishes a deadline to include a new message to the message log, after which
// a view change occurs. This is used after a request is received to ensure the system
// makes progress as requests arrive.
//
// The watchdog should be used to ensure that the service is live while in the normal operation.
// If the replica is not in an active view, this watchdog can cause excessive view changing.
pub fn create_execution_watchdog(
    manager: AtomicViewChangeManager,
    current_log_length: usize,
    current_view: ViewstampId,
    timeout_duration: Duration
) {
    tokio::spawn(async move {
        sleep(timeout_duration).await;
        let manager = manager.lock();
        if manager.is_err() {
            return;
        }
        let mut manager = manager.unwrap();
        if manager.last_seen_log_length > current_log_length {
            // Progress has been made so no need to engage in view change
            return;
        }

        info!("Execution did not occur before deadline. Performing a view change into view {}.", current_view + 1);
        let next_view = current_view + 1;
        manager.alert_requested_view_change(next_view);
    });
}

// Creates a deadline for the replica to transition to being active in the provided view
// Nothing will happen if the replica is in a lower view
pub fn create_successful_view_change_watchdog(
    manager: AtomicViewChangeManager,
    view: ViewstampId,
    timeout_duration: Duration
) {
    tokio::spawn(async move {
        sleep(timeout_duration).await;
        let manager = manager.lock();
        if manager.is_err() {
            return;
        }
        let mut manager = manager.unwrap();
        if manager.last_seen_view > view {
            // Replica has already moved forward and there is no point in requesting that it
            // enter a previous view
            return;
        }

        let next_view = view + 1;
        if manager.last_seen_view == view && !manager.last_seen_active_view {
            // The replica is still inactive in the view so view change
            info!("Successful view change did not occur before deadline. Performing a view change into view {}.", view + 1);
            manager.alert_requested_view_change(next_view);
        }

        // If last_seen_view < view or last_seen_active_view, do nothing
        // It is not a good idea to transition if the replica is still active as that could
        // negatively liveliness. A different test should be used to view change in an active view.
    });
}

// Waits for the provided duration before scheduling a view change
pub fn schedule_view_change_timeout(
    manager: AtomicViewChangeManager,
    new_view: ViewstampId,
    timeout: Duration
) {
    tokio::spawn(async move {
        sleep(timeout).await;
        debug!("View change manager: Stay in current view has elapsed. Scheduled a view change into view {}.", new_view);
        schedule_view_change(manager, new_view);
    });
}

pub fn schedule_view_change(
    manager: AtomicViewChangeManager,
    new_view: ViewstampId,
) {
    let manager = manager.lock();
    if manager.is_err() {
        return;
    }
    let mut manager = manager.unwrap();
    manager.alert_requested_view_change(new_view);
}
