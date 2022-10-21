use std::path::PathBuf;
use pbft_library::pbft_replica::generate_config_skeleton;

fn main() {
    generate_config_skeleton(PathBuf::from("./replica-test-config/replica0"));
    generate_config_skeleton(PathBuf::from("./replica-test-config/replica1"));
    generate_config_skeleton(PathBuf::from("./replica-test-config/replica2"));
    generate_config_skeleton(PathBuf::from("./replica-test-config/replica3"));
}