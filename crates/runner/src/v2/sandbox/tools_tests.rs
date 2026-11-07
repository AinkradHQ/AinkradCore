use super::ProcessSandbox;
use crate::v2::agent::Sandbox;

#[test]
fn the_tools_capability_follows_its_own_proof_on_linux_only() {
    let plain = ProcessSandbox::new("/state".into(), "/secrets".into());
    assert!(!plain.capabilities().contains(&"connection-tools"));
    let sandbox = ProcessSandbox::new("/state".into(), "/secrets".into())
        .with_egress_ready()
        .with_gateway_ready()
        .with_tools_ready();
    assert_eq!(
        sandbox.capabilities().contains(&"connection-tools"),
        cfg!(target_os = "linux")
    );
    assert!(sandbox.capabilities().contains(&"egress-filter"));
}
