//! End-to-end company flows (E8, E9): the server, a real runner and fake agents that play a
//! script per run (`stage`), so every step of a multi-agent flow is deterministic.

mod company {
    mod code_mode;
    mod done;
    mod forges;
    mod knowledge;
    mod lease;
    mod linear;
    mod multi_repo;
    mod phase_b;
    mod profile;
    mod push_confirmed;
    mod push_failures;
    #[allow(dead_code)]
    pub mod stage;
}
