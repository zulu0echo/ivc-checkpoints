//! Synthetic epoch workloads at illustrative scales. Produces the op stream, the initial
//! IVC state, and the ordered payee nets.

use ark_bn254::Fr;
use ledger_circuit::{native::EpochExecutor, EpochStepInput, OpWitness, BATCH, DEPTH};

use crate::{field_key, ExitWitness, NetEntry};

/// Workload shape. Loads fund accounts; spends move value to payees; one withdraw
/// per payee settles its net at epoch close.
#[derive(Clone, Copy, Debug)]
pub struct WorkloadSpec {
    pub n_accounts: usize,
    pub n_payees: usize,
    pub loads: usize,
    pub spends: usize,
    /// If set, pad the epoch with all-inactive (no-op) fold steps up to this many steps, so
    /// the public step count `i` is CONSTANT regardless of real op volume. Closes the
    /// epoch-op-count metadata leak (see docs/TRUST_MODEL.md §Privacy). `None` = no padding.
    pub pad_to_steps: Option<usize>,
}

impl WorkloadSpec {
    /// A few-hundred-op epoch: the CI / definition-of-done small path.
    pub fn small() -> Self {
        Self { n_accounts: 8, n_payees: 3, loads: 120, spends: 60, pad_to_steps: None }
    }

    /// A large (national-scale) daily epoch: ~42,705 ops, 42 payees.
    pub fn large_daily() -> Self {
        // ~1.28M ops/month at daily epochs; loads:spends ≈ 0.43:0.57.
        Self {
            n_accounts: 9_328,
            n_payees: 42,
            loads: 18_240,
            spends: 24_423,
            pad_to_steps: None,
        }
    }

    pub fn total_ops(&self) -> usize {
        self.loads + self.spends + self.n_payees
    }

    pub fn with_pad_to_steps(mut self, steps: Option<usize>) -> Self {
        self.pad_to_steps = steps;
        self
    }
}

pub struct Workload {
    pub token_id: u32,
    pub z0: Vec<Fr>,
    /// Native z_n = [stateRoot, opsAcc, netsAcc] — the prover cross-checks Nova against this.
    pub native_zn: Vec<Fr>,
    pub batches: Vec<EpochStepInput<Fr, BATCH, DEPTH>>,
    pub nets: Vec<NetEntry>,
    pub transfers_root: [u8; 32],
    pub op_count: usize,
    /// One account's escape-hatch witness at the final proven state (for exercising `exit`).
    pub exit: ExitWitness,
}

/// Build a synthetic epoch. Deterministic given `spec` and `epoch`.
pub fn build(spec: WorkloadSpec, epoch: u64) -> Workload {
    let token_id: u32 = 1;
    let token = Fr::from(token_id as u64);
    let mut exec = EpochExecutor::<Fr, DEPTH>::new();

    // --- genesis registration ------------------------------------------------
    // Settlement sink, registered with the epoch token (withdraws move value into it).
    let sink = exec.sink_key();
    exec.register(sink, token, 0, 0);

    let pool = Fr::from(7u64); // org pool account
    // Fund the pool with enough to cover every load.
    let pool_funding: u128 = (spec.loads as u128 + 1) * 1_000;
    exec.register(pool, token, pool_funding, 0);

    // Accounts: address-keyed (like payees), so an owner can later exit via the escape hatch.
    let mut account_addrs: Vec<[u8; 20]> = Vec::with_capacity(spec.n_accounts);
    let mut accounts: Vec<Fr> = Vec::with_capacity(spec.n_accounts);
    for i in 0..spec.n_accounts {
        let mut addr = [0u8; 20];
        addr[0] = 0xAC; // distinct prefix from payees (which start 0x00)
        addr[19] = (i & 0xff) as u8;
        addr[18] = ((i >> 8) & 0xff) as u8;
        let key = field_key(addr, token_id);
        exec.register(key, token, 0, 0);
        account_addrs.push(addr);
        accounts.push(key);
    }

    // Payees: on-chain addresses + matching field keys.
    let mut payee_addrs: Vec<[u8; 20]> = Vec::with_capacity(spec.n_payees);
    let mut payee_keys: Vec<Fr> = Vec::with_capacity(spec.n_payees);
    for r in 0..spec.n_payees {
        let mut addr = [0u8; 20];
        addr[19] = (r as u8).wrapping_add(1);
        addr[18] = (r >> 8) as u8;
        let key = field_key(addr, token_id);
        exec.register(key, token, 0, 0);
        payee_addrs.push(addr);
        payee_keys.push(key);
    }

    let z0 = exec.initial_state().to_vec();

    // --- op stream -----------------------------------------------------------
    let mut ops: Vec<OpWitness<Fr, DEPTH>> = Vec::with_capacity(spec.total_ops());

    // loads: pool -> account (round-robin), 1000 each so accounts can spend.
    for i in 0..spec.loads {
        let b = accounts[i % spec.n_accounts.max(1)];
        ops.push(exec.load(pool, b, token, 1_000));
    }
    // spends: account -> payee (round-robin), amount 1.
    for i in 0..spec.spends {
        let b = accounts[i % spec.n_accounts.max(1)];
        let r_idx = i % spec.n_payees.max(1);
        ops.push(exec.spend(b, payee_keys[r_idx], token, 1));
    }
    // withdraws: settle each payee's accrued net, in payee order.
    // net(r) = number of spends routed to r.
    let mut net_amounts = vec![0u128; spec.n_payees];
    for i in 0..spec.spends {
        net_amounts[i % spec.n_payees.max(1)] += 1;
    }
    for r in 0..spec.n_payees {
        if net_amounts[r] > 0 {
            ops.push(exec.withdraw(payee_keys[r], token, net_amounts[r]));
        }
    }

    let native_zn = exec.state().to_vec();

    // Escape-hatch witness for account 0 (which retains a nonzero balance) at the final root.
    let (balance, nonce, siblings, is_right) =
        exec.exit_witness(accounts[0]).expect("account 0 registered");
    let exit = ExitWitness {
        owner: account_addrs[0],
        token_id,
        key: accounts[0],
        balance,
        nonce,
        siblings,
        is_right,
    };

    // nets in the exact order the circuit folded them (executor.nets).
    let nets: Vec<NetEntry> = exec
        .nets
        .iter()
        .map(|(key, _tok, amount)| {
            let idx = payee_keys.iter().position(|k| k == key).expect("known payee key");
            NetEntry { addr: payee_addrs[idx], key: *key, amount: *amount }
        })
        .collect();

    let transfers_root = transfers_root_for(epoch);
    let op_count = ops.len();
    let mut batches = crate::chunk_into_batches(ops);

    // Constant-`i` padding: append all-inactive (no-op) steps so the public step count is
    // fixed. Inactive ops leave z unchanged in-circuit, so native_zn is still correct.
    if let Some(target) = spec.pad_to_steps {
        assert!(
            batches.len() <= target,
            "epoch needs {} steps but pad target is {}",
            batches.len(),
            target
        );
        while batches.len() < target {
            batches.push(EpochStepInput::default());
        }
    }

    Workload { token_id, z0, native_zn, batches, nets, transfers_root, op_count, exit }
}

fn transfers_root_for(epoch: u64) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(b"transfersRoot");
    h.update(epoch.to_be_bytes());
    h.finalize().into()
}
