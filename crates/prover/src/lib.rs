//! Epoch prover: builds a synthetic epoch, folds it with Nova+CycleFold, produces the
//! DeciderEth proof, verifies it in a revm instance, and emits the generated
//! `NovaDecider.sol` plus settlement calldata/artifacts for the Foundry contracts.
//!
//! Type instantiation follows sonobe's `examples/full_flow.rs` exactly (Nova over
//! BN254/Grumpkin, KZG + Pedersen commitments, Groth16 decider).

use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;

use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::{
        nova::{decider_eth::Decider as DeciderEth, Nova, PreprocessorParam},
        traits::CommittedInstanceOps,
    },
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Decider, FoldingScheme,
};
use solidity_verifiers::{
    calldata::{get_formatted_calldata, prepare_calldata_for_nova_cyclefold_verifier, NovaVerificationMode},
    evm::{compile_solidity, Evm},
    verifiers::nova_cyclefold::get_decider_template_for_cyclefold_decider,
    NovaCycleFoldVerifierKey,
};

use ledger_circuit::{EpochStepInput, LedgerCircuit, OpWitness, BATCH, DEPTH};

pub mod poseidon_codegen;
pub mod workload;

/// F-circuit instantiation: batch 16, depth 22.
pub type Fc = LedgerCircuit<Fr, BATCH, DEPTH>;
pub type NovaFc = Nova<G1, G2, Fc, KZG<'static, Bn254>, Pedersen<G2>, false>;
pub type DeciderFc =
    DeciderEth<G1, G2, Fc, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, NovaFc>;

/// A single settled payee net: on-chain address, its field key (as used in the
/// circuit's `netsAcc`), and the amount. `key == fieldKey(addr, tokenId)`.
#[derive(Clone, Debug)]
pub struct NetEntry {
    pub addr: [u8; 20],
    pub key: Fr,
    pub amount: u128,
}

/// An account's escape-hatch witness at the final proven state: enough to open its leaf against
/// `stateRoot` on-chain and pull its balance. `key == fieldKey(owner, tokenId)`.
#[derive(Clone, Debug)]
pub struct ExitWitness {
    pub owner: [u8; 20],
    pub token_id: u32,
    pub key: Fr,
    pub balance: u128,
    pub nonce: u64,
    pub siblings: Vec<Fr>,   // len DEPTH
    pub is_right: Vec<bool>, // len DEPTH (true => this node is the right child)
}

/// Everything the Foundry side needs to exercise `settleEpochProven` for one epoch.
pub struct EpochArtifacts {
    pub epoch: u64,
    pub token_id: u32,
    pub steps: usize,
    /// z_0 = [prevStateRoot, 0, 0]
    pub z0: Vec<Fr>,
    /// z_n = [newStateRoot, opsAcc, netsAcc]
    pub zn: Vec<Fr>,
    /// The 25-word opaque decider proof (input to `verifyOpaqueNovaProofWithInputs`).
    pub proof_words: Vec<String>,
    /// Full Explicit-mode calldata (for a direct `NovaDecider.verifyNovaProof` test).
    pub calldata_explicit: Vec<u8>,
    pub nets: Vec<NetEntry>,
    pub transfers_root: [u8; 32],
    pub decider_sol: String,
    // measurements
    pub fold_times_ms: Vec<u128>,
    pub decider_prove_ms: u128,
    pub evm_verify_gas: u64,
    pub calldata_bytes: usize,
}

/// True if a `solc` binary is on PATH (sonobe's `compile_solidity` requires it).
fn solc_available() -> bool {
    std::process::Command::new("solc")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Derive a payee's field key the same way `ProvenCheckpoint._fieldKey` does on-chain:
/// `uint256(keccak256(abi.encodePacked(addr, uint32(tokenId)))) mod r`.
pub fn field_key(addr: [u8; 20], token_id: u32) -> Fr {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(addr);
    h.update(token_id.to_be_bytes());
    let digest = h.finalize();
    Fr::from_be_bytes_mod_order(&digest)
}

/// Serialize a field element as a 0x-prefixed 32-byte big-endian hex string.
pub fn fr_to_hex(x: &Fr) -> String {
    let mut bytes = x.into_bigint().to_bytes_be();
    // BN254 Fr fits in 32 bytes.
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    format!("0x{}", hex::encode(bytes))
}

/// Fold an epoch (already chunked into `B`-op batches) and produce the decider proof and
/// all on-chain artifacts. `z0` is the epoch's initial IVC state `[prevRoot, 0, 0]`.
pub fn prove_epoch(
    epoch: u64,
    token_id: u32,
    z0: Vec<Fr>,
    batches: Vec<EpochStepInput<Fr, BATCH, DEPTH>>,
    nets: Vec<NetEntry>,
    transfers_root: [u8; 32],
) -> anyhow::Result<EpochArtifacts> {
    let f_circuit = Fc::new(()).map_err(|e| anyhow::anyhow!("FCircuit::new: {e:?}"))?;
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = ark_std::rand::rngs::OsRng;

    // Nova prover/verifier params.
    let nova_pp = PreprocessorParam::new(poseidon_config.clone(), f_circuit.clone());
    let nova_params =
        NovaFc::preprocess(&mut rng, &nova_pp).map_err(|e| anyhow::anyhow!("nova preprocess: {e:?}"))?;

    // Decider prover/verifier params.
    let (decider_pp, decider_vp) =
        DeciderFc::preprocess(&mut rng, (nova_params.clone(), f_circuit.state_len()))
            .map_err(|e| anyhow::anyhow!("decider preprocess: {e:?}"))?;

    // Fold.
    let mut nova = NovaFc::init(&nova_params, f_circuit.clone(), z0.clone())
        .map_err(|e| anyhow::anyhow!("nova init: {e:?}"))?;
    let mut fold_times_ms = Vec::with_capacity(batches.len());
    for (i, batch) in batches.into_iter().enumerate() {
        let t = Instant::now();
        nova.prove_step(rng, batch, None)
            .map_err(|e| anyhow::anyhow!("prove_step {i}: {e:?}"))?;
        fold_times_ms.push(t.elapsed().as_millis());
    }
    let steps = fold_times_ms.len();
    let zn = nova.z_i.clone();

    // Decider prove.
    let t = Instant::now();
    let proof = DeciderFc::prove(rng, decider_pp, nova.clone())
        .map_err(|e| anyhow::anyhow!("decider prove: {e:?}"))?;
    let decider_prove_ms = t.elapsed().as_millis();

    // Native verify (sanity).
    let verified = DeciderFc::verify(
        decider_vp.clone(),
        nova.i,
        nova.z_0.clone(),
        nova.z_i.clone(),
        &nova.U_i.get_commitments(),
        &nova.u_i.get_commitments(),
        &proof,
    )
    .map_err(|e| anyhow::anyhow!("decider verify: {e:?}"))?;
    anyhow::ensure!(verified, "decider proof did not verify natively");

    // Calldata (Explicit) + Solidity verifier.
    let calldata_explicit = prepare_calldata_for_nova_cyclefold_verifier(
        NovaVerificationMode::Explicit,
        nova.i,
        nova.z_0.clone(),
        nova.z_i.clone(),
        &nova.U_i,
        &nova.u_i,
        &proof,
    )
    .map_err(|e| anyhow::anyhow!("prepare_calldata: {e:?}"))?;

    let vk = NovaCycleFoldVerifierKey::from((decider_vp, f_circuit.state_len()));
    let decider_sol = get_decider_template_for_cyclefold_decider(vk);

    // Optional in-Rust revm cross-check + gas. sonobe's compile_solidity shells out to a
    // system `solc`; if it's absent we skip this (the Foundry suite does the authoritative
    // on-chain verification and gas metering, and manages its own solc).
    let evm_verify_gas: u64 = if solc_available() {
        let bytecode = compile_solidity(&decider_sol, "NovaDecider");
        let mut evm = Evm::default();
        let addr = evm.create(bytecode);
        let (gas, output) = evm.call(addr, calldata_explicit.clone());
        anyhow::ensure!(
            output.last() == Some(&1u8),
            "revm NovaDecider.verifyNovaProof returned false"
        );
        gas
    } else {
        eprintln!("[prover] `solc` not found — skipping in-Rust revm verify; Foundry will verify on-chain.");
        0
    };

    // Formatted words: [i, z0(3), zi(3), proof(25)] -> extract the trailing 25.
    let formatted = get_formatted_calldata(calldata_explicit.clone());
    anyhow::ensure!(formatted.len() == 32, "unexpected calldata word count: {}", formatted.len());
    let proof_words = formatted[7..32].to_vec();

    Ok(EpochArtifacts {
        epoch,
        token_id,
        steps,
        z0: nova.z_0.clone(),
        zn,
        proof_words,
        calldata_bytes: calldata_explicit.len(),
        calldata_explicit,
        nets,
        transfers_root,
        decider_sol,
        fold_times_ms,
        decider_prove_ms,
        evm_verify_gas,
    })
}

/// Chunk a flat op stream into exactly-`B` batches, padding the last with inactive ops.
pub fn chunk_into_batches(
    ops: Vec<OpWitness<Fr, DEPTH>>,
) -> Vec<EpochStepInput<Fr, BATCH, DEPTH>> {
    let mut batches = Vec::new();
    let mut it = ops.into_iter().peekable();
    while it.peek().is_some() {
        let mut arr: Vec<OpWitness<Fr, DEPTH>> = Vec::with_capacity(BATCH);
        for _ in 0..BATCH {
            arr.push(it.next().unwrap_or_else(OpWitness::padding));
        }
        batches.push(EpochStepInput { ops: arr.try_into().unwrap() });
    }
    batches
}
