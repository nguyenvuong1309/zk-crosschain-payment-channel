//! Generates a REAL KZG proof for `ChannelStateCircuit` (not just a
//! MockProver constraint check) using a small, LOCALLY-generated SRS —
//! `ParamsKZG::setup` with a throwaway random `s`, printed to stderr as a
//! reminder this is NOT a real ceremony. See circuits-halo2/README.md:
//! production use would need a real KZG-compatible ceremony (the same
//! Powers-of-Tau ceremony this repo already uses for Groth16 — see
//! circuits/README.md — is directly reusable for KZG, since both need the
//! same "powers of tau in G1/G2" structure, just needs format conversion).

use channel_state_halo2::circuit::demo_witness;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use halo2curves::bn256::{Bn256, G1Affine};
use rand_core::OsRng;
use std::time::Instant;

fn main() {
    let circuit = demo_witness();
    let public_inputs = circuit.public_inputs();

    let k = 19;
    eprintln!("[!] Using a LOCAL, INSECURE, dev-only KZG setup (ParamsKZG::setup with OsRng) — see this file's doc comment. NOT for real value.");
    let t0 = Instant::now();
    let params: ParamsKZG<Bn256> = ParamsKZG::setup(k, OsRng);
    eprintln!("SRS setup: {:?}", t0.elapsed());

    let t0 = Instant::now();
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("keygen_pk");
    eprintln!("keygen: {:?}", t0.elapsed());

    let t0 = Instant::now();
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&public_inputs]],
        OsRng,
        &mut transcript,
    )
    .expect("create_proof");
    let proof = transcript.finalize();
    eprintln!("proof generation: {:?}, proof size: {} bytes", t0.elapsed(), proof.len());

    let t0 = Instant::now();
    let strategy = SingleStrategy::new(&params);
    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        &[&[&public_inputs]],
        &mut verifier_transcript,
    )
    .expect("verify_proof — a genuine KZG proof must verify");
    eprintln!("verification: {:?}", t0.elapsed());

    println!("OK: real KZG proof generated and verified ({} bytes)", proof.len());
}
