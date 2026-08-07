//! Generates a REAL KZG proof for `ChannelStateCircuit` (not just a
//! MockProver constraint check) using a small, LOCALLY-generated SRS —
//! `ParamsKZG::setup` with a throwaway random `s`, printed to stderr as a
//! reminder this is NOT a real ceremony. See circuits-halo2/README.md:
//! production use would need a real KZG-compatible ceremony (the same
//! Powers-of-Tau ceremony this repo already uses for Groth16 — see
//! circuits/README.md — is directly reusable for KZG, since both need the
//! same "powers of tau in G1/G2" structure, just needs format conversion).

use channel_state_halo2::circuit::{ChannelStateCircuit, SignatureWitness};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2curves::ff::PrimeField;
use rand_core::OsRng;
use std::time::Instant;

fn fr(s: &str) -> Fr {
    Fr::from_str_vartime(s).expect("valid decimal Fr")
}

fn main() {
    let circuit = ChannelStateCircuit {
        contract_address: fr("97433442488726861213578988847752201310395502865"),
        chain_id: Fr::from(31337u64),
        channel_id: Fr::from(1u64),
        nonce: Fr::from(1u64),
        balance_a: Fr::from(400000u64),
        balance_b: Fr::from(600000u64),
        total_deposit: Fr::from(1000000u64),
        pub_key_ax: fr("6258698228857579243937097735069405513777546488206385948349971781708128047847"),
        pub_key_ay: fr("2216124967747932654884761600749314631961003421499958761754620989171020525870"),
        pub_key_bx: fr("21036738825193802266623779881692904721121294284483365787352024792419651640674"),
        pub_key_by: fr("17088268747125489648041885901336523179405935374090472533134592214513880559267"),
        sig_a: SignatureWitness {
            r8x: fr("4917344699118670943373348864095189513110544881241303759698448356854879866857"),
            r8y: fr("5468544676196101173266500702471328966306068888220567829875945479129822096316"),
            s: fr("2332341740213430710895160059533639433920566388022543560963322443715774995966"),
        },
        sig_b: SignatureWitness {
            r8x: fr("8425486573857761199328174831877931532857805810054432862926891341132244559543"),
            r8y: fr("14076165714719029565373764552193210300296476170884431308989492567248263735781"),
            s: fr("1013225836428401173556310194350073290416509558752576451792834375459276379446"),
        },
    };
    let public_inputs = circuit.public_inputs();

    let k = 17;
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
