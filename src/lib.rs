// prover/src/lib.rs
// BLS ZK Prover Implementation using arkworks

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    Proof, ProvingKey, VerifyingKey,
};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLSPublicInputs {
    pub message_hash: String,
    pub public_key_x: String,
    pub public_key_y: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLSPrivateInputs {
    pub signature_x: String,
    pub signature_y: String,
}

#[derive(Debug, Clone)]
pub struct BLSProofInputs {
    pub public_inputs: BLSPublicInputs,
    pub private_inputs: BLSPrivateInputs,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofResult {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofStats {
    pub proving_time_ms: u128,
    pub verification_time_ms: u128,
    pub proof_size_bytes: usize,
    pub num_constraints: usize,
}

pub struct BLSProver {
    circuit_path: String,
    proving_key: Option<ProvingKey<Bn254>>,
    verifying_key: Option<VerifyingKey<Bn254>>,
    num_constraints: usize,
}

impl BLSProver {
    pub fn new(circuit_path: &str) -> Self {
        BLSProver {
            circuit_path: circuit_path.to_string(),
            proving_key: None,
            verifying_key: None,
            num_constraints: 0,
        }
    }

    pub fn setup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("[SETUP] Caricamento circuito da: {}", self.circuit_path);

        let cfg = CircomConfig::<Bn254>::new(
            &format!("{}/bls_verify_js/bls_verify.wasm", self.circuit_path),
            &format!("{}/bls_verify.r1cs", self.circuit_path),
        )?;

        let builder = CircomBuilder::new(cfg);
        let circom = builder.build()?;

        self.num_constraints = circom.get_num_constraints();

        println!("[SETUP] Constraints: {}", self.num_constraints);
        println!("[SETUP] Variables: {}", circom.get_num_variables());
        println!("[SETUP] Generazione trusted setup...");

        let mut rng = thread_rng();
        let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng)?;

        self.proving_key = Some(params.clone());
        self.verifying_key = Some(params.vk.clone());

        println!("[SETUP] Completato");
        Ok(())
    }

    pub fn generate_proof(
        &self,
        inputs: BLSProofInputs,
    ) -> Result<(ProofResult, ProofStats), Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();

        println!("[PROVE] Inizio generazione prova");

        let proving_key = self.proving_key.as_ref().ok_or("Setup non eseguito")?;

        let cfg = CircomConfig::<Bn254>::new(
            &format!("{}/bls_verify_js/bls_verify.wasm", self.circuit_path),
            &format!("{}/bls_verify.r1cs", self.circuit_path),
        )?;

        let mut builder = CircomBuilder::new(cfg);

        builder.push_input(
            "messageHash",
            BigInt::parse_bytes(inputs.public_inputs.message_hash.as_bytes(), 10)
                .ok_or("Invalid messageHash")?,
        );
        builder.push_input(
            "publicKeyX",
            BigInt::parse_bytes(inputs.public_inputs.public_key_x.as_bytes(), 10)
                .ok_or("Invalid publicKeyX")?,
        );
        builder.push_input(
            "publicKeyY",
            BigInt::parse_bytes(inputs.public_inputs.public_key_y.as_bytes(), 10)
                .ok_or("Invalid publicKeyY")?,
        );
        builder.push_input(
            "signatureX",
            BigInt::parse_bytes(inputs.private_inputs.signature_x.as_bytes(), 10)
                .ok_or("Invalid signatureX")?,
        );
        builder.push_input(
            "signatureY",
            BigInt::parse_bytes(inputs.private_inputs.signature_y.as_bytes(), 10)
                .ok_or("Invalid signatureY")?,
        );

        let circom = builder.build()?;

        println!("[PROVE] Generazione Groth16...");
        let mut rng = thread_rng();
        let proof = create_random_proof(circom, proving_key, &mut rng)?;

        let proving_time = start.elapsed();
        println!("[PROVE] Generato in {:?}", proving_time);

        let proof_bytes = serialize_proof(&proof)?;

        let public_inputs = vec![
            inputs.public_inputs.message_hash,
            inputs.public_inputs.public_key_x,
            inputs.public_inputs.public_key_y,
        ];

        let verify_start = std::time::Instant::now();
        let is_valid = self.verify_proof(&proof_bytes, &public_inputs)?;
        let verification_time = verify_start.elapsed();

        if !is_valid {
            return Err("Prova non valida".into());
        }

        println!("[PROVE] Verificato in {:?}", verification_time);

        let stats = ProofStats {
            proving_time_ms: proving_time.as_millis(),
            verification_time_ms: verification_time.as_millis(),
            proof_size_bytes: proof_bytes.len(),
            num_constraints: self.num_constraints,
        };

        Ok((ProofResult { proof: proof_bytes, public_inputs }, stats))
    }

    pub fn verify_proof(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[String],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let verifying_key = self.verifying_key.as_ref().ok_or("Setup non eseguito")?;
        let proof = deserialize_proof(proof_bytes)?;

        let public_inputs_fr: Vec<Fr> = public_inputs
            .iter()
            .map(|s| string_to_fr(s))
            .collect();

        let pvk = prepare_verifying_key(verifying_key);
        let is_valid = verify_proof(&pvk, &proof, &public_inputs_fr)?;

        Ok(is_valid)
    }

    pub fn export_verifying_key(&self) -> Result<String, Box<dyn std::error::Error>> {
        let vk = self.verifying_key.as_ref().ok_or("Setup non eseguito")?;
        let vk_json = serde_json::to_string_pretty(vk)?;
        Ok(vk_json)
    }
}

fn serialize_proof(proof: &Proof<Bn254>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

fn deserialize_proof(bytes: &[u8]) -> Result<Proof<Bn254>, Box<dyn std::error::Error>> {
    let proof = Proof::<Bn254>::deserialize_compressed(bytes)?;
    Ok(proof)
}

fn string_to_fr(s: &str) -> Fr {
    use ark_ff::PrimeField;
    let big_int = BigInt::parse_bytes(s.as_bytes(), 10).unwrap();
    Fr::from_be_bytes_mod_order(&big_int.to_bytes_be().1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prover_setup() {
        let mut prover = BLSProver::new("../circuits");
        let result = prover.setup();
        assert!(result.is_ok());
    }
}