//! Nova/Decider parameter management.
//!
//! Directly reuses zERC20's params.rs pattern:
//!   - NovaParams<C>: prover + verifier params for Nova IVC
//!   - DeciderParams<C>: Groth16 decider for on-chain verification

use std::io::Cursor;

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize as _, Compress, Validate};
use folding_schemes::{
    Decider, FoldingScheme,
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::{
        nova::{IVCProof, Nova, PreprocessorParam, decider_eth::Decider as DeciderEth},
        traits::CommittedInstanceOps as _,
    },
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
};
use rand::rngs::OsRng;
use solidity_verifiers::{
    NovaCycleFoldVerifierKey, get_decider_template_for_cyclefold_decider, utils::eth::ToEth,
};

// ============================================================
// Type aliases (identical to zERC20)
// ============================================================

pub type N<C> = Nova<G1, G2, C, KZG<'static, Bn254>, Pedersen<G2>, false>;
pub type D<C> = DeciderEth<G1, G2, C, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, N<C>>;

pub type FParams<C> = <C as FCircuit<Fr>>::Params;
pub type NovaPP<C> = <N<C> as FoldingScheme<G1, G2, C>>::ProverParam;
pub type NovaVP<C> = <N<C> as FoldingScheme<G1, G2, C>>::VerifierParam;
pub type DeciderPP<C> = <D<C> as Decider<G1, G2, C, N<C>>>::ProverParam;
pub type DeciderVP<C> = <D<C> as Decider<G1, G2, C, N<C>>>::VerifierParam;

// ============================================================
// Error
// ============================================================

#[derive(thiserror::Error, Debug)]
pub enum NovaError {
    #[error("Deserialization Error: {0}")]
    DeserializationError(String),
    #[error("Serialization Error: {0}")]
    SerializationError(String),
    #[error("Initialization Error: {0}")]
    InitializationError(String),
    #[error("Verification Error: {0}")]
    VerificationError(String),
    #[error("Preprocess Error: {0}")]
    PreprocessError(String),
    #[error("Decider Proof Error: {0}")]
    DeciderProofError(String),
}

// ============================================================
// NovaParams (identical to zERC20's NovaParams)
// ============================================================

pub struct NovaParams<C: FCircuit<Fr>>
where
    FParams<C>: Clone,
{
    pub f_params: FParams<C>,
    pub pp: NovaPP<C>,
    pub vp: NovaVP<C>,
}

impl<C: FCircuit<Fr>> NovaParams<C>
where
    FParams<C>: Clone,
{
    /// Generate random Nova parameters (trusted setup).
    pub fn rand<R: rand::RngCore>(f_params: FParams<C>, rng: &mut R) -> Result<Self, NovaError> {
        let circuit = C::new(f_params.clone()).map_err(|e| {
            NovaError::InitializationError(format!("FCircuit Initialization: {}", e))
        })?;
        let poseidon_config = poseidon_canonical_config::<Fr>();
        let preprocess_params =
            PreprocessorParam::<G1, G2, C, KZG<'static, Bn254>, Pedersen<G2>, false>::new(
                poseidon_config,
                circuit.clone(),
            );
        let nova_params = N::preprocess(rng, &preprocess_params)
            .map_err(|e| NovaError::PreprocessError(format!("Nova Preprocess: {}", e)))?;
        Ok(Self {
            f_params,
            pp: nova_params.0,
            vp: nova_params.1,
        })
    }

    /// Deserialize from bytes.
    pub fn from_bytes(
        f_params: FParams<C>,
        pp_bytes: Vec<u8>,
        vp_bytes: Vec<u8>,
    ) -> Result<Self, NovaError> {
        let pp = {
            let mut cur = Cursor::new(&pp_bytes);
            N::<C>::pp_deserialize_with_mode(
                &mut cur,
                Compress::No,
                Validate::Yes,
                f_params.clone(),
            )
            .map_err(|e| NovaError::DeserializationError(format!("Nova PP: {}", e)))?
        };
        let vp = {
            let mut cur = Cursor::new(&vp_bytes);
            N::<C>::vp_deserialize_with_mode(&mut cur, Compress::No, Validate::Yes, f_params.clone())
                .map_err(|e| NovaError::DeserializationError(format!("Nova VP: {}", e)))?
        };
        Ok(Self { f_params, pp, vp })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<(Vec<u8>, Vec<u8>), NovaError> {
        let mut pp_bytes = Vec::new();
        self.pp
            .serialize_with_mode(&mut pp_bytes, Compress::No)
            .map_err(|e| NovaError::SerializationError(format!("PP: {}", e)))?;
        let mut vp_bytes = Vec::new();
        self.vp
            .serialize_with_mode(&mut vp_bytes, Compress::No)
            .map_err(|e| NovaError::SerializationError(format!("VP: {}", e)))?;
        Ok((pp_bytes, vp_bytes))
    }

    /// Initialize a Nova IVC instance with initial state z_0.
    pub fn initial_nova(&self, z0: Vec<Fr>) -> Result<N<C>, NovaError> {
        N::<C>::init(
            &(self.pp.clone(), self.vp.clone()),
            C::new(self.f_params.clone()).map_err(|e| {
                NovaError::InitializationError(format!("FCircuit: {}", e))
            })?,
            z0,
        )
        .map_err(|e| NovaError::InitializationError(format!("Nova init: {}", e)))
    }

    /// Verify an IVC proof.
    pub fn verify(&self, ivc_proof: IVCProof<G1, G2>) -> Result<(), NovaError> {
        N::<C>::verify(self.vp.clone(), ivc_proof)
            .map_err(|e| NovaError::VerificationError(format!("Nova verify: {}", e)))?;
        Ok(())
    }

    pub fn state_len(&self) -> Result<usize, NovaError> {
        let circuit = C::new(self.f_params.clone()).map_err(|e| {
            NovaError::InitializationError(format!("FCircuit: {}", e))
        })?;
        Ok(circuit.state_len())
    }
}

// ============================================================
// DeciderParams (Groth16 finalization for on-chain verification)
// ============================================================

pub struct DeciderParams<C: FCircuit<Fr>>
where
    FParams<C>: Clone,
{
    pub pp: DeciderPP<C>,
    pub vp: DeciderVP<C>,
}

impl<C: FCircuit<Fr>> DeciderParams<C>
where
    FParams<C>: Clone,
{
    pub fn rand<R: rand::RngCore + rand::CryptoRng>(
        rng: &mut R,
        nova_params: &NovaParams<C>,
    ) -> Result<Self, NovaError> {
        let decider_params = D::<C>::preprocess(
            rng,
            (
                (nova_params.pp.clone(), nova_params.vp.clone()),
                nova_params.state_len()?,
            ),
        )
        .map_err(|e| NovaError::PreprocessError(format!("Decider: {}", e)))?;
        Ok(Self {
            pp: decider_params.0,
            vp: decider_params.1,
        })
    }

    /// Generate Solidity verifier source code.
    pub fn verifier_solidity_code(&self, state_len: usize) -> String {
        let nova_cyclefold_vk = NovaCycleFoldVerifierKey::from((self.vp.clone(), state_len));
        get_decider_template_for_cyclefold_decider(nova_cyclefold_vk)
    }

    /// Generate on-chain decider proof.
    pub fn generate_decider_proof(&self, nova: N<C>) -> Result<Vec<u8>, NovaError> {
        let mut rng = OsRng;
        let proof = D::<C>::prove(&mut rng, self.pp.clone(), nova.clone()).map_err(|e| {
            NovaError::DeciderProofError(format!("Decider prove: {}", e))
        })?;

        let verified = D::<C>::verify(
            self.vp.clone(),
            nova.i,
            nova.z_0.clone(),
            nova.z_i.clone(),
            &nova.U_i.get_commitments(),
            &nova.u_i.get_commitments(),
            &proof,
        )
        .map_err(|e| NovaError::DeciderProofError(format!("Decider verify: {}", e)))?;
        if !verified {
            return Err(NovaError::DeciderProofError(
                "Decider verification failed".to_string(),
            ));
        }

        let calldata = [
            nova.i.to_eth(),
            nova.z_0.to_eth(),
            nova.z_i.to_eth(),
            nova.U_i.cmW.to_eth(),
            nova.U_i.cmE.to_eth(),
            nova.u_i.cmW.to_eth(),
            proof.cmT().to_eth(),
            proof.r().to_eth(),
            proof.snark_proof().to_eth(),
            proof.kzg_challenges().to_eth(),
            proof.kzg_proofs()[0].eval.to_eth(),
            proof.kzg_proofs()[1].eval.to_eth(),
            proof.kzg_proofs()[0].proof.to_eth(),
            proof.kzg_proofs()[1].proof.to_eth(),
        ]
        .concat();

        Ok(calldata)
    }
}
