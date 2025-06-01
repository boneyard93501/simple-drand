mod config;

pub use config::{Settings, DrandConfig, ChainConfig};

use anyhow::{anyhow, Result};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
use group::{Curve, Group};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrandBeacon {
    pub round: u64,
    pub randomness: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub public_key: String,
    pub period: u64,
    pub genesis_time: u64,
    pub hash: String,
    #[serde(rename = "groupHash")]
    pub group_hash: String,
    pub scheme_id: String,
    pub metadata: ChainMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    #[serde(rename = "beaconID")]
    pub beacon_id: String,
}

pub struct DrandClient {
    chain_config: config::ChainConfig,
    g1_public_key: Option<G1Affine>,
    g2_public_key: Option<G2Affine>,
    use_quicknet: bool,
    base_url: String,
    timeout_seconds: u64,
    quicknet_dst: String,
    mainnet_dst: String,
}

impl DrandClient {
    /// Create a new client with explicit configuration
    pub fn new(
        chain_config: ChainConfig, 
        base_url: String, 
        timeout_seconds: u64, 
        use_quicknet: bool,
        quicknet_dst: String,
        mainnet_dst: String,
    ) -> Result<Self> {
        let pk_bytes = hex::decode(&chain_config.public_key)?;
        
        let (g1_public_key, g2_public_key) = if use_quicknet {
            // Quicknet uses min_sig scheme: G1 signatures, G2 public keys
            let pk = G2Affine::from_compressed(&pk_bytes.try_into().map_err(|_| anyhow!("Invalid G2 public key length"))?)
                .into_option()
                .ok_or_else(|| anyhow!("Invalid G2 public key for quicknet"))?;
            (None, Some(pk))
        } else {
            // Mainnet uses min_pk scheme: G2 signatures, G1 public keys
            let pk = G1Affine::from_compressed(&pk_bytes.try_into().map_err(|_| anyhow!("Invalid G1 public key length"))?)
                .into_option()
                .ok_or_else(|| anyhow!("Invalid G1 public key for mainnet"))?;
            (Some(pk), None)
        };

        Ok(Self {
            chain_config,
            g1_public_key,
            g2_public_key,
            use_quicknet,
            base_url,
            timeout_seconds,
            quicknet_dst,
            mainnet_dst,
        })
    }
    
    /// Create a new client for quicknet (3s randomness) from config.toml
    pub fn new_quicknet() -> Result<Self> {
        let settings = Settings::new()?;
        let chain_config = settings.drand.quicknet.clone();
        
        Self::new(
            chain_config,
            settings.drand.base_url,
            settings.http.timeout_seconds,
            true,
            settings.crypto.quicknet_dst,
            settings.crypto.mainnet_dst,
        )
    }
    
    /// Create a new client for mainnet (30s randomness) from config.toml
    pub fn new_mainnet() -> Result<Self> {
        let settings = Settings::new()?;
        let chain_config = settings.drand.mainnet.clone();
        
        Self::new(
            chain_config,
            settings.drand.base_url,
            settings.http.timeout_seconds,
            false,
            settings.crypto.quicknet_dst,
            settings.crypto.mainnet_dst,
        )
    }

    /// Get the base URL
    fn get_base_url(&self) -> &str {
        &self.base_url
    }

    /// Fetch the latest beacon
    pub async fn get_latest(&self) -> Result<DrandBeacon> {
        let url = format!("{}/{}/public/latest", 
                         self.get_base_url(), 
                         self.chain_config.chain_hash);
        
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_seconds))
            .build()?;
            
        let beacon = client.get(&url)
            .send()
            .await?
            .json::<DrandBeacon>()
            .await?;
        
        self.verify_beacon(&beacon)?;
        Ok(beacon)
    }

    /// Fetch a specific round
    pub async fn get_round(&self, round: u64) -> Result<DrandBeacon> {
        let url = format!("{}/{}/public/{}", 
                         self.get_base_url(),
                         self.chain_config.chain_hash,
                         round);
        
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_seconds))
            .build()?;
            
        let beacon = client.get(&url)
            .send()
            .await?
            .json::<DrandBeacon>()
            .await?;
        
        self.verify_beacon(&beacon)?;
        Ok(beacon)
    }

    /// Get the round number for a given timestamp
    pub fn round_at_timestamp(&self, timestamp: u64) -> u64 {
        if timestamp <= self.chain_config.genesis_time {
            return 1;
        }
        ((timestamp - self.chain_config.genesis_time) / self.chain_config.period) + 1
    }

    /// Get the next round after a given timestamp
    pub fn next_round_after(&self, timestamp: u64) -> u64 {
        self.round_at_timestamp(timestamp) + 1
    }

    /// Verify a beacon's signature using BLS12-381
    pub fn verify_beacon(&self, beacon: &DrandBeacon) -> Result<()> {
        // Decode signature
        let sig_bytes = hex::decode(&beacon.signature)?;
        
        // Create the message that was signed based on drand scheme
        let mut hasher = Sha256::new();
        
        // Determine if we should include previous signature based on network type
        let include_prev_sig = match self.chain_config.scheme_id.as_str() {
            "pedersen-bls-chained" => true,
            "bls-unchained-g1-rfc9380" => false,
            "pedersen-bls-unchained" => false,
            "bls-unchained-on-g1" => false,
            _ => {
                beacon.previous_signature.as_ref()
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
            }
        };
        
        if include_prev_sig {
            if let Some(prev_sig) = &beacon.previous_signature {
                if !prev_sig.is_empty() {
                    let prev_bytes = hex::decode(prev_sig)?;
                    hasher.update(&prev_bytes);
                }
            }
        }
        
        // Add round number as big-endian bytes (8 bytes uint64)
        hasher.update(beacon.round.to_be_bytes());
        let message = hasher.finalize();

        // Get DST based on which network we're using
        let dst = if self.use_quicknet {
            self.quicknet_dst.as_bytes()
        } else {
            self.mainnet_dst.as_bytes()
        };

        // Hash message to curve point using the appropriate DST
        // Verify BLS signature based on curve
        if self.use_quicknet {
            // Quicknet: min_sig scheme (G1 signatures, G2 public keys)
            println!("DEBUG: Quicknet verification");
            
            let signature = G1Affine::from_compressed(&sig_bytes.clone().try_into().map_err(|_| anyhow!("Invalid G1 signature length"))?)
                .into_option()
                .ok_or_else(|| anyhow!("Invalid G1 signature for quicknet"))?;
            
            let public_key = self.g2_public_key
                .ok_or_else(|| anyhow!("Missing G2 public key for quicknet"))?;
            
            // Hash message to G1 for quicknet
            let hashed_message = hash_to_g1(&message, dst)?;
            
            // Verify: e(signature, g2) == e(hashed_message, public_key)
            let lhs = bls12_381::pairing(&signature, &G2Affine::generator());
            let rhs = bls12_381::pairing(&hashed_message, &public_key);
            
            println!("  Quicknet pairing verification");
            
            if lhs != rhs {
                println!("  Quicknet pairing verification FAILED");
                return Err(anyhow!("Quicknet signature verification failed"));
            }
            
            println!("  Quicknet pairing verification PASSED");
        } else {
            // Mainnet: min_pk scheme (G2 signatures, G1 public keys)
            println!("DEBUG: Mainnet verification");
            println!("  Signature bytes len: {}", sig_bytes.len());
            println!("  Message: {}", hex::encode(&message));
            println!("  DST: {}", String::from_utf8_lossy(dst));
            
            let signature = G2Affine::from_compressed(&sig_bytes.clone().try_into().map_err(|_| anyhow!("Invalid G2 signature length"))?)
                .into_option()
                .ok_or_else(|| anyhow!("Invalid G2 signature for mainnet"))?;
            
            let public_key = self.g1_public_key
                .ok_or_else(|| anyhow!("Missing G1 public key for mainnet"))?;
            
            // Hash message to G2 for mainnet (correct according to working implementation)
            let hashed_message = hash_to_g2(&message, dst)?;
            
            println!("  Parsed signature and public key successfully");
            println!("  Hashed message to G2 successfully");
            
            // Verify using fast pairing equality: e(g1, signature) == e(public_key, hashed_message)
            let verified = fast_pairing_equality(&G1Affine::generator(), &signature, &public_key, &hashed_message);
            
            println!("  LHS pairing: computed");
            println!("  RHS pairing: computed");
            
            if !verified {
                println!("  Fast pairing verification FAILED");
                return Err(anyhow!("Mainnet signature verification failed"));
            }
            
            println!("  Fast pairing verification PASSED");
        }

        // Verify randomness matches (randomness = H(signature))
        let mut hasher = Sha256::new();
        hasher.update(&sig_bytes);
        let expected_randomness = hex::encode(hasher.finalize());
        
        if expected_randomness != beacon.randomness {
            return Err(anyhow!("Randomness doesn't match signature hash"));
        }

        Ok(())
    }
}

// Helper function to hash message to G1 (for quicknet)
fn hash_to_g1(message: &[u8], dst: &[u8]) -> Result<G1Affine> {
    use bls12_381::hash_to_curve::{HashToCurve, ExpandMsgXmd};
    
    let point = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, dst);
    Ok(point.to_affine())
}

// Helper function to hash message to G2 (for mainnet)
fn hash_to_g2(message: &[u8], dst: &[u8]) -> Result<G2Affine> {
    use bls12_381::hash_to_curve::{HashToCurve, ExpandMsgXmd};
    
    let point = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, dst);
    Ok(point.to_affine())
}

/// Checks if e(p, q) == e(r, s)
/// Optimized pairing equality check from the working drand-verify implementation
fn fast_pairing_equality(p: &G1Affine, q: &G2Affine, r: &G1Affine, s: &G2Affine) -> bool {
    use bls12_381::{Bls12, G2Prepared};
    use pairing::MultiMillerLoop;
    
    let minus_p = -p;
    // "some number of (G1, G2) pairs" are the inputs of the miller loop
    let pair1 = (&minus_p, &G2Prepared::from(*q));
    let pair2 = (r, &G2Prepared::from(*s));
    let looped = Bls12::multi_miller_loop(&[pair1, pair2]);
    let value = looped.final_exponentiation();
    value.is_identity().into()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_config_loading() {
        let settings = super::Settings::new().unwrap();
        assert_eq!(settings.drand.quicknet.period, 3);
        assert_eq!(settings.drand.mainnet.period, 30);
        assert_eq!(settings.http.timeout_seconds, 30);
        assert!(!settings.drand.base_url.is_empty());
    }

    #[test]
    fn test_client_creation_quicknet() {
        let client = super::DrandClient::new_quicknet().unwrap();
        let settings = super::Settings::new().unwrap();
        let genesis = settings.drand.quicknet.genesis_time;
        let round = client.round_at_timestamp(genesis + 100);
        assert!(round > 1);
    }

    #[test]
    fn test_client_creation_mainnet() {
        let client = super::DrandClient::new_mainnet().unwrap();
        let settings = super::Settings::new().unwrap();
        let genesis = settings.drand.mainnet.genesis_time;
        let round = client.round_at_timestamp(genesis + 1000);
        assert!(round > 1);
    }

    #[test]
    fn test_round_calculation_quicknet() {
        let client = super::DrandClient::new_quicknet().unwrap();
        let settings = super::Settings::new().unwrap();
        let genesis = settings.drand.quicknet.genesis_time;
        
        assert_eq!(client.round_at_timestamp(genesis), 1);
        assert_eq!(client.round_at_timestamp(genesis - 100), 1);
        assert_eq!(client.round_at_timestamp(genesis + 3), 2);
        assert_eq!(client.round_at_timestamp(genesis + 6), 3);
        assert_eq!(client.round_at_timestamp(genesis + 300), 101);
    }

    #[test]
    fn test_round_calculation_mainnet() {
        let client = super::DrandClient::new_mainnet().unwrap();
        let settings = super::Settings::new().unwrap();
        let genesis = settings.drand.mainnet.genesis_time;
        
        assert_eq!(client.round_at_timestamp(genesis), 1);
        assert_eq!(client.round_at_timestamp(genesis - 100), 1);
        assert_eq!(client.round_at_timestamp(genesis + 30), 2);
        assert_eq!(client.round_at_timestamp(genesis + 60), 3);
        assert_eq!(client.round_at_timestamp(genesis + 3000), 101);
    }

    #[test]
    fn test_next_round_after() {
        let client = super::DrandClient::new_quicknet().unwrap();
        let settings = super::Settings::new().unwrap();
        let genesis = settings.drand.quicknet.genesis_time;
        
        assert_eq!(client.next_round_after(genesis), 2);
        assert_eq!(client.next_round_after(genesis - 100), 2);
        assert_eq!(client.next_round_after(genesis + 3), 3);
        assert_eq!(client.next_round_after(genesis + 300), 102);
    }
}