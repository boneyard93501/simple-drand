# drand-client

A Rust client library for interacting with the [drand](https://drand.love/) distributed randomness beacon network. Supports both mainnet (30s) and quicknet (3s) networks with full BLS signature verification.

## Features

- **Dual Network Support**: Mainnet (30s) and Quicknet (3s) randomness beacons
- **BLS Signature Verification**: Full cryptographic verification using BLS12-381
- **Configurable**: TOML-based configuration system
- **Round Calculation**: Timestamp-to-round conversion utilities

## Quick Start

Clone the repository:
```bash
git clone <repository-url>
cd drand-client
```

Or add to your `Cargo.toml`:
```toml
[dependencies]
drand-client = { git = "https://github.com/your-username/drand-client" }
```

### Basic Usage

```rust
use drand_client::DrandClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get latest quicknet randomness (3s frequency)
    let client = DrandClient::new_quicknet()?;
    let beacon = client.get_latest().await?;
    
    println!("Round: {}", beacon.round);
    println!("Randomness: {}", beacon.randomness);
    
    // Get latest mainnet randomness (30s frequency)  
    let mainnet_client = DrandClient::new_mainnet()?;
    let mainnet_beacon = mainnet_client.get_latest().await?;
    
    println!("Mainnet Round: {}", mainnet_beacon.round);
    println!("Mainnet Randomness: {}", mainnet_beacon.randomness);
    
    Ok(())
}
```

### Round-based Access

```rust
// Get specific round
let round_1000 = client.get_round(1000).await?;

// Calculate round from timestamp
let timestamp = 1692803367 + 300; // Genesis + 300s
let round = client.round_at_timestamp(timestamp);
println!("Round at timestamp: {}", round);
```

## Configuration

Configuration is loaded from `config.toml`:

```toml
[drand]
base_url = "https://api.drand.sh"
fallback_urls = ["https://drand.cloudflare.com"]

[drand.quicknet]
chain_hash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
period = 3

[drand.mainnet] 
chain_hash = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"
period = 30
```

## Testing

The test suite includes both unit and integration tests to ensure reliability. **Unit tests** verify core functionality like configuration loading, client creation, and round calculation algorithms without requiring network access. **Integration tests** make live requests to drand networks to validate end-to-end functionality including beacon retrieval, signature verification, and network-specific behavior differences between mainnet and quicknet. Integration tests require internet connectivity and may occasionally fail due to network conditions.

```bash
# Run unit tests
cargo test

# Run integration tests (requires network access)
cargo test --test integration_tests
```

## Networks

- **Mainnet**: 30-second intervals, chained signatures (G2), established network
- **Quicknet**: 3-second intervals, unchained signatures (G1), high-frequency randomness

## Attribution

This implementation benefitted greatly from:
- [thibmeu/drand-rs](https://github.com/thibmeu/drand-rs) (MIT License)
- [noislabs/drand-verify](https://github.com/noislabs/drand-verify)

## References

- [drand.love](https://drand.love/) - Official drand website
- [drand API specification](https://drand.love/docs/specification/)
- [League of Entropy](https://www.cloudflare.com/leagueofentropy/)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.