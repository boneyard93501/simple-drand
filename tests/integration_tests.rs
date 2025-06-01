use drand_client::*;

#[tokio::test]
async fn test_get_latest_quicknet() {
    let client = DrandClient::new_quicknet().unwrap();
    let beacon = client.get_latest().await.unwrap();
    
    println!("Latest quicknet beacon: round={}, randomness={}", 
             beacon.round, beacon.randomness);
    
    assert!(!beacon.randomness.is_empty());
    assert!(beacon.round > 0);
    assert_eq!(beacon.randomness.len(), 64);
    assert!(!beacon.signature.is_empty());
}

#[tokio::test]
async fn test_get_latest_mainnet() {
    let client = DrandClient::new_mainnet().unwrap();
    let beacon = client.get_latest().await.unwrap();
    
    println!("Latest mainnet beacon: round={}, randomness={}", 
             beacon.round, beacon.randomness);
    
    assert!(!beacon.randomness.is_empty());
    assert!(beacon.round > 0);
    assert_eq!(beacon.randomness.len(), 64);
    assert!(!beacon.signature.is_empty());
}

#[tokio::test]
async fn test_get_specific_round() {
    let client = DrandClient::new_quicknet().unwrap();
    let latest = client.get_latest().await.unwrap();
    
    if latest.round > 100 {
        let target_round = latest.round - 50;
        let beacon = client.get_round(target_round).await.unwrap();
        
        assert_eq!(beacon.round, target_round);
        assert!(!beacon.randomness.is_empty());
        assert!(!beacon.signature.is_empty());
        assert_eq!(beacon.randomness.len(), 64);
        
        println!("Retrieved round {}: randomness={}", 
                beacon.round, beacon.randomness);
    }
}

#[tokio::test]
async fn test_beacon_verification() {
    let client = DrandClient::new_quicknet().unwrap();
    let beacon = client.get_latest().await.unwrap();
    
    let result = client.verify_beacon(&beacon);
    assert!(result.is_ok(), "Beacon verification should succeed");
}

#[tokio::test]
async fn test_mainnet_vs_quicknet_differences() {
    let quicknet = DrandClient::new_quicknet().unwrap();
    let mainnet = DrandClient::new_mainnet().unwrap();
    
    let quicknet_beacon = quicknet.get_latest().await.unwrap();
    let mainnet_beacon = mainnet.get_latest().await.unwrap();
    
    // Quicknet should have higher round numbers due to 3s vs 30s frequency
    assert!(quicknet_beacon.round > mainnet_beacon.round);
    
    // Different signature lengths: quicknet (G1) = 48 bytes = 96 hex chars, mainnet (G2) = 96 bytes = 192 hex chars
    assert_eq!(quicknet_beacon.signature.len(), 96); // G1 signature (48 bytes)
    assert_eq!(mainnet_beacon.signature.len(), 192); // G2 signature (96 bytes)
    
    // Quicknet should not have previous_signature (unchained)
    assert!(quicknet_beacon.previous_signature.is_none() || 
            quicknet_beacon.previous_signature.as_ref().map(|s| s.is_empty()).unwrap_or(true));
    
    // Mainnet should have previous_signature (chained)
    assert!(mainnet_beacon.previous_signature.is_some() && 
            !mainnet_beacon.previous_signature.as_ref().unwrap().is_empty());
    
    println!("Quicknet round: {}, signature len: {} chars", 
             quicknet_beacon.round, quicknet_beacon.signature.len());
    println!("Mainnet round: {}, signature len: {} chars", 
             mainnet_beacon.round, mainnet_beacon.signature.len());
}