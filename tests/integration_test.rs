use bg12rust::{
    AggregatePublicKey, AggregateRevealToken, MaskedCard, PublicKey, RevealToken, RevealTokenProof,
    SecretKey, Shuffle, ShuffleError, Verified,
};

type TestDeck = Shuffle<52>;

const POKER_CTX: &[u8] = b"poker_integration_test";

#[test]
fn test_full_poker_workflow() {
    let mut rng = rand::thread_rng();
    let shuffle = TestDeck::default();

    let (sk1, pk1, proof1) = shuffle.keygen(&mut rng, POKER_CTX);
    let vpk1 = proof1.verify(pk1, POKER_CTX).expect("player 1 proof valid");

    let (sk2, pk2, proof2) = shuffle.keygen(&mut rng, POKER_CTX);
    let vpk2 = proof2.verify(pk2, POKER_CTX).expect("player 2 proof valid");

    let apk = AggregatePublicKey::new(&[vpk1, vpk2]);

    let encrypted = shuffle.encrypt_initial_deck(apk, POKER_CTX);
    let encryption_valid = shuffle.verify_initial_encryption(apk, &encrypted, POKER_CTX);
    assert!(encryption_valid, "initial encryption should be valid");

    let (alice_deck, alice_proof) =
        shuffle.shuffle_encrypted_deck(&mut rng, apk, &encrypted, POKER_CTX);
    let alice_vdeck = shuffle
        .verify_shuffle(
            apk,
            &Verified::new(encrypted),
            &alice_deck,
            alice_proof,
            POKER_CTX,
        )
        .expect("Alice's shuffle should be valid");

    let (bob_deck, bob_proof) = shuffle.shuffle_deck(&mut rng, apk, &alice_vdeck, POKER_CTX);
    let final_deck = shuffle
        .verify_shuffle(apk, &alice_vdeck, &bob_deck, bob_proof, POKER_CTX)
        .expect("Bob's shuffle should be valid");

    assert!(final_deck.get(51).is_some(), "should access last card");

    let hole_cards: Vec<MaskedCard> = (0..4).map(|i| final_deck.get(i).unwrap()).collect();
    assert_eq!(hole_cards.len(), 4);

    let card_0 = hole_cards[0];

    let (token1, proof1) = card_0.reveal_token(&mut rng, &sk1, pk1, POKER_CTX);
    let verified1: Verified<RevealToken> = proof1.verify(vpk1, token1, card_0, POKER_CTX).unwrap();

    let (token2, proof2) = card_0.reveal_token(&mut rng, &sk2, pk2, POKER_CTX);
    let verified2: Verified<RevealToken> = proof2.verify(vpk2, token2, card_0, POKER_CTX).unwrap();

    let art = AggregateRevealToken::new(&[verified1, verified2]);
    let revealed_idx = shuffle
        .reveal_card(art, card_0)
        .expect("should reveal card");
    assert!(revealed_idx < 52, "revealed index should be valid");
}

#[test]
fn test_three_player_workflow() {
    let mut rng = rand::thread_rng();
    let shuffle = TestDeck::default();

    let players: Vec<(SecretKey, PublicKey, Verified<PublicKey>)> = (0..3)
        .map(|_| {
            let (sk, pk, proof) = shuffle.keygen(&mut rng, POKER_CTX);
            let vpk = proof.verify(pk, POKER_CTX).expect("valid proof");
            (sk, pk, vpk)
        })
        .collect();

    let apk = AggregatePublicKey::new(&players.iter().map(|(_, _, vpk)| *vpk).collect::<Vec<_>>());

    let encrypted = shuffle.encrypt_initial_deck(apk, POKER_CTX);

    let mut current_deck = Verified::new(encrypted);
    for i in 0..3 {
        let (new_deck, proof) = shuffle.shuffle_deck(&mut rng, apk, &current_deck, POKER_CTX);
        current_deck = shuffle
            .verify_shuffle(apk, &current_deck, &new_deck, proof, POKER_CTX)
            .expect(&format!("shuffle {} should verify", i + 1));
    }

    let card = current_deck.get(0).unwrap();
    let tokens_and_proofs: Vec<(RevealToken, RevealTokenProof)> = players
        .iter()
        .map(|(sk, pk, _)| card.reveal_token(&mut rng, sk, *pk, POKER_CTX))
        .collect();

    let verified_tokens: Vec<Verified<RevealToken>> = tokens_and_proofs
        .iter()
        .zip(players.iter())
        .map(|((token, proof), (_, _, vpk))| proof.verify(*vpk, *token, card, POKER_CTX).unwrap())
        .collect();

    let art = AggregateRevealToken::new(&verified_tokens);
    let revealed = shuffle.reveal_card(art, card);
    assert!(revealed.is_some(), "3-player reveal should succeed");
}

#[test]
fn test_shuffle_proof_catches_tampering() {
    let mut rng = rand::thread_rng();
    let shuffle = TestDeck::default();

    let (_, pk1, proof1) = shuffle.keygen(&mut rng, POKER_CTX);
    let vpk1 = proof1.verify(pk1, POKER_CTX).unwrap();

    let (_, pk2, proof2) = shuffle.keygen(&mut rng, POKER_CTX);
    let vpk2 = proof2.verify(pk2, POKER_CTX).unwrap();

    let apk = AggregatePublicKey::new(&[vpk1, vpk2]);

    let encrypted = shuffle.encrypt_initial_deck(apk, POKER_CTX);

    let (tampered_deck, proof) =
        shuffle.shuffle_encrypted_deck(&mut rng, apk, &encrypted, POKER_CTX);

    let result = shuffle.verify_shuffle(
        apk,
        &Verified::new(encrypted),
        &tampered_deck,
        proof,
        POKER_CTX,
    );
    assert!(result.is_some(), "valid shuffle should pass");

    let (_, tampered_proof) = shuffle.shuffle_encrypted_deck(&mut rng, apk, &encrypted, POKER_CTX);

    let result2 = shuffle.verify_shuffle(
        apk,
        &Verified::new(encrypted),
        &encrypted,
        tampered_proof,
        POKER_CTX,
    );
    assert!(result2.is_none(), "wrong deck should fail verification");
}

#[test]
fn test_reveal_token_proof_catches_wrong_key() {
    let mut rng = rand::thread_rng();
    let shuffle = TestDeck::default();

    let (sk1, pk1, proof1) = shuffle.keygen(&mut rng, POKER_CTX);
    let vpk1 = proof1.verify(pk1, POKER_CTX).unwrap();

    let (_, pk2, proof2) = shuffle.keygen(&mut rng, POKER_CTX);
    let vpk2 = proof2.verify(pk2, POKER_CTX).unwrap();

    let apk = AggregatePublicKey::new(&[vpk1, vpk2]);

    let encrypted = shuffle.encrypt_initial_deck(apk, POKER_CTX);

    let (deck, shuffle_proof) =
        shuffle.shuffle_encrypted_deck(&mut rng, apk, &encrypted, POKER_CTX);
    let verified = shuffle
        .verify_shuffle(
            apk,
            &Verified::new(encrypted),
            &deck,
            shuffle_proof,
            POKER_CTX,
        )
        .unwrap();

    let card = verified.get(0).unwrap();

    let (token, proof) = card.reveal_token(&mut rng, &sk1, pk1, POKER_CTX);

    assert!(proof.verify(vpk1, token, card, POKER_CTX).is_some());
    assert!(proof.verify(vpk2, token, card, POKER_CTX).is_none());
}

#[test]
fn test_error_type_display() {
    assert_eq!(
        ShuffleError::InvalidProof.to_string(),
        "proof verification failed"
    );
    assert_eq!(
        ShuffleError::InvalidRevealTokenProof.to_string(),
        "reveal token proof verification failed"
    );
    assert_eq!(
        ShuffleError::IndexOutOfBounds { index: 5, size: 3 }.to_string(),
        "index 5 out of bounds for deck size 3"
    );
    assert_eq!(
        ShuffleError::InsufficientRevealTokens {
            required: 3,
            provided: 1
        }
        .to_string(),
        "insufficient reveal tokens: required 3, provided 1"
    );
}

#[test]
fn test_multiple_rounds_same_deck() {
    let mut rng = rand::thread_rng();
    let shuffle = TestDeck::default();

    let (sk1, pk1, proof1) = shuffle.keygen(&mut rng, POKER_CTX);
    let vpk1 = proof1.verify(pk1, POKER_CTX).unwrap();

    let (sk2, pk2, proof2) = shuffle.keygen(&mut rng, POKER_CTX);
    let vpk2 = proof2.verify(pk2, POKER_CTX).unwrap();

    let apk = AggregatePublicKey::new(&[vpk1, vpk2]);

    let encrypted = shuffle.encrypt_initial_deck(apk, POKER_CTX);

    let (deck, _) = shuffle.shuffle_encrypted_deck(&mut rng, apk, &encrypted, POKER_CTX);
    let mut verified_deck = Verified::new(deck);

    for round in 0..5 {
        let (new_deck, proof) = shuffle.shuffle_deck(&mut rng, apk, &verified_deck, POKER_CTX);
        let verified = shuffle.verify_shuffle(apk, &verified_deck, &new_deck, proof, POKER_CTX);

        assert!(
            verified.is_some(),
            "round {} shuffle should verify",
            round + 1
        );
        verified_deck = verified.unwrap();

        if round < 4 {
            let card = verified_deck.get(0).unwrap();
            let (token1, proof1) = card.reveal_token(&mut rng, &sk1, pk1, POKER_CTX);
            let verified1: Verified<RevealToken> =
                proof1.verify(vpk1, token1, card, POKER_CTX).unwrap();

            let (token2, proof2) = card.reveal_token(&mut rng, &sk2, pk2, POKER_CTX);
            let verified2: Verified<RevealToken> =
                proof2.verify(vpk2, token2, card, POKER_CTX).unwrap();

            let art = AggregateRevealToken::new(&[verified1, verified2]);
            let revealed = shuffle.reveal_card(art, card);
            assert!(
                revealed.is_some(),
                "should reveal card in round {}",
                round + 1
            );
        }
    }
}
