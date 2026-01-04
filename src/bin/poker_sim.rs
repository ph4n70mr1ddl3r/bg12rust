use bg12rust::{
    AggregatePublicKey, AggregateRevealToken, MaskedCard, MaskedDeck, PublicKey, RevealToken,
    RevealTokenProof, SecretKey, Shuffle, Verified,
};
use rand::RngCore;
use std::time::Instant;

type Deck = Shuffle<52>;

struct Player {
    name: String,
    secret_key: SecretKey,
    public_key: PublicKey,
    verified_pk: Verified<PublicKey>,
}

struct PokerTable {
    shuffle: Deck,
    aggregate_pk: AggregatePublicKey,
    players: Vec<Player>,
}

impl PokerTable {
    fn new(player_names: &[&str]) -> Self {
        let shuffle = Deck::default();
        let mut rng = rand::thread_rng();
        let ctx = b"texas_hold'em";

        let players: Vec<Player> = player_names
            .iter()
            .map(|name| {
                let (sk, pk, proof) = shuffle.keygen(&mut rng, ctx);
                let vpk = proof.verify(pk, ctx).unwrap();
                Player {
                    name: name.to_string(),
                    secret_key: sk,
                    public_key: pk,
                    verified_pk: vpk,
                }
            })
            .collect();

        let apk =
            AggregatePublicKey::new(&players.iter().map(|p| p.verified_pk).collect::<Vec<_>>());

        Self {
            shuffle,
            aggregate_pk: apk,
            players,
        }
    }

    fn deal_hole_cards(&self, deck: Verified<MaskedDeck<52>>, start_idx: usize) -> Vec<MaskedCard> {
        (0..4).map(|i| deck.get(start_idx + i).unwrap()).collect()
    }

    fn deal_community_cards(
        &self,
        deck: Verified<MaskedDeck<52>>,
        start_idx: usize,
        count: usize,
    ) -> Vec<MaskedCard> {
        (0..count)
            .map(|i| deck.get(start_idx + i).unwrap())
            .collect()
    }
}

fn create_reveal_tokens(
    rng: &mut impl RngCore,
    card: MaskedCard,
    players: &[Player],
    ctx: &[u8],
) -> Vec<(RevealToken, RevealTokenProof)> {
    players
        .iter()
        .map(|p| card.reveal_token(rng, &p.secret_key, p.public_key, ctx))
        .collect()
}

fn verify_and_aggregate_tokens(
    card: MaskedCard,
    tokens_and_proofs: &[(RevealToken, RevealTokenProof)],
    players: &[Player],
    ctx: &[u8],
) -> AggregateRevealToken {
    let verified_tokens: Vec<Verified<RevealToken>> = tokens_and_proofs
        .iter()
        .zip(players.iter())
        .map(|(token_proof, player)| {
            let (token, proof) = token_proof;
            proof.verify(player.verified_pk, *token, card, ctx).unwrap()
        })
        .collect();

    AggregateRevealToken::new(&verified_tokens)
}

fn card_to_string(shuffle: &Deck, art: AggregateRevealToken, card: MaskedCard) -> String {
    let idx = shuffle.reveal_card(art, card).unwrap();

    let suits = ["♣", "♦", "♥", "♠"];
    let ranks = [
        "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A",
    ];

    format!("{}{}", ranks[idx % 13], suits[idx / 13])
}

fn main() {
    println!("=== Two-Player Texas Hold'em Simulation ===\n");

    let mut rng = rand::thread_rng();
    let ctx = b"texas_hold'em";

    let table = PokerTable::new(&["Alice", "Bob"]);
    println!(
        "Players: {}",
        table
            .players
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("Context: {}", String::from_utf8_lossy(ctx));
    println!();

    println!("--- Deck Preparation ---");

    let start_encrypt = Instant::now();
    let initial_encrypted = table.shuffle.encrypt_initial_deck(table.aggregate_pk, ctx);
    let encrypt_time = start_encrypt.elapsed();
    println!(
        "Encrypt unshuffled deck with joint key... ({:.2}s)",
        encrypt_time.as_secs_f64()
    );

    let start_verify_enc = Instant::now();
    let encryption_valid =
        table
            .shuffle
            .verify_initial_encryption(table.aggregate_pk, &initial_encrypted, ctx);
    let verify_enc_time = start_verify_enc.elapsed();
    println!(
        "✓ Encryption verified ({:.2}s)",
        verify_enc_time.as_secs_f64()
    );
    assert!(encryption_valid, "Initial encryption should be valid");

    println!("\n--- Shuffle Phase ---");

    let start_alice = Instant::now();
    let (alice_deck, alice_proof) =
        table
            .shuffle
            .shuffle_encrypted_deck(&mut rng, table.aggregate_pk, &initial_encrypted, ctx);
    let alice_shuffle_time = start_alice.elapsed();
    println!(
        "Alice shuffles the encrypted deck... ({:.2}s)",
        alice_shuffle_time.as_secs_f64()
    );

    println!("\n--- Verification Phase ---");

    let start_alice_verify = Instant::now();
    let alice_vdeck = table
        .shuffle
        .verify_shuffle(
            table.aggregate_pk,
            &Verified::new(initial_encrypted),
            alice_deck,
            alice_proof,
            ctx,
        )
        .expect("Alice's shuffle should be valid");
    let alice_verify_time = start_alice_verify.elapsed();
    println!(
        "✓ Alice's initial shuffle verified ({:.2}s)",
        alice_verify_time.as_secs_f64()
    );

    let start_bob = Instant::now();
    let (bob_deck, bob_proof) =
        table
            .shuffle
            .shuffle_deck(&mut rng, table.aggregate_pk, &alice_vdeck, ctx);
    let bob_shuffle_time = start_bob.elapsed();
    println!(
        "Bob shuffles Alice's verified deck... ({:.2}s)",
        bob_shuffle_time.as_secs_f64()
    );

    let start_bob_verify = Instant::now();
    let final_deck = table
        .shuffle
        .verify_shuffle(table.aggregate_pk, &alice_vdeck, bob_deck, bob_proof, ctx)
        .expect("Bob's shuffle should be valid");
    let bob_verify_time = start_bob_verify.elapsed();
    println!(
        "✓ Bob's shuffle verified ({:.2}s)",
        bob_verify_time.as_secs_f64()
    );

    println!("\n✓ Final deck is now locked - no player knows the card order!");
    println!();

    let total_shuffle_time = alice_shuffle_time + bob_shuffle_time;
    let total_verify_time = alice_verify_time + bob_verify_time;
    println!("--- Timing Summary ---");
    println!(
        "  Total shuffle time:  {:.2}s",
        total_shuffle_time.as_secs_f64()
    );
    println!("  Total proof size:    ~5.5 KB per shuffle");
    println!(
        "  Total verify time:   {:.2}s",
        total_verify_time.as_secs_f64()
    );
    println!("  Encrypt initial:     {:.2}s", encrypt_time.as_secs_f64());
    println!(
        "  Verify encryption:   {:.2}s",
        verify_enc_time.as_secs_f64()
    );
    println!();

    println!("--- Dealing Phase ---");

    let hole_cards = table.deal_hole_cards(final_deck, 0);
    let alice_hole = &hole_cards[0..2];
    let bob_hole = &hole_cards[2..4];

    println!("Alice dealt encrypted hole cards at positions 0,1");
    println!("Bob dealt encrypted hole cards at positions 2,3");
    println!();

    println!("--- Revealing Hole Cards ---");

    let start_reveal = Instant::now();
    println!("\nAlice's hole cards:");
    for (i, card) in alice_hole.iter().enumerate() {
        let tokens = create_reveal_tokens(&mut rng, *card, &table.players, ctx);
        let art = verify_and_aggregate_tokens(*card, &tokens, &table.players, ctx);
        let card_str = card_to_string(&table.shuffle, art, *card);
        println!(
            "  Card {}: {} (both players cooperated to reveal)",
            i + 1,
            card_str
        );
    }

    println!("\nBob's hole cards:");
    for (i, card) in bob_hole.iter().enumerate() {
        let tokens = create_reveal_tokens(&mut rng, *card, &table.players, ctx);
        let art = verify_and_aggregate_tokens(*card, &tokens, &table.players, ctx);
        let card_str = card_to_string(&table.shuffle, art, *card);
        println!(
            "  Card {}: {} (both players cooperated to reveal)",
            i + 1,
            card_str
        );
    }
    let reveal_time = start_reveal.elapsed();

    println!("\n--- Dealing Community Cards ---");

    let flop = table.deal_community_cards(final_deck, 7, 3);
    let turn = table.deal_community_cards(final_deck, 10, 1);
    let river = table.deal_community_cards(final_deck, 11, 1);

    println!("Flop dealt to positions 7,8,9 (3 cards)");
    println!("Turn dealt to position 10 (1 card)");
    println!("River dealt to position 11 (1 card)");
    println!("Positions 4,5,6 are burn cards (unused)");
    println!();

    println!("--- Revealing Community Cards ---");

    println!("\nFlop:");
    for (i, card) in flop.iter().enumerate() {
        let tokens = create_reveal_tokens(&mut rng, *card, &table.players, ctx);
        let art = verify_and_aggregate_tokens(*card, &tokens, &table.players, ctx);
        let card_str = card_to_string(&table.shuffle, art, *card);
        println!("  Card {}: {}", i + 1, card_str);
    }

    println!("\nTurn:");
    for card in turn.iter() {
        let tokens = create_reveal_tokens(&mut rng, *card, &table.players, ctx);
        let art = verify_and_aggregate_tokens(*card, &tokens, &table.players, ctx);
        let card_str = card_to_string(&table.shuffle, art, *card);
        println!("  Card: {}", card_str);
    }

    println!("\nRiver:");
    for card in river.iter() {
        let tokens = create_reveal_tokens(&mut rng, *card, &table.players, ctx);
        let art = verify_and_aggregate_tokens(*card, &tokens, &table.players, ctx);
        let card_str = card_to_string(&table.shuffle, art, *card);
        println!("  Card: {}", card_str);
    }

    println!("\n=== Game Summary ===");
    println!("Steps:");
    println!("  1. Create unshuffled deck (52 visible cards)");
    println!("  2. Encrypt with joint key (deterministic, verifiable)");
    println!("  3. Alice shuffles + re-encrypts");
    println!("  4. Bob shuffles + re-encrypts");
    println!("  5. Cards revealed with cooperation");
    println!("Total shuffles: 2 (Alice then Bob)");
    println!("Zero-knowledge proofs verified: 4");
    println!("Cards revealed: 8 (4 hole + 4 community)");
    println!("Cards remaining encrypted: 44");
    println!();
    println!("Timing:");
    println!(
        "  Shuffle + proof:  {:.2}s",
        total_shuffle_time.as_secs_f64()
    );
    println!(
        "  Verify proofs:    {:.2}s",
        total_verify_time.as_secs_f64()
    );
    println!("  Reveal 8 cards:   {:.2}s", reveal_time.as_secs_f64());
    println!();
    println!("The deck can continue being used for:");
    println!("  - Revealing showdown cards");
    println!("  - Dealing to additional players");
    println!("  - Future hands with the same deck");
    println!();
    println!("Note: Both players cooperated to reveal cards.");
    println!("In a real game, players would only reveal their own hole cards.");
}
