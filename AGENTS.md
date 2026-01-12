# AGENTS.md - Guide for Claude Code and Other AI Agents

This document provides guidelines for working with the bg12rust codebase, a Bayer-Groth 2012 mental poker library implementing zero-knowledge shuffle proofs in Rust.

## Project Structure

```
/home/riddler/bg12rust/
├── src/
│   ├── lib.rs              # Main library (1800+ lines of cryptographic code)
│   └── bin/
│       └── poker_sim.rs    # Demo binary for Texas Hold'em simulation
├── tests/
│   └── integration_test.rs # Integration tests for full workflows
├── Cargo.toml              # Package manifest with arkworks dependencies
└── AGENTS.md               # This file
```

## Build, Lint, and Test Commands

### Standard Commands
```bash
cargo build              # Debug build
cargo build --release    # Optimized release build
cargo test               # Run all tests (unit + integration + doc)
cargo test --lib         # Run only library unit tests
cargo test --test integration_test  # Run specific test file
cargo doc --no-deps      # Generate documentation
cargo clippy             # Run linter
cargo clippy --fix       # Run linter with auto-fixes
```

### Running Single Tests
```bash
cargo test test_keygen_and_ownership_proof       # By test name
cargo test --test integration_test test_full_poker_workflow  # Integration test
cargo test --lib -- --test-threads=1             # Single-threaded for debugging
```

### Test Patterns
- Unit tests reside in `src/lib.rs` under `#[cfg(test)] mod tests`
- Integration tests live in `tests/`
- Doc tests are embedded in doc comments

## Code Style Guidelines

### Imports and Dependencies
- Group imports by crate: standard library → external crates → local modules
- Use specific imports over glob imports (`use ark_ec::short_weierstrass::SWCurveConfig`)
- Keep dependencies minimal; the project uses arkworks suite, rand, sha2, and zeroize
- Import traits where used (`use ark_ff::Field, UniformRand;`)

### Formatting
- Run `cargo fmt` before committing (4-space indentation, Rust 2021 edition)
- Maximum line length: 100 characters
- Use blank lines to separate logical sections within functions
- No trailing whitespace

### Types and Generics
- Use const generics for deck size: `Shuffle<N>` where `N: usize`
- Derive `Debug, Clone, Copy` for most public types; add `PartialEq, Eq` where meaningful
- Mark internal types (PedersonCommitment, MultiExpArg) as non-public
- Use tuple structs for simple wrappers: `pub struct RevealToken(CurveAffine)`

### Naming Conventions
- **Types**: PascalCase (`ShuffleProof`, `AggregatePublicKey`)
- **Constants**: SCREAMING_SNAKE_CASE with version suffixes (`PEDERSON_H_PRNG_SEED`)
- **Functions**: snake_case (`encrypt_initial_deck`, `verify_shuffle`)
- **Type parameters**: Uppercase single letters (`const N: usize`)
- **Variables**: snake_case (`encrypted_deck`, `shuffle_proof`)
- **Modules**: snake_case (`src/bin/poker_sim.rs`)

### Error Handling
- Prefer `Option` over `Result` for verification functions (returns `Some(Verified<T>)` or `None`)
- Use `ShuffleError` enum for detailed errors (see `src/lib.rs:28-75`)
- Use `ShuffleResult<T>` alias: `type ShuffleResult<T> = core::result::Result<T, ShuffleError>`
- Avoid `unwrap()` in production code; use `expect()` with descriptive messages
- Use `#[must_use]` on functions that return verification results

### Documentation
- Document all public APIs with `# Arguments`, `# Returns`, `# Examples` sections
- Include doc tests in examples (run via `cargo test --doc`)
- Use triple-backticks for code examples in docs
- Reference paper URLs in structural comments (e.g., Bayer-Groth 2012)

### Cryptographic Code Specifics
- Domain separation strings use versioning: `b"bg12rust/DLOG/v1"`
- Use `arkworks` traits: `Field`, `UniformRand`, `CanonicalSerialize`
- Memory-sensitive types implement `Zeroize, ZeroizeOnDrop` (see `SecretKey`)
- PRNG seeding uses SHA-256 for deterministic initialization

### Testing Requirements
- All new functionality must have corresponding tests
- Tests should cover: success cases, failure cases, edge cases
- Integration tests simulate full workflows (e.g., `test_full_poker_workflow`)
- Property tests verify cryptographic properties (determinism, all cards present)

### Key Types and Components
- `Shuffle<N>`: Main API struct for deck operations with const generic N (deck size)
- `Verified<T>`: Marker type for cryptographically verified values
- `MaskedDeck<N>`: Array of ElGamal-encrypted cards
- `ShuffleProof<N>`: Bayer-Groth 2012 zero-knowledge shuffle proof
- `OwnershipProof`: Schnorr-style proof of secret key ownership
- `RevealTokenProof`: Chaum-Pedersen DLEQ proof for card decryption
- `PedersonCommitKey<N>`: Commitment key for zero-knowledge proofs

### Internal Patterns and Macros
- `ct_mspp!`: Multi-scalar product macro for ElGamal ciphertext operations
- `impl_valid_and_serde_unit!`: Macro implementing serialization for types with single field
- `impl_valid_and_deser!`: Macro implementing serialization for types with multiple fields
- `usize_to_u64!`: Macro for safe usize to u64 conversion with bounds checking

### Security Considerations
- SecretKey implements Zeroize and ZeroizeOnDrop for automatic memory clearing
- All cryptographic randomness comes from StdRng seeded with SHA-256
- Domain separation strings prevent protocol confusion across versions
- Verification functions return Option to avoid panics on invalid proofs

### Working with Verified Types
- Verified<MaskedDeck<N>> extends MaskedDeck with .get() method for card access
- Verified types can only be constructed through successful verification
- Never construct Verified types manually without verification
- The Verified marker provides compile-time safety for cryptographic guarantees

### Code Review Checklist
- [ ] Code compiles without warnings (`cargo build` with `RUSTFLAGS=-D warnings`)
- [ ] All tests pass (`cargo test`)
- [ ] Clippy passes (`cargo clippy`)
- [ ] New public APIs have documentation
- [ ] Cryptographic operations have appropriate randomness sources
- [ ] No hardcoded secrets or weak randomness

### Binary Target
- The binary at `src/bin/poker_sim.rs` is a demonstration, not a CLI tool
- Keep it focused on simulation and benchmarking, not general utilities
