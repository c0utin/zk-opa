//! The login circuit accepts an honest credential and nothing that differs from it.

use ark_std::rand::{SeedableRng, rngs::StdRng};
use zkopa_prove::{
    Credential, Fr, IssuerKey, LoginCircuit, RevocationTree, SignedCredential, commitment,
    is_satisfied, revocation_tag,
};

const EPOCH: u64 = 1234;
// The top bit and mixed low bits are set, so every level of the path matters.
const ID: u32 = 0x9000_0005;

struct Issuer {
    key: IssuerKey,
    revoked: RevocationTree,
    rng: StdRng,
}

impl Issuer {
    fn new() -> Self {
        let mut rng = StdRng::seed_from_u64(7);
        let mut revoked = RevocationTree::default();
        // Neighbours of the test id, so a left/right mix-up on the path changes the root.
        for id in [ID ^ 1, ID + 2, 1] {
            revoked.revoke(id);
        }
        Self {
            key: IssuerKey::generate(&mut rng),
            revoked,
            rng,
        }
    }

    fn sign(&mut self, exp: u64) -> SignedCredential {
        let credential = Credential {
            id: ID,
            attributes: vec![10_001, 2, u64::MAX],
            exp,
        };
        self.key.sign(credential, &mut self.rng)
    }
}

fn satisfied(circuit: LoginCircuit<'_>) -> bool {
    is_satisfied(circuit).unwrap()
}

fn login<'a>(issuer: &Issuer, credential: &'a SignedCredential) -> LoginCircuit<'a> {
    LoginCircuit::new(
        issuer.key.public(),
        credential,
        &issuer.revoked,
        EPOCH,
        Fr::from(99u64),
    )
}

#[test]
fn accepts_a_valid_credential_and_denies_a_revoked_one() {
    let mut issuer = Issuer::new();
    let credential = issuer.sign(EPOCH + 100);
    assert!(credential.verify(issuer.key.public()));
    assert!(satisfied(login(&issuer, &credential)));

    issuer.revoked.revoke(ID);
    assert!(!satisfied(login(&issuer, &credential)));
}

#[test]
fn denies_a_path_for_another_id() {
    let mut issuer = Issuer::new();
    let credential = issuer.sign(EPOCH + 100);
    let circuit = login(&issuer, &credential);
    assert!(!satisfied(LoginCircuit {
        siblings: issuer.revoked.siblings(ID + 4),
        ..circuit
    }));
}

#[test]
fn expires_at_the_expiry_epoch() {
    let mut issuer = Issuer::new();
    let last = issuer.sign(EPOCH + 1);
    let expired = issuer.sign(EPOCH);
    let long_expired = issuer.sign(EPOCH - 1);
    let never = issuer.sign(u64::MAX);
    assert!(satisfied(login(&issuer, &last)));
    assert!(!satisfied(login(&issuer, &expired)));
    assert!(!satisfied(login(&issuer, &long_expired)));
    assert!(satisfied(login(&issuer, &never)));
}

#[test]
fn denies_an_attribute_changed_after_signing() {
    let mut issuer = Issuer::new();
    let mut forged = issuer.sign(EPOCH + 100);
    forged.credential.attributes[0] += 1;
    assert!(!forged.verify(issuer.key.public()));
    // Everything is consistent with the changed credential except the issuer's signature.
    assert!(!satisfied(login(&issuer, &forged)));

    let mut later = issuer.sign(EPOCH + 100);
    later.credential.exp += 1;
    assert!(!satisfied(login(&issuer, &later)));
}

#[test]
fn denies_another_issuers_key() {
    let mut issuer = Issuer::new();
    let credential = issuer.sign(EPOCH + 100);
    let other = IssuerKey::generate(&mut issuer.rng).public();
    assert!(!credential.verify(other));
    assert!(!satisfied(LoginCircuit {
        issuer: other,
        ..login(&issuer, &credential)
    }));
}

#[test]
fn denies_a_commitment_or_tag_it_did_not_compute() {
    let mut issuer = Issuer::new();
    let credential = issuer.sign(EPOCH + 100);
    let circuit = login(&issuer, &credential);
    let blinding = circuit.blinding;
    assert!(!satisfied(LoginCircuit {
        commitment: commitment(&[10_001, 3, u64::MAX], blinding),
        ..circuit
    }));
    assert!(!satisfied(LoginCircuit {
        commitment: commitment(&[10_001, 2, u64::MAX], blinding + Fr::from(1u64)),
        ..circuit
    }));
    assert!(!satisfied(LoginCircuit {
        tag: revocation_tag(ID, EPOCH + 1),
        ..circuit
    }));
    assert!(!satisfied(LoginCircuit {
        tag: revocation_tag(ID + 1, EPOCH),
        ..circuit
    }));
}

#[test]
fn credentials_and_keys_round_trip() {
    let mut issuer = Issuer::new();
    let credential = issuer.sign(EPOCH + 100);
    let bytes = credential.encode();
    assert_eq!(SignedCredential::decode(&bytes).unwrap(), credential);
    assert!(SignedCredential::decode(&bytes[..bytes.len() - 1]).is_err());

    let key = IssuerKey::from_bytes(&issuer.key.to_bytes()).unwrap();
    assert_eq!(key.public(), issuer.key.public());
    assert!(IssuerKey::from_bytes(&[0xff; 32]).is_err());
}
