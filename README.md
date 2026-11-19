# ZK-OPA: Privacy-Preserving Decentralized Authorization for Microservices

This research proposes **ZK-OPA**, a general, modular authorization system for microservices in which a Zero-Knowledge Proof (ZKP) is the access decision itself. Any operator that runs its own services can use it for fine-grained, privacy-preserving access control: a bank, a healthcare provider, a SaaS platform, a government service, or an internal platform. Banking is the running example in this proposal, not the only target.

A trusted issuer (the operator's identity system) signs a credential over a user's attributes. Policies are written in Rego, the language of Open Policy Agent (OPA), and compiled ahead of time into ZK circuits. OPA runs only at compile time and is not present in the services.

At login, the client proves once that it holds a valid, unrevoked credential and commits to its hidden attributes. From then on a service uses ZK-OPA the way it uses OPA: the handler builds an `input` from the request and its own data, names a decision path such as `transfers/create/allow`, and gets allow or deny. Instead of sending attributes, the client sends a proof that its committed attributes, together with that exact `input`, satisfy the whole policy. A small kernel in the service's own process encodes the `input`, checks the proof against a public verifying key, and returns the decision. A proof made for one request therefore fails for any other, and only the values the handler chose enter the proof, never the raw HTTP request. There is no policy engine at runtime, no central decision service, and no third-party call in the request path. Verification takes the same small, fixed time however complex the policy is.

Shared infrastructure holds only public commitments (verifying keys, policy hashes, revocation roots, state roots). Services receive them in the background, so requests never wait on them. No service ever sees the user's sensitive attributes, such as income or risk score in a bank, diagnoses in healthcare, or plan and usage data in SaaS.

ZK-OPA is implemented in Rust around one small kernel crate. The kernel takes the handler's `input`, the client's proof and the current time, returns allow or deny, and does no I/O. Proof systems, policy languages and hosts (a service extractor, and a command-line tool with OPA's verbs) are modules around it. The kernel and the prover are pure Rust.

The design is modular. Cryptography is a pluggable profile: each deployment chooses a classical profile with the smallest proofs or a post-quantum, setup-free profile with larger proofs. The classical profile is built first. Server-held state enters the proof by how fresh it must be:

- Data the verifying service owns is read exactly from its own store.
- Slowly changing data comes from signed state roots that the owner publishes each epoch.
- Consumable resources (quotas, rate limits, credits, seats, balances) use grants that the owner reserves up front.

The research will investigate:

- How to translate a provable subset of Rego into ZK circuits, and possibly a Rego-like language that is provable by construction.
- How to split proving into a heavy login proof and a small per-request proof.
- How to bring fresh server-held state into the proof without a synchronous call.
- Revocation, replay protection, and dynamic policies.

Moving the decision into the proof shifts the cost from the service to the client, which must generate a proof for every request. **The primary objective is to evaluate what this costs in per-request proving time, end-to-end latency, proof size per crypto profile, and policy expressiveness compared to a hybrid design (proof at login plus local OPA), locally evaluated OPA with signed tokens, and centralized OPA.**
