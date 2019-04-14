# Provisions: Privacy-preserving proofs of solvency

This Rust is an implementation of the [Provisions Protocol][Paper] which is described like so:

> Bitcoin exchanges function like banks, securely holding their customers' bitcoins on their behalf.
> Several exchanges have suffered catastrophic losses with customers permanently losing their
> savings. A proof of solvency demonstrates that the exchange controls sufficient reserves to settle
> each customer's account. We introduce Provisions, a privacy-preserving proof of solvency whereby
> an exchange does not have to disclose its Bitcoin addresses; total holdings or liabilities; or any
> information about its customers. We also propose an extension which prevents exchanges from
> colluding to cover for each other's losses. We have implemented Provisions and it offers practical
> computation times and proof sizes even for a large Bitcoin exchange with millions of customers.

**Warning: This library has not received any security audit and is authored by an novice
cryptographer. It is very likely insecure and _should not be used in any production systems._**

## Supported Features

The protocol multiple proofs and a few optional extensions. This is the status of support
of those features in this project so far:

| Name | Description | Status |
| --- | --- | --- |
| Proof of Assets | Proof of knowledge of the on-chain balance and private keys. | :white_check_mark: |
| Proof of Liability | Proof of knowledge of all customers and their balance. | :white_check_mark: |
| Proof of Solvency | Proof that `total assets - total liabilities = 0`. | :white_check_mark: |
| Proof of Surplus | Optional proof of surplus of assets so that the prover can have more assets than liabilities without the proof failing. | :x: |
| Proof of Non-Collusion | Optional proof that can be used to verify provers are not colluding and including the same asset in multiple proofs of solvency. | :x: |

## Usage

Coming soon. In the meantime, see `tests/integration_test.rs` for current API.

Currently this only works with small sets of addresses and liabilities since it does everything in
memory. Future work will include persistence to allow it to scale up.

[Paper]: https://crypto.stanford.edu/~dabo/pubs/abstracts/provisions.html
