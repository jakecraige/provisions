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

The protocol includes multiple proofs and a few optional extensions. This is the status of support
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
memory.

## Future Work

A list of features that I'd like to eventually have this library support.

- **Persistence:** This is needed to run on larger datasets as well as to actually implement this in
  a system. You have to provide the data in a format available for others to verify.
- **Proof of Surplus:** Many exchanges operate on a surplus, this is a necessary feature for any
  practical usage.
- **A CLI:** A CLI interface that can accept data from some data source like CSV and produce a proof
  that can be published and then used to verify the proof on that data.

## Open Problems

There's a few open problems that would need to be supported for practical usage or improvements
from when the paper was published, these are:

**Support for cold-storage keys**

Exchanges operate with a majority of funds in cold-storage. To have an option of publishing a Proof
of Solvency we need to support this use case that doesn't require regularly having cold-storage
private keys available. The idea of ["Valet
Keys"](https://rwc.iacr.org/2016/Slides/Provisions%20talk%20RWC.pdf) has been proposed but is not
documented in a paper yet. We'll need to investigate this further and see how we could integrate
this.

**Support for addresses**

The protocol currently requires publishing all public keys alongside some extras to create an
anonimity set. This is problematic for cold-storage if there are no sends from the address but it
has received funds. If they are included in the proof it would break some of the privacy of the
protocol since it would be easy to confirm which of these are not on chain by diffing with the
published PKs on chain. This could be done with proving systems like zkSNARKS or Bulletproofs but
would take some work to integrate it with the protocol.

**General Proof Optimizations**

All the proofs in the protocol scale linearly and are quite large. By using newer cryptographic
tools we could reduce the size of the proofs significantly. Bulletproofs for range proofs have been
proposed for this.

[Paper]: https://crypto.stanford.edu/~dabo/pubs/abstracts/provisions.html
