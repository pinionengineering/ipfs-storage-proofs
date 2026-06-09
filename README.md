# IPFS Storage Proofs

A Go library that adapts the [storage-proofs](https://github.com/pinionengineering/storage-proofs) `line` API for use with IPFS. It bridges the gap between IPFS's content-addressed block DAG and the index-based `blocks.BlockStore` interface that storage-proof protocols expect.

File transfer is out of scope. This library only handles tagging and proof generation/verification, assuming the IPFS node handles data movement.

---

## Design

### The Problem

Storage-proof protocols operate on sequences of fixed-size, index-addressable blocks: block 0, block 1, …, block n. IPFS stores data as a Merkle DAG of content-addressed blocks, with no canonical index and no fixed block size. This library introduces a thin layer that imposes an ordering on IPFS blocks and satisfies the `blocks.BlockStore` interface against live IPFS data.

### CID as Block Identifier

Every storage-proof tag includes a block identifier `W` that binds the tag to a specific block. Schemes like Ateniese and SW use `W = name || index` by default, tying each tag to its integer position within a file.

This library uses `W = CID.Bytes()` instead. Because a CID is a content hash, it is globally unique per block regardless of which file it belongs to or what position it occupies in any list. A tag produced with `W = CID` is valid at any position in any `ChallengedList`, which enables a single key pair to authenticate an arbitrary collection of IPFS blocks — spanning multiple files and multiple roots — without re-tagging.

The verifier needs only the CID for each challenged block to reconstruct `W`. In IPFS, CIDs are always known to the challenger, so this requires no additional communication.

### Data Model

**TagBlock** associates one storage-proof tag with the IPFS CID of the block it authenticates:

```go
type TagBlock struct {
    Tag line.Tag  // opaque auth tag produced by the storage-proof protocol
    Cid cid.Cid   // CID of the IPFS block whose bytes were tagged
}
```

**TagList** holds all TagBlocks for a single IPFS DAG, ordered by CID bytes, and records the root CID:

```go
type TagList struct {
    Tags []TagBlock
    Root cid.Cid
}
```

**ChallengedList** implements `blocks.BlockStore`. It is constructed from one or more TagLists; `Block(i)` fetches live bytes from the IPFS node using the stored CID:

```go
func (cl *ChallengedList) Block(i int) ([]byte, error)      // fetches block i from IPFS by CID
func (cl *ChallengedList) SetBlock(_ int, _ []byte) error   // always errors — read-only
```

### TagList Generation

1. Walk the Merkle DAG rooted at the given CID, collecting every reachable node (root and all descendants). Shared nodes are deduplicated.
2. Sort collected CIDs by raw bytes (`bytes.Compare(a.Bytes(), b.Bytes())`).
3. Build a `blocks.MemStore` from the sorted raw bytes and pass it to `line.Tagger.TagBlocks`.
4. Pair each resulting tag with its CID to form a `TagBlock`.

All DAG nodes are tagged, not just leaves. An intermediate node is required to reconstruct the file; a missing internal node makes the data unrecoverable.

### Challenge Flow

A challenge may target one or more root CIDs:

1. Look up the stored `TagList` for each requested root.
2. Concatenate the `TagBlocks` from each `TagList` in the order the roots appear in the challenge.
3. Pass the resulting `ChallengedList` to `line.Prover.Prove`.

Because `W = CID.Bytes()`, each tag is valid regardless of its position in the concatenated list. The verifier reconstructs the same ordering and verifies via `line.Validator.Verify`.

### Recommended Protocol

**SW Public** (`line/swpub`) is recommended for IPFS:

- **Public verifiability**: any network participant can issue challenges using only the public key — no shared secret required between challenger and prover.
- **Cross-CID challenges**: a single proof can span multiple root CIDs. Proof size is one EC point plus a small number of field elements regardless of how many blocks are challenged.
- **Efficient verification**: elliptic-curve arithmetic (BLS) is significantly faster than RSA-group arithmetic at equivalent security.

Ateniese and SW Private support the same cross-CID approach but require the challenger to hold the secret key. Erway's skip list rank is positional and does not support cross-CID challenges; use it only for single-DAG proofs where dynamic updates are needed.

---

## Usage

This library exposes two IPFS-specific operations that plug directly into the `line` API. Everything else (key generation, challenge issuance, proof verification) is handled by storage-proofs directly.

**Tagging** — walk an IPFS DAG and produce a `TagList` using any `line.Tagger`:

```go
tagList, err := ipfsproof.TagRoot(ctx, ipfsNode, rootCID, tagger)
```

**Building a ChallengedList** — given stored `TagList`s and a set of root CIDs, produce the `blocks.BlockStore` the prover passes to `line.Prover.Prove`:

```go
store, err := ipfsproof.NewChallengedList(ctx, ipfsNode, tagLists, rootCIDs)
proof, err := prover.Prove(chal, store)
```

---

## Dependencies

- [storage-proofs](https://github.com/pinionengineering/storage-proofs) — protocol implementations (PDP: ateniese, erway; POR: sw, bjo)
- [go-ipld-format](https://github.com/ipfs/go-ipld-format) — `format.NodeGetter` interface; satisfied by both the kubo RPC client (`httpApi.Dag()`) and an in-process IPFS node (`coreAPI.Dag()`)
