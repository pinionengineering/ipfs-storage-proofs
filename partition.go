package ipfsproof

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/ipfs/go-cid"
	format "github.com/ipfs/go-ipld-format"
	"github.com/pinionengineering/storage-proofs/blocks"
)

// manifestEntry is one block's identity and size, collected during a
// manifest-only walk (no bytes retained).
type manifestEntry struct {
	c    cid.Cid
	size int
}

// WalkDAGManifest walks the IPFS DAG rooted at root and returns the ordered
// manifest of reachable blocks (CID + byte length), in the same CID-sorted
// order walkDAG produces for TagRoot/TagRootChunked. Unlike walkDAG, block
// bytes are discarded as soon as their length is recorded, so a planning
// pass over a very large root doesn't hold the whole DAG's bytes in memory
// at once — only the manifest, proportional to block *count*, not total
// bytes.
func WalkDAGManifest(ctx context.Context, getter format.NodeGetter, root cid.Cid) ([]RealBlockInfo, error) {
	seen := make(map[cid.Cid]bool)
	var collected []manifestEntry

	var walk func(c cid.Cid) error
	walk = func(c cid.Cid) error {
		if seen[c] {
			return nil
		}
		seen[c] = true

		node, err := getter.Get(ctx, c)
		if err != nil {
			return fmt.Errorf("ipfsproof: WalkDAGManifest: get %s: %w", c, err)
		}
		collected = append(collected, manifestEntry{c: c, size: len(node.RawData())})

		for _, link := range node.Links() {
			if err := walk(link.Cid); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walk(root); err != nil {
		return nil, err
	}

	sort.Slice(collected, func(i, j int) bool {
		return bytes.Compare(collected[i].c.Bytes(), collected[j].c.Bytes()) < 0
	})

	manifest := make([]RealBlockInfo, len(collected))
	for i, e := range collected {
		manifest[i] = RealBlockInfo{Cid: e.c, Size: e.size}
	}
	return manifest, nil
}

// rangeStore wraps a blocks.BlockStore, exposing only a contiguous
// [start,end) window of its index space via Len()/IDs(). Block(id) delegates
// straight through to inner, since id resolution is content-addressed and
// doesn't depend on which window it's called from — this is what lets a
// partition worker call the exact same, unmodified TagBlocks implementations
// on a bounded slice of a much larger root, with tags[0] in the result
// corresponding to global index start, tags[1] to start+1, and so on.
type rangeStore struct {
	inner      blocks.BlockStore
	start, end int
}

var _ blocks.BlockStore = (*rangeStore)(nil)

func (s *rangeStore) Len() int { return s.end - s.start }

func (s *rangeStore) IDs() [][]byte { return s.inner.IDs()[s.start:s.end] }

func (s *rangeStore) Block(id []byte) ([]byte, error) { return s.inner.Block(id) }

func (s *rangeStore) SetBlock(_ []byte, _ []byte) error {
	return fmt.Errorf("ipfsproof: rangeStore is read-only")
}

// lazyManifestStore implements CIDBlockStore over a manifest of real block
// CIDs, fetching bytes lazily from getter as each is actually needed — a
// partition worker only ever asks for ids inside its own assigned range, so
// this never fetches blocks outside that range. Used for the non-chunked
// (Ateniese) partitioning path; the chunked (SW-Priv/SW-Pub) path reuses the
// existing superBlockStore/lazyByteSource machinery instead (see
// NewChunkedPartitionStore).
type lazyManifestStore struct {
	cids   []cid.Cid
	index  map[string]int
	ctx    context.Context
	getter format.NodeGetter
}

var _ CIDBlockStore = (*lazyManifestStore)(nil)

func newLazyManifestStore(ctx context.Context, getter format.NodeGetter, manifest []RealBlockInfo) *lazyManifestStore {
	cids := make([]cid.Cid, len(manifest))
	index := make(map[string]int, len(manifest))
	for i, b := range manifest {
		cids[i] = b.Cid
		index[string(b.Cid.Bytes())] = i
	}
	return &lazyManifestStore{cids: cids, index: index, ctx: ctx, getter: getter}
}

func (s *lazyManifestStore) Len() int { return len(s.cids) }

func (s *lazyManifestStore) CIDs() []cid.Cid { return s.cids }

func (s *lazyManifestStore) IDs() [][]byte {
	ids := make([][]byte, len(s.cids))
	for i, c := range s.cids {
		ids[i] = c.Bytes()
	}
	return ids
}

func (s *lazyManifestStore) Block(id []byte) ([]byte, error) {
	pos, ok := s.index[string(id)]
	if !ok {
		return nil, fmt.Errorf("ipfsproof: lazyManifestStore: block not found for id")
	}
	node, err := s.getter.Get(s.ctx, s.cids[pos])
	if err != nil {
		return nil, fmt.Errorf("ipfsproof: fetch %s: %w", s.cids[pos], err)
	}
	return node.RawData(), nil
}

func (s *lazyManifestStore) SetBlock(_ []byte, _ []byte) error {
	return fmt.Errorf("ipfsproof: lazyManifestStore is read-only")
}

// ManifestBlockCount returns the total number of tag units a manifest
// produces: len(manifest) for the non-chunked path (pass superBlockSize 0),
// or the sum of per-block super-block counts for the chunked path — matches
// ChunkedTagList.BlockCount()'s math exactly, without needing a full
// ChunkedTagList already built (used by planning, before any tag exists).
func ManifestBlockCount(manifest []RealBlockInfo, superBlockSize int) int {
	if superBlockSize <= 0 {
		return len(manifest)
	}
	total := 0
	for _, b := range manifest {
		total += superBlockCount(b.Size, superBlockSize)
	}
	return total
}

// NewPartitionStore builds a blocks.BlockStore over a bounded index range
// [start,end) of a root's manifest, fetching real block bytes lazily via
// getter — the non-chunked (Ateniese) partitioning path, where each manifest
// index is one real block.
func NewPartitionStore(ctx context.Context, getter format.NodeGetter, manifest []RealBlockInfo, start, end int) blocks.BlockStore {
	return &rangeStore{inner: newLazyManifestStore(ctx, getter, manifest), start: start, end: end}
}

// NewChunkedPartitionStore builds a blocks.BlockStore over a bounded virtual
// super-block index range [start,end) for a single root, reusing the exact
// same superBlockStore/lazyByteSource machinery NewChunkedChallengedList
// uses at prove time — the chunked (SW-Priv/SW-Pub) partitioning path, where
// a partition's index range can cut across real-block boundaries.
//
// start and end are always global super-block indices (into the root's
// whole, unsliced index space), same as NewPartitionStore's — regardless of
// whether manifest is the whole file's manifest or just a slice of it.
// globalOffset must be the super-block index manifest[0] actually starts at
// (0 if manifest is the whole file; see ResolveSuperBlockRange for how a
// caller working from a partial slice computes this). This is required —
// not just a memory optimization — because unlike a real block's CID, a
// super-block's id embeds its index directly, so tags computed from a
// slice without the correct global offset would carry the wrong id and
// never verify.
func NewChunkedPartitionStore(ctx context.Context, getter format.NodeGetter, root cid.Cid, manifest []RealBlockInfo, superBlockSize, globalOffset, start, end int) blocks.BlockStore {
	m := newRootManifestWithOffset(root, manifest, superBlockSize, globalOffset)
	inner := newSuperBlockStore([]*rootManifest{m}, newLazyByteSource(ctx, getter), superBlockSize)
	return &rangeStore{inner: inner, start: start - globalOffset, end: end - globalOffset}
}
