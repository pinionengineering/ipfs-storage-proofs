package ipfsproof

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/ipfs/go-cid"
	format "github.com/ipfs/go-ipld-format"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
)

// SuperBlockID encodes a challenge id for schemes (SW-Priv, SW-Pub) that
// virtualize real content blocks into fixed-size super-blocks: the root CID
// of the tagged DAG, plus an 8-byte big-endian index local to that root.
//
// Only the root's CID is ever encoded — never a content-block CID — because
// this id is used purely as PRF/hash input by por/sw, which both the prover
// and the client construct independently (the client already knows which
// root it's auditing and how many super-blocks it has; it never needs to
// know which physical content block or byte offset a given index maps to).
// The root-CID prefix exists only to keep two independently-tagged roots'
// local index spaces from colliding when a challenge merges more than one
// root (see NewChunkedChallengedList).
func SuperBlockID(root cid.Cid, localIndex uint64) []byte {
	rb := root.Bytes()
	id := make([]byte, len(rb)+8)
	copy(id, rb)
	binary.BigEndian.PutUint64(id[len(rb):], localIndex)
	return id
}

// ParseSuperBlockID splits an id produced by SuperBlockID back into its root
// CID and local index. cid.CidFromBytes reports how many leading bytes it
// consumed, so the variable-length CID prefix is parsed unambiguously.
func ParseSuperBlockID(id []byte) (cid.Cid, uint64, error) {
	n, root, err := cid.CidFromBytes(id)
	if err != nil {
		return cid.Undef, 0, fmt.Errorf("ipfsproof: ParseSuperBlockID: %w", err)
	}
	if len(id)-n != 8 {
		return cid.Undef, 0, fmt.Errorf("ipfsproof: ParseSuperBlockID: expected 8 trailing bytes, got %d", len(id)-n)
	}
	return root, binary.BigEndian.Uint64(id[n:]), nil
}

// RealBlockInfo records one real content block's CID and byte length — the
// manifest entry needed to know how many super-blocks a real block splits
// into, and where to fetch it, without holding its bytes in memory. Recorded
// once at tag time (bytes are already in hand from the DAG walk); persisted
// alongside the tags so prove time never needs to re-fetch a whole block
// just to learn its length.
type RealBlockInfo struct {
	Cid  cid.Cid
	Size int
}

// ChunkedTagList is the super-block analog of TagList: one tag per virtual
// super-block (not per real content block), plus the ordered manifest of
// real blocks needed to resolve a super-block's local index back to actual
// storage. A distinct type from TagList — Ateniese/Erway/BJO's TagList,
// cidStore, ChallengedList, TagRoot, and NewChallengedList are unaffected by
// anything in this file.
type ChunkedTagList struct {
	Root           cid.Cid
	Blocks         []RealBlockInfo // ordered manifest, CID-sorted (same order as the DAG walk)
	Tags           []line.Tag      // flat, ordered by (real block index, local super-block offset within it)
	SuperBlockSize int
}

// BlockCount returns the total number of virtual super-blocks across all of
// this tag list's real blocks — what pinion-prover returns to clients
// instead of a manifest (see rootManifest.total, which computes the same
// value from Blocks; kept as a method here for callers that only have the
// already-built ChunkedTagList and not a rootManifest).
func (tl *ChunkedTagList) BlockCount() int {
	total := 0
	for _, b := range tl.Blocks {
		total += superBlockCount(b.Size, tl.SuperBlockSize)
	}
	return total
}

// superBlockCount returns ceil(size/superBlockSize), with a minimum of 1 so
// even a zero-byte real block still gets one (fully zero-padded) super-block.
func superBlockCount(size, superBlockSize int) int {
	n := (size + superBlockSize - 1) / superBlockSize
	if n == 0 {
		n = 1
	}
	return n
}

type wireChunkedTagBlock struct {
	Cid  string `json:"cid"`
	Size int    `json:"size"`
}

type wireChunkedTagList struct {
	Root           string                `json:"root"`
	Blocks         []wireChunkedTagBlock `json:"blocks"`
	Tags           []string              `json:"tags"` // base64-encoded line.Tag bytes
	SuperBlockSize int                   `json:"super_block_size"`
}

// MarshalJSON encodes a ChunkedTagList for persistent storage.
func (tl ChunkedTagList) MarshalJSON() ([]byte, error) {
	w := wireChunkedTagList{
		Root:           tl.Root.String(),
		Blocks:         make([]wireChunkedTagBlock, len(tl.Blocks)),
		Tags:           make([]string, len(tl.Tags)),
		SuperBlockSize: tl.SuperBlockSize,
	}
	for i, b := range tl.Blocks {
		w.Blocks[i] = wireChunkedTagBlock{Cid: b.Cid.String(), Size: b.Size}
	}
	for i, t := range tl.Tags {
		w.Tags[i] = base64.StdEncoding.EncodeToString([]byte(t))
	}
	return json.Marshal(w)
}

// UnmarshalJSON decodes a ChunkedTagList from the JSON produced by MarshalJSON.
func (tl *ChunkedTagList) UnmarshalJSON(data []byte) error {
	var w wireChunkedTagList
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	root, err := cid.Decode(w.Root)
	if err != nil {
		return fmt.Errorf("ipfsproof: decode root CID: %w", err)
	}
	tl.Root = root
	tl.SuperBlockSize = w.SuperBlockSize
	tl.Blocks = make([]RealBlockInfo, len(w.Blocks))
	for i, wb := range w.Blocks {
		c, err := cid.Decode(wb.Cid)
		if err != nil {
			return fmt.Errorf("ipfsproof: decode block CID %d: %w", i, err)
		}
		tl.Blocks[i] = RealBlockInfo{Cid: c, Size: wb.Size}
	}
	tl.Tags = make([]line.Tag, len(w.Tags))
	for i, wt := range w.Tags {
		tagBytes, err := base64.StdEncoding.DecodeString(wt)
		if err != nil {
			return fmt.Errorf("ipfsproof: decode tag %d: %w", i, err)
		}
		tl.Tags[i] = line.Tag(tagBytes)
	}
	return nil
}

// rootManifest is the prefix-summed index for one root's real-block list,
// letting a local super-block index be resolved to (real block, byte range)
// in O(log k) for k real blocks, without needing the total super-block
// count to be recomputed on every lookup.
type rootManifest struct {
	root   cid.Cid
	blocks []RealBlockInfo
	prefix []int // len(blocks)+1; prefix[i] = super-blocks before real block i
}

func newRootManifest(root cid.Cid, realBlocks []RealBlockInfo, superBlockSize int) *rootManifest {
	prefix := make([]int, len(realBlocks)+1)
	for i, b := range realBlocks {
		prefix[i+1] = prefix[i] + superBlockCount(b.Size, superBlockSize)
	}
	return &rootManifest{root: root, blocks: realBlocks, prefix: prefix}
}

func (m *rootManifest) total() int { return m.prefix[len(m.blocks)] }

// resolve maps a local super-block index to the real block it falls in and
// its zero-based super-block offset within that real block.
func (m *rootManifest) resolve(localIndex int) (RealBlockInfo, int, error) {
	if localIndex < 0 || localIndex >= m.total() {
		return RealBlockInfo{}, 0, fmt.Errorf("ipfsproof: local index %d out of range [0,%d)", localIndex, m.total())
	}
	i := sort.Search(len(m.blocks), func(i int) bool { return m.prefix[i+1] > localIndex })
	return m.blocks[i], localIndex - m.prefix[i], nil
}

// blockByteSource abstracts where superBlockStore fetches real content-block
// bytes from — an in-memory map at tag time (bytes already in hand from the
// DAG walk), or a lazy, per-CID-cached IPFS fetch at prove time.
type blockByteSource interface {
	Bytes(c cid.Cid) ([]byte, error)
}

type memByteSource map[cid.Cid][]byte

func (m memByteSource) Bytes(c cid.Cid) ([]byte, error) {
	b, ok := m[c]
	if !ok {
		return nil, fmt.Errorf("ipfsproof: superBlockStore: block not found for %s", c)
	}
	return b, nil
}

// lazyByteSource fetches a real block's bytes from IPFS on first access and
// caches them, so that multiple super-blocks drawn from the same real block
// (only possible now that one real block can produce many virtual
// super-blocks) don't refetch it over the network.
type lazyByteSource struct {
	ctx    context.Context
	getter format.NodeGetter
	mu     sync.Mutex
	cache  map[cid.Cid][]byte
}

func newLazyByteSource(ctx context.Context, getter format.NodeGetter) *lazyByteSource {
	return &lazyByteSource{ctx: ctx, getter: getter, cache: make(map[cid.Cid][]byte)}
}

func (l *lazyByteSource) Bytes(c cid.Cid) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.cache[c]; ok {
		return b, nil
	}
	node, err := l.getter.Get(l.ctx, c)
	if err != nil {
		return nil, fmt.Errorf("ipfsproof: fetch %s: %w", c, err)
	}
	b := node.RawData()
	l.cache[c] = b
	return b, nil
}

// superBlockStore implements blocks.BlockStore over one or more roots'
// virtualized super-blocks. It never modifies the byte range it's given —
// Block(id) always returns exactly superBlockSize bytes, zero-padded on the
// right if the real block ends before the super-block boundary.
type superBlockStore struct {
	manifests      []*rootManifest
	byRoot         map[cid.Cid]*rootManifest
	src            blockByteSource
	superBlockSize int
}

var _ blocks.BlockStore = (*superBlockStore)(nil)

func newSuperBlockStore(manifests []*rootManifest, src blockByteSource, superBlockSize int) *superBlockStore {
	byRoot := make(map[cid.Cid]*rootManifest, len(manifests))
	for _, m := range manifests {
		byRoot[m.root] = m
	}
	return &superBlockStore{manifests: manifests, byRoot: byRoot, src: src, superBlockSize: superBlockSize}
}

func (s *superBlockStore) Len() int {
	n := 0
	for _, m := range s.manifests {
		n += m.total()
	}
	return n
}

func (s *superBlockStore) IDs() [][]byte {
	ids := make([][]byte, 0, s.Len())
	for _, m := range s.manifests {
		for i := 0; i < m.total(); i++ {
			ids = append(ids, SuperBlockID(m.root, uint64(i)))
		}
	}
	return ids
}

func (s *superBlockStore) Block(id []byte) ([]byte, error) {
	root, localIndex, err := ParseSuperBlockID(id)
	if err != nil {
		return nil, err
	}
	m, ok := s.byRoot[root]
	if !ok {
		return nil, fmt.Errorf("ipfsproof: superBlockStore: unknown root %s", root)
	}
	info, offset, err := m.resolve(int(localIndex))
	if err != nil {
		return nil, err
	}
	raw, err := s.src.Bytes(info.Cid)
	if err != nil {
		return nil, err
	}
	start := offset * s.superBlockSize
	out := make([]byte, s.superBlockSize) // zero-padded by default
	if start < len(raw) {
		end := start + s.superBlockSize
		if end > len(raw) {
			end = len(raw)
		}
		copy(out, raw[start:end])
	}
	return out, nil
}

func (s *superBlockStore) SetBlock(_ []byte, _ []byte) error {
	return fmt.Errorf("ipfsproof: superBlockStore is read-only")
}

// TagRootChunked walks the IPFS DAG rooted at root (same walk as TagRoot),
// virtualizes it into superBlockSize-byte super-blocks, tags them with
// tagger, and returns a ChunkedTagList.
func TagRootChunked(ctx context.Context, getter format.NodeGetter, root cid.Cid, tagger line.Tagger, superBlockSize int) (*ChunkedTagList, error) {
	collected, err := walkDAG(ctx, getter, root)
	if err != nil {
		return nil, err
	}

	realBlocks := make([]RealBlockInfo, len(collected))
	src := make(memByteSource, len(collected))
	for i, e := range collected {
		realBlocks[i] = RealBlockInfo{Cid: e.c, Size: len(e.b)}
		src[e.c] = e.b
	}

	manifest := newRootManifest(root, realBlocks, superBlockSize)
	store := newSuperBlockStore([]*rootManifest{manifest}, src, superBlockSize)

	tags, err := tagger.TagBlocks(store)
	if err != nil {
		return nil, fmt.Errorf("ipfsproof: TagRootChunked: TagBlocks: %w", err)
	}

	return &ChunkedTagList{Root: root, Blocks: realBlocks, Tags: tags, SuperBlockSize: superBlockSize}, nil
}

// NewChunkedChallengedList builds a blocks.BlockStore over one or more
// already-tagged roots' super-blocks, fetching real block bytes lazily (and
// caching per-CID) as specific super-blocks are actually challenged.
func NewChunkedChallengedList(ctx context.Context, getter format.NodeGetter, tagLists []*ChunkedTagList, roots []cid.Cid, superBlockSize int) (blocks.BlockStore, error) {
	index := make(map[cid.Cid]*ChunkedTagList, len(tagLists))
	for _, tl := range tagLists {
		index[tl.Root] = tl
	}

	manifests := make([]*rootManifest, 0, len(roots))
	for _, root := range roots {
		tl, ok := index[root]
		if !ok {
			return nil, fmt.Errorf("ipfsproof: no ChunkedTagList for root %s", root)
		}
		manifests = append(manifests, newRootManifest(root, tl.Blocks, superBlockSize))
	}

	return newSuperBlockStore(manifests, newLazyByteSource(ctx, getter), superBlockSize), nil
}
