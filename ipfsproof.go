// Package ipfsproof adapts the storage-proofs line API for use with IPFS.
// It provides two operations that bridge IPFS's content-addressed DAG to the
// index-based blocks.BlockStore interface that storage-proof protocols require.
package ipfsproof

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/ipfs/go-cid"
	format "github.com/ipfs/go-ipld-format"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
)

// CIDBlockStore extends blocks.BlockStore with access to the CID for each block.
// TagRoot always passes a CIDBlockStore to line.Tagger implementations.
// Taggers that want per-block unique identifiers (e.g. for cross-collection
// challenges) should type-assert the store argument of TagBlocks to this interface.
type CIDBlockStore interface {
	blocks.BlockStore
	CIDs() []cid.Cid
}

// cidStore is the unexported CIDBlockStore passed by TagRoot to taggers.
// Block IDs are CID.Bytes(); the index maps them back to positions.
type cidStore struct {
	rawBlocks [][]byte
	cids      []cid.Cid
	index     map[string]int // CID.Bytes() → position
}

func (s *cidStore) Len() int { return len(s.cids) }

func (s *cidStore) CIDs() []cid.Cid { return s.cids }

func (s *cidStore) IDs() [][]byte {
	ids := make([][]byte, len(s.cids))
	for i, c := range s.cids {
		ids[i] = c.Bytes()
	}
	return ids
}

func (s *cidStore) Block(id []byte) ([]byte, error) {
	pos, ok := s.index[string(id)]
	if !ok {
		return nil, fmt.Errorf("ipfsproof: cidStore: block not found for id")
	}
	return s.rawBlocks[pos], nil
}

func (s *cidStore) SetBlock(_ []byte, _ []byte) error {
	return fmt.Errorf("ipfsproof: cidStore is read-only")
}

// Compile-time interface checks.
var (
	_ blocks.BlockStore = (*ChallengedList)(nil)
	_ CIDBlockStore     = (*cidStore)(nil)
)

// TagBlock pairs a storage-proof tag with the IPFS CID of the block it authenticates.
type TagBlock struct {
	Tag line.Tag
	Cid cid.Cid
}

// TagList holds all TagBlocks for a single IPFS DAG, ordered by CID,
// and records the root CID of that DAG.
type TagList struct {
	Tags []TagBlock
	Root cid.Cid
}

// ChallengedList implements blocks.BlockStore for a proof challenge.
// Block(id) fetches live bytes from the IPFS node via the CID encoded in id.
// SetBlock always returns an error; this store is read-only.
type ChallengedList struct {
	tagBlocks []TagBlock
	index     map[string]int // CID.Bytes() → position in tagBlocks
	ctx       context.Context
	getter    format.NodeGetter
}

func (cl *ChallengedList) Len() int { return len(cl.tagBlocks) }

func (cl *ChallengedList) IDs() [][]byte {
	ids := make([][]byte, len(cl.tagBlocks))
	for i, tb := range cl.tagBlocks {
		ids[i] = tb.Cid.Bytes()
	}
	return ids
}

func (cl *ChallengedList) Block(id []byte) ([]byte, error) {
	pos, ok := cl.index[string(id)]
	if !ok {
		return nil, fmt.Errorf("ipfsproof: ChallengedList: block not found for id")
	}
	node, err := cl.getter.Get(cl.ctx, cl.tagBlocks[pos].Cid)
	if err != nil {
		return nil, fmt.Errorf("ipfsproof: fetch %s: %w", cl.tagBlocks[pos].Cid, err)
	}
	return node.RawData(), nil
}

func (cl *ChallengedList) SetBlock(_ []byte, _ []byte) error {
	return fmt.Errorf("ipfsproof: ChallengedList is read-only")
}

// TagRoot walks the IPFS DAG rooted at root, tags all reachable blocks using
// tagger, and returns a TagList with blocks ordered by CID bytes.
// getter is typically the Dag() service of a kubo RPC or in-process API client.
func TagRoot(ctx context.Context, getter format.NodeGetter, root cid.Cid, tagger line.Tagger) (*TagList, error) {
	type entry struct {
		c cid.Cid
		b []byte
	}

	seen := make(map[cid.Cid]bool)
	var collected []entry

	var walk func(c cid.Cid) error
	walk = func(c cid.Cid) error {
		if seen[c] {
			return nil
		}
		seen[c] = true

		node, err := getter.Get(ctx, c)
		if err != nil {
			return fmt.Errorf("ipfsproof: get %s: %w", c, err)
		}
		collected = append(collected, entry{c: c, b: node.RawData()})

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

	rawBlocks := make([][]byte, len(collected))
	sortedCIDs := make([]cid.Cid, len(collected))
	cidIndex := make(map[string]int, len(collected))
	for i, e := range collected {
		rawBlocks[i] = e.b
		sortedCIDs[i] = e.c
		cidIndex[string(e.c.Bytes())] = i
	}

	store := &cidStore{rawBlocks: rawBlocks, cids: sortedCIDs, index: cidIndex}
	tags, err := tagger.TagBlocks(store)
	if err != nil {
		return nil, fmt.Errorf("ipfsproof: TagBlocks: %w", err)
	}

	tagBlocks := make([]TagBlock, len(collected))
	for i, e := range collected {
		tagBlocks[i] = TagBlock{Tag: tags[i], Cid: e.c}
	}

	return &TagList{Tags: tagBlocks, Root: root}, nil
}

// NewChallengedList builds a blocks.BlockStore from the stored TagLists for
// the given root CIDs, concatenated in the order of roots.
func NewChallengedList(ctx context.Context, getter format.NodeGetter, tagLists []*TagList, roots []cid.Cid) (*ChallengedList, error) {
	index := make(map[cid.Cid]*TagList, len(tagLists))
	for _, tl := range tagLists {
		index[tl.Root] = tl
	}

	var tagBlocks []TagBlock
	for _, root := range roots {
		tl, ok := index[root]
		if !ok {
			return nil, fmt.Errorf("ipfsproof: no TagList for root %s", root)
		}
		tagBlocks = append(tagBlocks, tl.Tags...)
	}

	cidIdx := make(map[string]int, len(tagBlocks))
	for i, tb := range tagBlocks {
		cidIdx[string(tb.Cid.Bytes())] = i
	}

	return &ChallengedList{tagBlocks: tagBlocks, index: cidIdx, ctx: ctx, getter: getter}, nil
}
