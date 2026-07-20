package ipfsproof

import (
	"bytes"
	"context"
	"testing"

	"github.com/ipfs/boxo/ipld/merkledag"
	mdutils "github.com/ipfs/boxo/ipld/merkledag/test"
	format "github.com/ipfs/go-ipld-format"
	"github.com/pinionengineering/storage-proofs/blocks"
)

func TestWalkDAGManifest_MatchesTagRootOrderAndSizes(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()

	leaf1 := merkledag.NewRawNode([]byte("leaf block 1"))
	leaf2 := merkledag.NewRawNode([]byte("leaf block 2 is longer"))
	root := merkledag.NodeWithData([]byte("root block"))
	if err := root.AddNodeLink("leaf1", leaf1); err != nil {
		t.Fatal(err)
	}
	if err := root.AddNodeLink("leaf2", leaf2); err != nil {
		t.Fatal(err)
	}
	for _, n := range []format.Node{leaf1, leaf2, root} {
		if err := dag.Add(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	manifest, err := WalkDAGManifest(ctx, dag, root.Cid())
	if err != nil {
		t.Fatal(err)
	}

	tagList, err := TagRoot(ctx, dag, root.Cid(), &mockTagger{})
	if err != nil {
		t.Fatal(err)
	}

	if len(manifest) != len(tagList.Tags) {
		t.Fatalf("manifest length %d != TagRoot block count %d", len(manifest), len(tagList.Tags))
	}
	nodesByCID := map[string]format.Node{
		root.Cid().String():  root,
		leaf1.Cid().String(): leaf1,
		leaf2.Cid().String(): leaf2,
	}
	for i, tb := range tagList.Tags {
		if manifest[i].Cid != tb.Cid {
			t.Errorf("index %d: manifest CID %s != TagRoot CID %s", i, manifest[i].Cid, tb.Cid)
		}
		want := len(nodesByCID[tb.Cid.String()].RawData())
		if manifest[i].Size != want {
			t.Errorf("index %d: manifest size %d != actual size %d", i, manifest[i].Size, want)
		}
	}
}

func TestNewPartitionStore_MatchesTagRootWhenConcatenated(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()

	var leaves []format.Node
	root := merkledag.NodeWithData([]byte("root block"))
	for i := 0; i < 6; i++ {
		leaf := merkledag.NewRawNode([]byte{byte('a' + i), byte('a' + i), byte('a' + i)})
		leaves = append(leaves, leaf)
		if err := root.AddNodeLink(string(rune('a'+i)), leaf); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range append(leaves, root) {
		if err := dag.Add(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	whole, err := TagRoot(ctx, dag, root.Cid(), &mockTagger{})
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := WalkDAGManifest(ctx, dag, root.Cid())
	if err != nil {
		t.Fatal(err)
	}

	// Partition into three ranges and tag each independently, exactly as a
	// partition worker would.
	n := len(manifest)
	bounds := []int{0, n / 3, 2 * n / 3, n}
	var gotTags [][]byte
	for p := 0; p < 3; p++ {
		start, end := bounds[p], bounds[p+1]
		store := NewPartitionStore(ctx, dag, manifest, start, end)
		tags, err := (&mockTagger{}).TagBlocks(store)
		if err != nil {
			t.Fatalf("partition [%d,%d): TagBlocks: %v", start, end, err)
		}
		for _, tag := range tags {
			gotTags = append(gotTags, tag)
		}
	}

	if len(gotTags) != len(whole.Tags) {
		t.Fatalf("partitioned tag count %d != whole tag count %d", len(gotTags), len(whole.Tags))
	}
	for i, tb := range whole.Tags {
		if !bytes.Equal(gotTags[i], tb.Tag) {
			t.Errorf("index %d: partitioned tag != whole-root tag", i)
		}
	}
}

func TestNewChunkedPartitionStore_MatchesTagRootChunkedWhenConcatenated(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()

	const superBlockSize = 4
	leaf1 := merkledag.NewRawNode([]byte("0123456789")) // 10 bytes -> 3 super-blocks (4,4,2)
	leaf2 := merkledag.NewRawNode([]byte("abcdefg"))     // 7 bytes -> 2 super-blocks (4,3)
	root := merkledag.NodeWithData([]byte("root"))
	if err := root.AddNodeLink("a", leaf1); err != nil {
		t.Fatal(err)
	}
	if err := root.AddNodeLink("b", leaf2); err != nil {
		t.Fatal(err)
	}
	for _, node := range []format.Node{leaf1, leaf2, root} {
		if err := dag.Add(ctx, node); err != nil {
			t.Fatal(err)
		}
	}

	whole, err := TagRootChunked(ctx, dag, root.Cid(), &mockTagger{}, superBlockSize)
	if err != nil {
		t.Fatal(err)
	}
	total := whole.BlockCount()
	if total < 2 {
		t.Fatalf("expected at least 2 super-blocks to make partitioning meaningful, got %d", total)
	}

	manifest, err := WalkDAGManifest(ctx, dag, root.Cid())
	if err != nil {
		t.Fatal(err)
	}

	// Split the virtual super-block index space roughly in half — this
	// partition boundary is very likely to fall in the middle of leaf1 or
	// leaf2's super-blocks, not on a real-block boundary, which is exactly
	// the case this store type exists to handle.
	mid := total / 2
	store1 := NewChunkedPartitionStore(ctx, dag, root.Cid(), manifest, superBlockSize, 0, 0, mid)
	store2 := NewChunkedPartitionStore(ctx, dag, root.Cid(), manifest, superBlockSize, 0, mid, total)

	tags1, err := (&mockTagger{}).TagBlocks(store1)
	if err != nil {
		t.Fatalf("partition [0,%d): TagBlocks: %v", mid, err)
	}
	tags2, err := (&mockTagger{}).TagBlocks(store2)
	if err != nil {
		t.Fatalf("partition [%d,%d): TagBlocks: %v", mid, total, err)
	}

	got := append(tags1, tags2...)
	if len(got) != len(whole.Tags) {
		t.Fatalf("partitioned tag count %d != whole tag count %d", len(got), len(whole.Tags))
	}
	for i, tag := range whole.Tags {
		if !bytes.Equal(got[i], tag) {
			t.Errorf("super-block index %d: partitioned tag != whole-root tag", i)
		}
	}
}

func TestRangeStore_SetBlockIsReadOnly(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()
	store := NewPartitionStore(ctx, dag, nil, 0, 0)
	if err := store.SetBlock([]byte("id"), []byte("data")); err == nil {
		t.Error("expected error from SetBlock, got nil")
	}
	if err := blocks.BlockStore(store).SetBlock([]byte("id"), []byte("data")); err == nil {
		t.Error("expected error from SetBlock via interface, got nil")
	}
}
