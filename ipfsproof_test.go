package ipfsproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/ipfs/boxo/ipld/merkledag"
	mdutils "github.com/ipfs/boxo/ipld/merkledag/test"
	"github.com/ipfs/go-cid"
	format "github.com/ipfs/go-ipld-format"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/line"
)

// mockTagger tags each block with SHA-256 of its raw bytes.
type mockTagger struct{}

func (t *mockTagger) TagBlocks(store blocks.BlockStore) ([]line.Tag, error) {
	tags := make([]line.Tag, store.Len())
	for i := range store.Len() {
		b, err := blocks.BlockAt(store, i)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(b)
		tags[i] = line.Tag(h[:])
	}
	return tags, nil
}

func TestTagRoot_SimpleDAG(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()

	leaf1 := merkledag.NewRawNode([]byte("leaf block 1"))
	leaf2 := merkledag.NewRawNode([]byte("leaf block 2"))
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

	tagList, err := TagRoot(ctx, dag, root.Cid(), &mockTagger{})
	if err != nil {
		t.Fatal(err)
	}

	if tagList.Root != root.Cid() {
		t.Errorf("root: got %s, want %s", tagList.Root, root.Cid())
	}
	if len(tagList.Tags) != 3 {
		t.Fatalf("expected 3 tags, got %d", len(tagList.Tags))
	}

	// Tags must be sorted by CID bytes.
	for i := 1; i < len(tagList.Tags); i++ {
		if bytes.Compare(tagList.Tags[i-1].Cid.Bytes(), tagList.Tags[i].Cid.Bytes()) > 0 {
			t.Errorf("tags not sorted by CID at index %d", i)
		}
	}

	// Each tag must match SHA-256 of the node's RawData.
	nodesByCID := map[cid.Cid]format.Node{
		root.Cid():  root,
		leaf1.Cid(): leaf1,
		leaf2.Cid(): leaf2,
	}
	for _, tb := range tagList.Tags {
		n, ok := nodesByCID[tb.Cid]
		if !ok {
			t.Errorf("unexpected CID in TagList: %s", tb.Cid)
			continue
		}
		h := sha256.Sum256(n.RawData())
		if !bytes.Equal(tb.Tag, h[:]) {
			t.Errorf("tag mismatch for CID %s", tb.Cid)
		}
	}
}

func TestTagRoot_DeduplicatesSharedBlocks(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()

	shared := merkledag.NewRawNode([]byte("shared block"))
	root := merkledag.NodeWithData([]byte("root"))
	if err := root.AddNodeLink("a", shared); err != nil {
		t.Fatal(err)
	}
	if err := root.AddNodeLink("b", shared); err != nil {
		t.Fatal(err)
	}

	for _, n := range []format.Node{shared, root} {
		if err := dag.Add(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	tagList, err := TagRoot(ctx, dag, root.Cid(), &mockTagger{})
	if err != nil {
		t.Fatal(err)
	}
	if len(tagList.Tags) != 2 {
		t.Errorf("expected 2 unique blocks, got %d", len(tagList.Tags))
	}
}

func TestNewChallengedList_SingleRoot(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()

	leaf1 := merkledag.NewRawNode([]byte("block A"))
	leaf2 := merkledag.NewRawNode([]byte("block B"))
	for _, n := range []format.Node{leaf1, leaf2} {
		if err := dag.Add(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	rootCID := merkledag.NewRawNode([]byte("root")).Cid()
	tl := &TagList{
		Root: rootCID,
		Tags: []TagBlock{
			{Tag: line.Tag("tag1"), Cid: leaf1.Cid()},
			{Tag: line.Tag("tag2"), Cid: leaf2.Cid()},
		},
	}

	cl, err := NewChallengedList(ctx, dag, []*TagList{tl}, []cid.Cid{rootCID})
	if err != nil {
		t.Fatal(err)
	}
	if cl.Len() != 2 {
		t.Fatalf("expected 2 blocks, got %d", cl.Len())
	}

	b0, err := blocks.BlockAt(cl, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b0, leaf1.RawData()) {
		t.Errorf("block 0: got %q, want %q", b0, leaf1.RawData())
	}

	b1, err := blocks.BlockAt(cl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, leaf2.RawData()) {
		t.Errorf("block 1: got %q, want %q", b1, leaf2.RawData())
	}
}

func TestNewChallengedList_MultipleRoots(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()

	nodeA := merkledag.NewRawNode([]byte("file A block"))
	nodeB := merkledag.NewRawNode([]byte("file B block"))
	for _, n := range []format.Node{nodeA, nodeB} {
		if err := dag.Add(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	rootACID := merkledag.NewRawNode([]byte("root A")).Cid()
	rootBCID := merkledag.NewRawNode([]byte("root B")).Cid()
	tlA := &TagList{Root: rootACID, Tags: []TagBlock{{Tag: line.Tag("tagA"), Cid: nodeA.Cid()}}}
	tlB := &TagList{Root: rootBCID, Tags: []TagBlock{{Tag: line.Tag("tagB"), Cid: nodeB.Cid()}}}

	cl, err := NewChallengedList(ctx, dag,
		[]*TagList{tlA, tlB},
		[]cid.Cid{rootACID, rootBCID},
	)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Len() != 2 {
		t.Fatalf("expected 2 blocks, got %d", cl.Len())
	}

	b0, _ := blocks.BlockAt(cl, 0)
	b1, _ := blocks.BlockAt(cl, 1)
	if !bytes.Equal(b0, nodeA.RawData()) {
		t.Errorf("block 0 mismatch")
	}
	if !bytes.Equal(b1, nodeB.RawData()) {
		t.Errorf("block 1 mismatch")
	}
}

func TestNewChallengedList_MissingTagList(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()
	rootCID := merkledag.NewRawNode([]byte("root")).Cid()

	_, err := NewChallengedList(ctx, dag, nil, []cid.Cid{rootCID})
	if err == nil {
		t.Error("expected error for missing TagList, got nil")
	}
}

func TestChallengedList_SetBlockIsReadOnly(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()
	cl := &ChallengedList{
		tagBlocks: []TagBlock{{Cid: merkledag.NewRawNode([]byte("x")).Cid()}},
		ctx:       ctx,
		getter:    dag,
	}
	if err := cl.SetBlock([]byte("anyid"), []byte("data")); err == nil {
		t.Error("expected error from SetBlock, got nil")
	}
}

func TestChallengedList_BlockRemovedFromStore(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()

	n := merkledag.NewRawNode([]byte("some data"))
	if err := dag.Add(ctx, n); err != nil {
		t.Fatal(err)
	}

	tl := &TagList{
		Root: n.Cid(),
		Tags: []TagBlock{{Tag: line.Tag("tag"), Cid: n.Cid()}},
	}
	cl, err := NewChallengedList(ctx, dag, []*TagList{tl}, []cid.Cid{n.Cid()})
	if err != nil {
		t.Fatal(err)
	}

	// Block present: should succeed.
	if _, err := blocks.BlockAt(cl, 0); err != nil {
		t.Fatalf("expected block to be available: %v", err)
	}

	// Remove (un-pin) the block.
	if err := dag.Remove(ctx, n.Cid()); err != nil {
		t.Fatal(err)
	}

	// Block gone: should fail.
	if _, err := blocks.BlockAt(cl, 0); err == nil {
		t.Error("expected error after block removal, got nil")
	}
}
