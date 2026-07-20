package ipfsproof

import (
	"bytes"
	"context"
	"testing"

	"github.com/ipfs/boxo/ipld/merkledag"
	mdutils "github.com/ipfs/boxo/ipld/merkledag/test"
	"github.com/ipfs/go-cid"
	format "github.com/ipfs/go-ipld-format"
	"github.com/pinionengineering/storage-proofs/line"
)

func TestEncodeDecodeManifest_RoundTrip(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()

	var leaves []format.Node
	root := merkledag.NodeWithData([]byte("root block"))
	for i := 0; i < 6; i++ {
		leaf := merkledag.NewRawNode(bytes.Repeat([]byte{byte('a' + i)}, i+1))
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

	manifest, err := WalkDAGManifest(ctx, dag, root.Cid())
	if err != nil {
		t.Fatal(err)
	}

	data, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != len(manifest)*ManifestRecordSize {
		t.Fatalf("encoded length %d != %d records * %d bytes", len(data), len(manifest), ManifestRecordSize)
	}

	got, err := DecodeManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(manifest) {
		t.Fatalf("decoded %d entries, want %d", len(got), len(manifest))
	}
	for i := range manifest {
		if !got[i].Cid.Equals(manifest[i].Cid) || got[i].Size != manifest[i].Size {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], manifest[i])
		}
	}
}

func TestDecodeManifest_RangeSliceMatchesSubslice(t *testing.T) {
	ctx := context.Background()
	dag := mdutils.Mock()

	var leaves []format.Node
	root := merkledag.NodeWithData([]byte("root block"))
	for i := 0; i < 8; i++ {
		leaf := merkledag.NewRawNode(bytes.Repeat([]byte{byte('a' + i)}, i+1))
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

	manifest, err := WalkDAGManifest(ctx, dag, root.Cid())
	if err != nil {
		t.Fatal(err)
	}

	data, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a ranged blob read: fetch only entries [2,5) by byte offset,
	// exactly what Bucket.NewRangeReader would be asked for.
	start, end := 2, 5
	slice := data[start*ManifestRecordSize : end*ManifestRecordSize]

	got, err := DecodeManifest(slice)
	if err != nil {
		t.Fatal(err)
	}
	want := manifest[start:end]
	if len(got) != len(want) {
		t.Fatalf("range-decoded %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if !got[i].Cid.Equals(want[i].Cid) || got[i].Size != want[i].Size {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestDecodeManifest_RejectsMisalignedLength(t *testing.T) {
	if _, err := DecodeManifest(make([]byte, ManifestRecordSize+1)); err == nil {
		t.Error("expected error for length not a multiple of ManifestRecordSize, got nil")
	}
}

func TestEncodeManifest_RejectsOversizedCID(t *testing.T) {
	oversized := cid.NewCidV1(cid.Raw, bytes.Repeat([]byte{0xAA}, maxCIDBytes+1))
	_, err := EncodeManifest([]RealBlockInfo{{Cid: oversized, Size: 1}})
	if err == nil {
		t.Error("expected error for CID exceeding maxCIDBytes, got nil")
	}
}

// TestResolveSuperBlockRange_MatchesFullManifestResolution is the critical
// regression test for the memory-reduction path: it proves that fetching
// only manifest[realBlockStart:realBlockEnd] (as a partition worker would,
// via a ranged blob read) and translating global super-block indices to
// ones local to that slice produces byte-identical tags to using the whole
// manifest with global indices — even when a partition boundary falls in
// the middle of a real block, which is exactly the case super-block
// virtualization exists to handle.
func TestResolveSuperBlockRange_MatchesFullManifestResolution(t *testing.T) {
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
	encoded, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}

	// Same mid-real-block split as the whole-manifest partition test.
	mid := total / 2
	bounds := [][2]int{{0, mid}, {mid, total}}

	var got []line.Tag
	for _, b := range bounds {
		start, end := b[0], b[1]
		realStart, realEnd, offset, err := ResolveSuperBlockRange(manifest, superBlockSize, start, end)
		if err != nil {
			t.Fatalf("ResolveSuperBlockRange([%d,%d)): %v", start, end, err)
		}

		// Fetch only this partition's real-block slice — the ranged-read
		// simulation. start/end stay global; offset tells the store where
		// this slice actually starts in the whole file's super-block index
		// space, so ids it generates carry the correct global index.
		slice := encoded[realStart*ManifestRecordSize : realEnd*ManifestRecordSize]
		localManifest, err := DecodeManifest(slice)
		if err != nil {
			t.Fatal(err)
		}

		store := NewChunkedPartitionStore(ctx, dag, root.Cid(), localManifest, superBlockSize, offset, start, end)
		tags, err := (&mockTagger{}).TagBlocks(store)
		if err != nil {
			t.Fatalf("partition [%d,%d) (offset %d, real blocks [%d,%d)): TagBlocks: %v",
				start, end, offset, realStart, realEnd, err)
		}
		got = append(got, tags...)
	}

	if len(got) != len(whole.Tags) {
		t.Fatalf("partitioned tag count %d != whole tag count %d", len(got), len(whole.Tags))
	}
	for i, tag := range whole.Tags {
		if !bytes.Equal(got[i], tag) {
			t.Errorf("super-block index %d: range-read partitioned tag != whole-root tag", i)
		}
	}
}

func TestResolveSuperBlockRange_RejectsOutOfRange(t *testing.T) {
	manifest := []RealBlockInfo{{Cid: cid.Undef, Size: 4}}
	if _, _, _, err := ResolveSuperBlockRange(manifest, 4, 0, 0); err == nil {
		t.Error("expected error for empty range, got nil")
	}
	if _, _, _, err := ResolveSuperBlockRange(manifest, 4, -1, 1); err == nil {
		t.Error("expected error for negative start, got nil")
	}
	if _, _, _, err := ResolveSuperBlockRange(manifest, 4, 0, 2); err == nil {
		t.Error("expected error for end beyond total super-blocks, got nil")
	}
}
