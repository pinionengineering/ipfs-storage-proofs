package ipfsproof_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/ipfs/boxo/ipld/merkledag"
	mdutils "github.com/ipfs/boxo/ipld/merkledag/test"
	"github.com/ipfs/go-cid"
	format "github.com/ipfs/go-ipld-format"
	ipfsproof "github.com/pinionengineering/ipfs-storage-proofs"
	"github.com/pinionengineering/storage-proofs/blocks"
	"github.com/pinionengineering/storage-proofs/capability"
	"github.com/pinionengineering/storage-proofs/line"
)

const testSuperBlockSize = 8

// chunkedBlockSize and chunkedSectorsPerBlock configure SW-Priv/SW-Pub for
// TestChunkedRoundTrip and TestChunkedExtraction — the same value passed to
// both spec.NewTagger and the super-block virtualization layer, matching how
// a real caller must keep the two in agreement.
const (
	chunkedBlockSize       = 1024
	chunkedSectorsPerBlock = 64
)

// stubTagger is a trivial line.Tagger used to test the chunking/manifest
// mechanics in isolation from any real crypto: each tag is just a copy of
// the super-block's own (already zero-padded) bytes.
type stubTagger struct{}

func (stubTagger) TagBlocks(store blocks.BlockStore) ([]line.Tag, error) {
	tags := make([]line.Tag, store.Len())
	for i, id := range store.IDs() {
		b, err := store.Block(id)
		if err != nil {
			return nil, err
		}
		tags[i] = line.Tag(append([]byte(nil), b...))
	}
	return tags, nil
}

// buildTwoBlockDAG builds a 2-block DAG (root -> big, small) sized against
// superBlockSize: big forces a partial last super-block, small forces
// zero-padding of its only super-block.
func buildTwoBlockDAG(t *testing.T, superBlockSize int) (dag format.DAGService, root format.Node, big, small []byte) {
	t.Helper()
	ctx := context.Background()
	dag = mdutils.Mock()

	big = make([]byte, 5*superBlockSize+3)
	for i := range big {
		big[i] = byte(i)
	}
	small = []byte{0xAA, 0xBB, 0xCC}

	bigNode := merkledag.NewRawNode(big)
	smallNode := merkledag.NewRawNode(small)
	rootNode := merkledag.NodeWithData([]byte("root"))
	if err := rootNode.AddNodeLink("big", bigNode); err != nil {
		t.Fatalf("link big: %v", err)
	}
	if err := rootNode.AddNodeLink("small", smallNode); err != nil {
		t.Fatalf("link small: %v", err)
	}
	for _, n := range []format.Node{bigNode, smallNode, rootNode} {
		if err := dag.Add(ctx, n); err != nil {
			t.Fatalf("add node: %v", err)
		}
	}
	return dag, rootNode, big, small
}

// prefixSums mirrors the internal manifest's cumulative super-block counts,
// for locating a real block's tags/super-blocks within the flat arrays.
func prefixSums(blocksInfo []ipfsproof.RealBlockInfo, superBlockSize int) []int {
	prefix := make([]int, len(blocksInfo)+1)
	for i, b := range blocksInfo {
		n := (b.Size + superBlockSize - 1) / superBlockSize
		if n == 0 {
			n = 1
		}
		prefix[i+1] = prefix[i] + n
	}
	return prefix
}

func findBySize(blocksInfo []ipfsproof.RealBlockInfo, size int) int {
	for i, b := range blocksInfo {
		if b.Size == size {
			return i
		}
	}
	return -1
}

func TestTagRootChunked_PartialAndZeroPadding(t *testing.T) {
	ctx := context.Background()
	dag, rootNode, big, small := buildTwoBlockDAG(t, testSuperBlockSize)

	tl, err := ipfsproof.TagRootChunked(ctx, dag, rootNode.Cid(), stubTagger{}, testSuperBlockSize)
	if err != nil {
		t.Fatalf("TagRootChunked: %v", err)
	}

	wantBigSB := (len(big) + testSuperBlockSize - 1) / testSuperBlockSize

	// Total block count includes the DAG root's own node too (a dag-pb node
	// with a link table, not just "big"+"small") — don't hardcode it; sum
	// over the manifest TagRootChunked actually recorded.
	wantTotal := 0
	for _, b := range tl.Blocks {
		n := (b.Size + testSuperBlockSize - 1) / testSuperBlockSize
		if n == 0 {
			n = 1
		}
		wantTotal += n
	}
	if got := tl.BlockCount(); got != wantTotal {
		t.Fatalf("BlockCount=%d, want %d (sum over recorded manifest sizes)", got, wantTotal)
	}
	if len(tl.Tags) != tl.BlockCount() {
		t.Fatalf("len(Tags)=%d, want %d", len(tl.Tags), tl.BlockCount())
	}
	for i, tag := range tl.Tags {
		if len(tag) != testSuperBlockSize {
			t.Fatalf("tag[%d] len=%d, want %d", i, len(tag), testSuperBlockSize)
		}
	}

	bigIdx := findBySize(tl.Blocks, len(big))
	smallIdx := findBySize(tl.Blocks, len(small))
	if bigIdx == -1 || smallIdx == -1 {
		t.Fatalf("expected one %d-byte and one %d-byte block in manifest, got %+v", len(big), len(small), tl.Blocks)
	}

	prefix := prefixSums(tl.Blocks, testSuperBlockSize)

	bigTags := tl.Tags[prefix[bigIdx]:prefix[bigIdx+1]]
	if len(bigTags) != wantBigSB {
		t.Fatalf("big block super-block count=%d, want %d", len(bigTags), wantBigSB)
	}
	for j := 0; j < wantBigSB-1; j++ {
		want := big[j*testSuperBlockSize : (j+1)*testSuperBlockSize]
		if !bytes.Equal([]byte(bigTags[j]), want) {
			t.Fatalf("big super-block %d = %x, want %x", j, []byte(bigTags[j]), want)
		}
	}
	lastStart := (wantBigSB - 1) * testSuperBlockSize
	wantLast := make([]byte, testSuperBlockSize)
	copy(wantLast, big[lastStart:])
	if !bytes.Equal([]byte(bigTags[wantBigSB-1]), wantLast) {
		t.Fatalf("big block's last (partial) super-block = %x, want %x", []byte(bigTags[wantBigSB-1]), wantLast)
	}

	smallTags := tl.Tags[prefix[smallIdx]:prefix[smallIdx+1]]
	if len(smallTags) != 1 {
		t.Fatalf("small block super-block count=%d, want 1", len(smallTags))
	}
	wantSmall := make([]byte, testSuperBlockSize)
	copy(wantSmall, small)
	if !bytes.Equal([]byte(smallTags[0]), wantSmall) {
		t.Fatalf("small block's super-block = %x, want %x", []byte(smallTags[0]), wantSmall)
	}
}

// schemeForTest returns the capability.SchemeSpec for a given scheme name.
func schemeForTest(t *testing.T, name string) capability.SchemeSpec {
	t.Helper()
	for _, s := range capability.Schemes {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("scheme %q not found", name)
	return capability.SchemeSpec{}
}

// TestChunkedRoundTrip drives a full tag -> challenge -> respond -> verify
// cycle through the real SW-Priv/SW-Pub machinery via the super-block layer.
// buildTwoBlockDAG's "big" fixture spans several super-blocks with a partial
// last one; chalSize is set higher than the total super-block count so
// MakeChallenge (which caps its challenge size down to the total when asked
// for more) always covers every super-block, making each round's result
// deterministic instead of a probabilistic sample.
func TestChunkedRoundTrip(t *testing.T) {
	for _, name := range []string{"SW-Priv", "SW-Pub"} {
		name := name
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			spec := schemeForTest(t, name)

			dag, rootNode, big, _ := buildTwoBlockDAG(t, chunkedBlockSize)
			bigSB := (len(big) + chunkedBlockSize - 1) / chunkedBlockSize
			chalSizeMargin := bigSB + 5 // headroom for the small fixture block + the DAG root's own node

			tagger, err := spec.NewTagger(512, chalSizeMargin, chunkedBlockSize, chunkedSectorsPerBlock)
			if err != nil {
				t.Fatalf("NewTagger: %v", err)
			}

			tl, err := ipfsproof.TagRootChunked(ctx, dag, rootNode.Cid(), tagger, chunkedBlockSize)
			if err != nil {
				t.Fatalf("TagRootChunked: %v", err)
			}
			totalSuperBlocks := tl.BlockCount()
			if totalSuperBlocks > chalSizeMargin {
				t.Fatalf("BlockCount=%d exceeds chalSizeMargin=%d — widen the margin", totalSuperBlocks, chalSizeMargin)
			}

			proverSetup, err := tagger.ProverSetup()
			if err != nil {
				t.Fatalf("ProverSetup: %v", err)
			}
			clientSetup, err := tagger.ClientSetup()
			if err != nil {
				t.Fatalf("ClientSetup: %v", err)
			}

			cl, err := ipfsproof.NewChunkedChallengedList(ctx, dag, []*ipfsproof.ChunkedTagList{tl}, []cid.Cid{rootNode.Cid()}, chunkedBlockSize)
			if err != nil {
				t.Fatalf("NewChunkedChallengedList: %v", err)
			}
			if cl.Len() != totalSuperBlocks {
				t.Fatalf("challenged list Len()=%d, want %d", cl.Len(), totalSuperBlocks)
			}

			prover, err := spec.ProvFactory.NewProver(proverSetup, cl)
			if err != nil {
				t.Fatalf("NewProver: %v", err)
			}
			challenger, err := spec.ChalFactory.NewChallenger(clientSetup, totalSuperBlocks)
			if err != nil {
				t.Fatalf("NewChallenger: %v", err)
			}

			ids := cl.IDs()
			for round := 0; round < 5; round++ {
				chal, validator, err := challenger.Challenge(ids)
				if err != nil {
					t.Fatalf("round %d: Challenge: %v", round, err)
				}
				proof, err := prover.Prove(chal, cl)
				if err != nil {
					t.Fatalf("round %d: Prove: %v", round, err)
				}
				ok, err := validator.Verify(chal, proof)
				if err != nil {
					t.Fatalf("round %d: Verify: %v", round, err)
				}
				if !ok {
					t.Fatalf("round %d: verification failed (every round covers all %d super-blocks of the big real block)", round, bigSB)
				}
			}
		})
	}
}

// TestChunkedExtraction drives tag -> witness -> extract through the real
// SW-Priv/SW-Pub extraction machinery and confirms both the big
// (multi-super-block) and small (zero-padded) real blocks are recovered
// byte-for-byte.
func TestChunkedExtraction(t *testing.T) {
	const maxRounds = 200
	for _, name := range []string{"SW-Priv", "SW-Pub"} {
		name := name
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			spec := schemeForTest(t, name)

			dag, rootNode, big, small := buildTwoBlockDAG(t, chunkedBlockSize)
			bigSB := (len(big) + chunkedBlockSize - 1) / chunkedBlockSize
			chalSizeMargin := bigSB + 5 // headroom for the small block + the DAG root's own node

			tagger, err := spec.NewTagger(512, chalSizeMargin, chunkedBlockSize, chunkedSectorsPerBlock)
			if err != nil {
				t.Fatalf("NewTagger: %v", err)
			}
			tl, err := ipfsproof.TagRootChunked(ctx, dag, rootNode.Cid(), tagger, chunkedBlockSize)
			if err != nil {
				t.Fatalf("TagRootChunked: %v", err)
			}
			totalSuperBlocks := tl.BlockCount()
			if totalSuperBlocks > chalSizeMargin {
				t.Fatalf("BlockCount=%d exceeds chalSizeMargin=%d — widen the margin", totalSuperBlocks, chalSizeMargin)
			}

			ep, ok := tagger.(line.ExtractorProducer)
			if !ok {
				t.Fatalf("scheme %q's tagger does not implement ExtractorProducer", name)
			}
			extractor, err := ep.NewExtractor()
			if err != nil {
				t.Fatalf("NewExtractor: %v", err)
			}

			proverSetup, err := tagger.ProverSetup()
			if err != nil {
				t.Fatalf("ProverSetup: %v", err)
			}
			clientSetup, err := tagger.ClientSetup()
			if err != nil {
				t.Fatalf("ClientSetup: %v", err)
			}
			cl, err := ipfsproof.NewChunkedChallengedList(ctx, dag, []*ipfsproof.ChunkedTagList{tl}, []cid.Cid{rootNode.Cid()}, chunkedBlockSize)
			if err != nil {
				t.Fatalf("NewChunkedChallengedList: %v", err)
			}
			prover, err := spec.ProvFactory.NewProver(proverSetup, cl)
			if err != nil {
				t.Fatalf("NewProver: %v", err)
			}
			challenger, err := spec.ChalFactory.NewChallenger(clientSetup, totalSuperBlocks)
			if err != nil {
				t.Fatalf("NewChallenger: %v", err)
			}

			ids := cl.IDs()
			var recovered blocks.BlockStore
			for round := 0; round < maxRounds; round++ {
				chal, validator, err := challenger.Challenge(ids)
				if err != nil {
					t.Fatalf("round %d: Challenge: %v", round, err)
				}
				proof, err := prover.Prove(chal, cl)
				if err != nil {
					t.Fatalf("round %d: Prove: %v", round, err)
				}
				valid, err := validator.Verify(chal, proof)
				if err != nil {
					t.Fatalf("round %d: Verify: %v", round, err)
				}
				if valid {
					if err := extractor.Witness(chal, proof); err != nil {
						t.Fatalf("round %d: Witness: %v", round, err)
					}
				}
				recovered, err = extractor.Extract()
				if err == nil {
					break
				}
				if !errors.Is(err, line.ErrInsufficientProofs) {
					t.Fatalf("round %d: Extract: %v", round, err)
				}
			}
			if recovered == nil {
				t.Fatalf("did not converge within %d rounds", maxRounds)
			}

			prefix := prefixSums(tl.Blocks, chunkedBlockSize)
			bigIdx := findBySize(tl.Blocks, len(big))
			smallIdx := findBySize(tl.Blocks, len(small))
			if bigIdx == -1 || smallIdx == -1 {
				t.Fatalf("expected one %d-byte and one %d-byte block in manifest", len(big), len(small))
			}

			reassemble := func(idx int) ([]byte, error) {
				var out []byte
				for flat := prefix[idx]; flat < prefix[idx+1]; flat++ {
					b, err := blocks.BlockAt(recovered, flat)
					if err != nil {
						return nil, err
					}
					out = append(out, b...)
				}
				return out, nil
			}

			gotBig, err := reassemble(bigIdx)
			if err != nil {
				t.Fatalf("reassemble big: %v", err)
			}
			if !bytes.Equal(gotBig[:len(big)], big) {
				t.Fatalf("recovered big block mismatch")
			}

			gotSmall, err := reassemble(smallIdx)
			if err != nil {
				t.Fatalf("reassemble small: %v", err)
			}
			if !bytes.Equal(gotSmall[:len(small)], small) {
				t.Fatalf("recovered small block mismatch")
			}
		})
	}
}
