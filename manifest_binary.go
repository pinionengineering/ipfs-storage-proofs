package ipfsproof

import (
	"encoding/binary"
	"fmt"

	"github.com/ipfs/go-cid"
)

// maxCIDBytes is the largest CID byte length EncodeManifest will store.
// Comfortably covers any CID this codebase actually produces (CIDv0/v1 with
// sha2-256, sha512, blake2b-256, etc. all fit well under this), while
// staying fixed so every record is the same size.
const maxCIDBytes = 64

// ManifestRecordSize is the fixed on-disk size of one binary-encoded
// RealBlockInfo record: 1 length-prefix byte + maxCIDBytes of CID bytes
// (zero-padded) + 8 bytes for Size (big-endian uint64). Fixed width means
// entry i always lives at byte offset i*ManifestRecordSize, so a caller who
// only needs entries [start,end) can fetch exactly that byte range with a
// single ranged blob read — see gocloud.dev/blob's Bucket.NewRangeReader —
// instead of downloading and parsing the whole manifest, which for a large
// file can be tens to hundreds of megabytes even though a single tag
// partition only ever needs a small slice of it.
const ManifestRecordSize = 1 + maxCIDBytes + 8

// EncodeManifest serializes manifest into the fixed-width binary format
// ManifestRecordSize/DecodeManifest describe.
func EncodeManifest(manifest []RealBlockInfo) ([]byte, error) {
	out := make([]byte, len(manifest)*ManifestRecordSize)
	for i, b := range manifest {
		cb := b.Cid.Bytes()
		if len(cb) > maxCIDBytes {
			return nil, fmt.Errorf("ipfsproof: EncodeManifest: cid %s is %d bytes, exceeds max %d", b.Cid, len(cb), maxCIDBytes)
		}
		rec := out[i*ManifestRecordSize : (i+1)*ManifestRecordSize]
		rec[0] = byte(len(cb))
		copy(rec[1:1+maxCIDBytes], cb)
		binary.BigEndian.PutUint64(rec[1+maxCIDBytes:], uint64(b.Size))
	}
	return out, nil
}

// DecodeManifest deserializes data produced by EncodeManifest — the whole
// thing, or any contiguous byte range that starts and ends on a record
// boundary (i.e. offset and length are both multiples of ManifestRecordSize),
// such as one fetched via Bucket.NewRangeReader.
func DecodeManifest(data []byte) ([]RealBlockInfo, error) {
	if len(data)%ManifestRecordSize != 0 {
		return nil, fmt.Errorf("ipfsproof: DecodeManifest: length %d is not a multiple of record size %d", len(data), ManifestRecordSize)
	}
	n := len(data) / ManifestRecordSize
	manifest := make([]RealBlockInfo, n)
	for i := 0; i < n; i++ {
		rec := data[i*ManifestRecordSize : (i+1)*ManifestRecordSize]
		cidLen := int(rec[0])
		if cidLen > maxCIDBytes {
			return nil, fmt.Errorf("ipfsproof: DecodeManifest: record %d has invalid cid length %d", i, cidLen)
		}
		_, c, err := cid.CidFromBytes(rec[1 : 1+cidLen])
		if err != nil {
			return nil, fmt.Errorf("ipfsproof: DecodeManifest: record %d: %w", i, err)
		}
		size := binary.BigEndian.Uint64(rec[1+maxCIDBytes:])
		manifest[i] = RealBlockInfo{Cid: c, Size: int(size)}
	}
	return manifest, nil
}
