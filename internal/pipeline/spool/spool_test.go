package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func open(t *testing.T, dir string, opts Options) *Spool {
	t.Helper()
	s, err := Open(dir, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAppendReadRoundTrip(t *testing.T) {
	s := open(t, t.TempDir(), Options{SegmentBytes: 1 << 20, MaxBytes: 1 << 20})
	for i := range 3 {
		if err := s.Append([]byte(fmt.Sprintf("record-%d", i))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	recs, err := s.Read(10)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	if string(recs[2].Data) != "record-2" {
		t.Errorf("recs[2] = %q", recs[2].Data)
	}
}

func TestReadRespectsLimit(t *testing.T) {
	s := open(t, t.TempDir(), Options{SegmentBytes: 1 << 20, MaxBytes: 1 << 20})
	for i := range 5 {
		s.Append([]byte(fmt.Sprintf("r%d", i)))
	}
	recs, _ := s.Read(2)
	if len(recs) != 2 {
		t.Fatalf("got %d, want 2", len(recs))
	}
}

func TestCommitAdvancesAndSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	opts := Options{SegmentBytes: 1 << 20, MaxBytes: 1 << 20}
	s := open(t, dir, opts)
	for i := range 4 {
		s.Append([]byte(fmt.Sprintf("r%d", i)))
	}
	recs, _ := s.Read(2)
	if err := s.Commit(recs[1].Next); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s.Close()

	s2 := open(t, dir, opts)
	rest, err := s2.Read(10)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(rest) != 2 {
		t.Fatalf("got %d records after reopen, want 2", len(rest))
	}
	if string(rest[0].Data) != "r2" {
		t.Errorf("rest[0] = %q, want r2", rest[0].Data)
	}
}

func TestUncommittedRecordsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	opts := Options{SegmentBytes: 1 << 20, MaxBytes: 1 << 20}
	s := open(t, dir, opts)
	for i := range 100 {
		s.Append([]byte(fmt.Sprintf("payload-%03d", i)))
	}
	s.Sync()
	s.Close()

	s2 := open(t, dir, opts)
	recs, _ := s2.Read(1000)
	if len(recs) != 100 {
		t.Fatalf("got %d records, want 100 (nothing may be lost)", len(recs))
	}
}

func TestSegmentRotationAndCrossSegmentRead(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{SegmentBytes: 64, MaxBytes: 1 << 20})
	for i := range 20 {
		if err := s.Append([]byte(fmt.Sprintf("record-number-%02d", i))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	ids, _ := s.segmentIDs()
	if len(ids) < 2 {
		t.Fatalf("expected rotation, got %d segment(s)", len(ids))
	}
	recs, _ := s.Read(100)
	if len(recs) != 20 {
		t.Fatalf("read %d records across segments, want 20", len(recs))
	}
	if string(recs[19].Data) != "record-number-19" {
		t.Errorf("last = %q", recs[19].Data)
	}
}

func TestCommitRemovesConsumedSegments(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{SegmentBytes: 64, MaxBytes: 1 << 20})
	for i := range 20 {
		s.Append([]byte(fmt.Sprintf("record-number-%02d", i)))
	}
	before, _ := s.segmentIDs()
	recs, _ := s.Read(100)
	s.Commit(recs[len(recs)-1].Next)
	after, _ := s.segmentIDs()
	if len(after) >= len(before) {
		t.Errorf("segments not reclaimed: before %d, after %d", len(before), len(after))
	}
}

func TestCorruptTailIsIgnored(t *testing.T) {
	dir := t.TempDir()
	opts := Options{SegmentBytes: 1 << 20, MaxBytes: 1 << 20}
	s := open(t, dir, opts)
	s.Append([]byte("good-record"))
	s.Sync()
	s.Close()

	path := filepath.Join(dir, fmt.Sprintf("%020d.seg", 1))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{0xff, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02})
	f.Close()

	s2 := open(t, dir, opts)
	recs, err := s2.Read(10)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(recs) != 1 || string(recs[0].Data) != "good-record" {
		t.Fatalf("got %d records %v, want the single valid record", len(recs), recs)
	}
}

func TestCorruptChecksumStopsRead(t *testing.T) {
	dir := t.TempDir()
	opts := Options{SegmentBytes: 1 << 20, MaxBytes: 1 << 20}
	s := open(t, dir, opts)
	s.Append([]byte("aaaa"))
	s.Append([]byte("bbbb"))
	s.Sync()
	s.Close()

	path := filepath.Join(dir, fmt.Sprintf("%020d.seg", 1))
	b, _ := os.ReadFile(path)
	b[headerSize] ^= 0xff // corrupt the first record's payload
	os.WriteFile(path, b, 0o640)

	s2 := open(t, dir, opts)
	recs, _ := s2.Read(10)
	if len(recs) != 0 {
		t.Fatalf("got %d records, want 0 after checksum failure", len(recs))
	}
}

func TestWatermarkDropsOldestSegments(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Options{SegmentBytes: 64, MaxBytes: 256})
	for i := range 100 {
		if err := s.Append([]byte(fmt.Sprintf("record-number-%03d", i))); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if s.Size() > 256+64 {
		t.Errorf("size %d exceeds watermark plus one segment", s.Size())
	}
	if s.Dropped() == 0 {
		t.Error("expected a non-zero dropped counter")
	}
}

func TestAppendRejectsEmpty(t *testing.T) {
	s := open(t, t.TempDir(), Options{SegmentBytes: 1 << 10, MaxBytes: 1 << 10})
	if err := s.Append(nil); err == nil {
		t.Error("expected an error for an empty record")
	}
}

func TestOpenRejectsUnwritableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	// A segment already there, so opening it for append succeeds and only the
	// checkpoint would fail.
	s := open(t, dir, Options{SegmentBytes: 1 << 10, MaxBytes: 1 << 10})
	if err := s.Append([]byte("one")); err != nil {
		t.Fatalf("append: %v", err)
	}
	s.Close()

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o750) })

	if _, err := Open(dir, Options{}); err == nil {
		t.Error("expected Open to refuse a directory it cannot write to")
	}
}

func TestOpenDefaultsInvalidOptions(t *testing.T) {
	s := open(t, t.TempDir(), Options{})
	if s.opts.SegmentBytes <= 0 || s.opts.MaxBytes < s.opts.SegmentBytes {
		t.Errorf("options not defaulted: %+v", s.opts)
	}
}
