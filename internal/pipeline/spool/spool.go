// Package spool implements the on-disk write-ahead log that makes captured
// events durable before they are shipped to ClickHouse.
//
// Records are appended to rotating segment files and consumed in order. A
// checkpoint records how far the consumer has committed, so a restart resumes
// without loss. Append writes to the file immediately; Sync flushes to the
// device, so a process crash loses nothing and a host crash loses at most the
// records appended since the last Sync.
package spool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	headerSize    = 8
	maxRecordSize = 64 << 20
	segSuffix     = ".seg"
	checkpointRel = "checkpoint"
)

// Options tunes a Spool.
type Options struct {
	SegmentBytes int64
	MaxBytes     int64
}

// Cursor identifies a position in the spool.
type Cursor struct {
	Segment uint64
	Offset  int64
}

// Record is one spooled payload and the cursor immediately after it.
type Record struct {
	Data []byte
	Next Cursor
}

// Spool is a durable FIFO of byte payloads.
type Spool struct {
	dir  string
	opts Options

	mu      sync.Mutex
	cur     *os.File
	curID   uint64
	curSize int64
	read    Cursor
	dropped uint64
}

// Open prepares the spool directory, recovering any existing segments and checkpoint.
func Open(dir string, opts Options) (*Spool, error) {
	if opts.SegmentBytes <= 0 {
		opts.SegmentBytes = 64 << 20
	}
	if opts.MaxBytes < opts.SegmentBytes {
		opts.MaxBytes = opts.SegmentBytes
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("spool: create dir: %w", err)
	}
	s := &Spool{dir: dir, opts: opts}

	// Every commit creates a file in this directory. Appending to a segment
	// that already exists does not, so without this check an unwritable
	// directory lets the proxy start and then fail every checkpoint, replaying
	// the whole spool on the next restart.
	if err := writable(dir); err != nil {
		return nil, err
	}

	ids, err := s.segmentIDs()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		if err := s.openSegment(1); err != nil {
			return nil, err
		}
	} else if err := s.openSegment(ids[len(ids)-1]); err != nil {
		return nil, err
	}

	s.read = s.loadCheckpoint()
	if s.read.Segment == 0 {
		if len(ids) > 0 {
			s.read = Cursor{Segment: ids[0]}
		} else {
			s.read = Cursor{Segment: s.curID}
		}
	}
	return s, nil
}

// Append durably queues one payload.
func (s *Spool) Append(data []byte) error {
	if len(data) == 0 {
		return errors.New("spool: empty record")
	}
	if len(data) > maxRecordSize {
		return fmt.Errorf("spool: record of %d bytes exceeds limit %d", len(data), maxRecordSize)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.curSize >= s.opts.SegmentBytes {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	buf := make([]byte, headerSize+len(data))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(data)))
	binary.LittleEndian.PutUint32(buf[4:8], crc32.ChecksumIEEE(data))
	copy(buf[headerSize:], data)

	n, err := s.cur.Write(buf)
	s.curSize += int64(n)
	if err != nil {
		return fmt.Errorf("spool: write: %w", err)
	}
	return s.enforceWatermark()
}

// Sync flushes appended records to the storage device.
func (s *Spool) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	return s.cur.Sync()
}

// Read returns up to max uncommitted records in order.
func (s *Spool) Read(max int) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids, err := s.segmentIDs()
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, max)
	pos := s.read
	for _, id := range ids {
		if id < pos.Segment {
			continue
		}
		off := int64(0)
		if id == pos.Segment {
			off = pos.Offset
		}
		recs, next, err := s.readSegment(id, off, max-len(out))
		if err != nil {
			return out, err
		}
		out = append(out, recs...)
		if len(out) >= max {
			return out, nil
		}
		// Segment exhausted; continue at the start of the next one.
		_ = next
	}
	return out, nil
}

// Commit persists the consumer position and removes fully consumed segments.
func (s *Spool) Commit(c Cursor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.read = c
	if err := s.saveCheckpoint(c); err != nil {
		return err
	}
	ids, err := s.segmentIDs()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if id < c.Segment && id != s.curID {
			_ = os.Remove(s.segPath(id))
		}
	}
	return nil
}

// Dropped reports how many records were discarded to stay under MaxBytes.
func (s *Spool) Dropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Size reports the total bytes currently held on disk.
func (s *Spool) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, _ := s.totalSize()
	return n
}

// Close flushes and releases the current segment.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	err := s.cur.Sync()
	if cerr := s.cur.Close(); err == nil {
		err = cerr
	}
	s.cur = nil
	return err
}

func (s *Spool) readSegment(id uint64, off int64, limit int) ([]Record, Cursor, error) {
	f, err := os.Open(s.segPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, Cursor{Segment: id, Offset: off}, nil
		}
		return nil, Cursor{}, fmt.Errorf("spool: open segment %d: %w", id, err)
	}
	defer f.Close()

	if _, err := f.Seek(off, 0); err != nil {
		return nil, Cursor{}, fmt.Errorf("spool: seek segment %d: %w", id, err)
	}
	out := make([]Record, 0, limit)
	hdr := make([]byte, headerSize)
	for len(out) < limit {
		if _, err := readFull(f, hdr); err != nil {
			break
		}
		size := binary.LittleEndian.Uint32(hdr[0:4])
		sum := binary.LittleEndian.Uint32(hdr[4:8])
		if size == 0 || size > maxRecordSize {
			break
		}
		data := make([]byte, size)
		if _, err := readFull(f, data); err != nil {
			break
		}
		if crc32.ChecksumIEEE(data) != sum {
			break
		}
		off += headerSize + int64(size)
		out = append(out, Record{Data: data, Next: Cursor{Segment: id, Offset: off}})
	}
	return out, Cursor{Segment: id, Offset: off}, nil
}

func (s *Spool) rotate() error {
	if s.cur != nil {
		if err := s.cur.Sync(); err != nil {
			return fmt.Errorf("spool: sync on rotate: %w", err)
		}
		if err := s.cur.Close(); err != nil {
			return fmt.Errorf("spool: close on rotate: %w", err)
		}
	}
	return s.openSegment(s.curID + 1)
}

func (s *Spool) openSegment(id uint64) error {
	f, err := os.OpenFile(s.segPath(id), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("spool: open segment %d: %w", id, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("spool: stat segment %d: %w", id, err)
	}
	s.cur, s.curID, s.curSize = f, id, info.Size()
	return nil
}

func (s *Spool) enforceWatermark() error {
	total, err := s.totalSize()
	if err != nil {
		return err
	}
	if total <= s.opts.MaxBytes {
		return nil
	}
	ids, err := s.segmentIDs()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if total <= s.opts.MaxBytes {
			break
		}
		if id == s.curID {
			break
		}
		info, err := os.Stat(s.segPath(id))
		if err != nil {
			continue
		}
		if err := os.Remove(s.segPath(id)); err != nil {
			continue
		}
		total -= info.Size()
		s.dropped += uint64(info.Size())
		if s.read.Segment <= id {
			s.read = Cursor{Segment: id + 1}
			_ = s.saveCheckpoint(s.read)
		}
	}
	return nil
}

func (s *Spool) totalSize() (int64, error) {
	ids, err := s.segmentIDs()
	if err != nil {
		return 0, err
	}
	var total int64
	for _, id := range ids {
		info, err := os.Stat(s.segPath(id))
		if err != nil {
			continue
		}
		total += info.Size()
	}
	return total, nil
}

func (s *Spool) segmentIDs() ([]uint64, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("spool: read dir: %w", err)
	}
	ids := make([]uint64, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, segSuffix) {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(name, segSuffix), 10, 64)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func (s *Spool) segPath(id uint64) string {
	return filepath.Join(s.dir, fmt.Sprintf("%020d%s", id, segSuffix))
}

// writable reports whether the spool can create files in dir, which is what
// saving a checkpoint needs.
func writable(dir string) error {
	probe := filepath.Join(dir, checkpointRel+".probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("spool: directory is not writable: %w", err)
	}
	f.Close()
	return os.Remove(probe)
}

func (s *Spool) saveCheckpoint(c Cursor) error {
	path := filepath.Join(s.dir, checkpointRel)
	tmp := path + ".tmp"
	line := fmt.Sprintf("%d %d\n", c.Segment, c.Offset)
	if err := os.WriteFile(tmp, []byte(line), 0o640); err != nil {
		return fmt.Errorf("spool: write checkpoint: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("spool: commit checkpoint: %w", err)
	}
	return nil
}

func (s *Spool) loadCheckpoint() Cursor {
	b, err := os.ReadFile(filepath.Join(s.dir, checkpointRel))
	if err != nil {
		return Cursor{}
	}
	var c Cursor
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d %d", &c.Segment, &c.Offset); err != nil {
		return Cursor{}
	}
	return c
}

func readFull(f *os.File, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := f.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
