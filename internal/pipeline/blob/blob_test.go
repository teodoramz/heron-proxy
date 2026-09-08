package blob

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPutReturnsSHA256Key(t *testing.T) {
	s := New(t.TempDir())
	key, err := s.Put([]byte("hello"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if key != want {
		t.Errorf("key = %s, want %s", key, want)
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	s := New(t.TempDir())
	data := bytes.Repeat([]byte("payload"), 1000)
	key, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("round-trip mismatch")
	}
}

func TestPutDeduplicates(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	k1, _ := s.Put([]byte("same"))
	k2, _ := s.Put([]byte("same"))
	if k1 != k2 {
		t.Fatalf("keys differ: %s vs %s", k1, k2)
	}
	var files int
	filepath.Walk(dir, func(_ string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() {
			files++
		}
		return nil
	})
	if files != 1 {
		t.Errorf("stored %d files, want 1", files)
	}
}

func TestGetMissingKey(t *testing.T) {
	s := New(t.TempDir())
	_, err := s.Get(Key([]byte("absent")))
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestRejectsInvalidKey(t *testing.T) {
	s := New(t.TempDir())
	for _, k := range []string{"", "short", "../../../etc/passwd", "zz24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824x"} {
		if _, err := s.Get(k); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) = %v, want a validation error", k, err)
		}
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	s := New(t.TempDir())
	key, _ := s.Put([]byte("x"))
	if err := s.Delete(key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(key); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
}
