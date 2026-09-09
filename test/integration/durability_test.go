package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/amzteodor/proxy-waf/internal/pipeline/event"
	"github.com/amzteodor/proxy-waf/internal/pipeline/spool"
)

const (
	childEnv     = "PROXYWAF_SPOOL_CHILD"
	childRecords = 2000
)

// TestMain lets this binary re-exec itself as the child process that gets killed.
func TestMain(m *testing.M) {
	if dir := os.Getenv(childEnv); dir != "" {
		runChild(dir)
		return
	}
	os.Exit(m.Run())
}

// runChild appends records, syncs, signals readiness, then waits to be killed.
func runChild(dir string) {
	sp, err := spool.Open(dir, spool.Options{SegmentBytes: 64 << 10, MaxBytes: 16 << 20})
	if err != nil {
		fmt.Fprintln(os.Stderr, "child spool.Open:", err)
		os.Exit(1)
	}
	for i := range childRecords {
		data, err := json.Marshal(event.Event{ID: fmt.Sprintf("evt-%04d", i), Path: "/kill-test"})
		if err != nil {
			os.Exit(1)
		}
		if err := sp.Append(data); err != nil {
			fmt.Fprintln(os.Stderr, "child append:", err)
			os.Exit(1)
		}
	}
	if err := sp.Sync(); err != nil {
		fmt.Fprintln(os.Stderr, "child sync:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("ok"), 0o644); err != nil {
		os.Exit(1)
	}
	select {} // wait to be killed
}

// TestSpoolSurvivesSIGKILL is the durability guarantee, verified the only way
// that counts: a real process is killed with SIGKILL after writing, and a fresh
// process must read back every record.
func TestSpoolSurvivesSIGKILL(t *testing.T) {
	dir := t.TempDir()

	child := exec.Command(os.Args[0], "-test.run=TestSpoolSurvivesSIGKILL")
	child.Env = append(os.Environ(), childEnv+"="+dir)
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	}()

	// Wait for the child to finish writing.
	ready := filepath.Join(dir, "ready")
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child never signalled readiness")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := child.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill child: %v", err)
	}
	state, err := child.Process.Wait()
	if err != nil {
		t.Fatalf("wait child: %v", err)
	}
	if state.ExitCode() != -1 {
		t.Logf("child exited with %d (expected a signal)", state.ExitCode())
	}

	// A fresh process must find every record.
	sp, err := spool.Open(dir, spool.Options{SegmentBytes: 64 << 10, MaxBytes: 16 << 20})
	if err != nil {
		t.Fatalf("reopen spool: %v", err)
	}
	defer sp.Close()

	recs, err := sp.Read(childRecords * 2)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(recs) != childRecords {
		t.Fatalf("recovered %d records after SIGKILL, want %d", len(recs), childRecords)
	}

	// Order and content must be intact, not merely the count.
	for i, r := range recs {
		var e event.Event
		if err := json.Unmarshal(r.Data, &e); err != nil {
			t.Fatalf("record %d is corrupt: %v", i, err)
		}
		if want := fmt.Sprintf("evt-%04d", i); e.ID != want {
			t.Fatalf("record %d has ID %q, want %q", i, e.ID, want)
		}
	}
}

// TestSpoolResumesFromCheckpointAfterKill checks that a consumer which
// committed part way through does not re-deliver what it already shipped.
func TestSpoolResumesFromCheckpointAfterKill(t *testing.T) {
	dir := t.TempDir()
	opts := spool.Options{SegmentBytes: 64 << 10, MaxBytes: 16 << 20}

	sp, err := spool.Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 500 {
		if err := sp.Append([]byte(fmt.Sprintf("record-%04d", i))); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := sp.Read(200)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Commit(recs[len(recs)-1].Next); err != nil {
		t.Fatal(err)
	}
	sp.Sync()
	// Abandon without closing, as a crash would.

	sp2, err := spool.Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer sp2.Close()

	rest, err := sp2.Read(1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 300 {
		t.Fatalf("recovered %d records, want the 300 that were never committed", len(rest))
	}
	if string(rest[0].Data) != "record-0200" {
		t.Errorf("resumed at %q, want record-0200", rest[0].Data)
	}
}
