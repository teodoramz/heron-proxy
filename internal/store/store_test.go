package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/amzteodor/heron/internal/config"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

// newStore connects to the test database and starts each test from a clean schema.
func newStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn, testKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(s.Close)

	if _, err := s.pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

// mustSaveApp fails the test if the app cannot be stored, so a broken insert
// cannot silently cascade into later assertions.
func mustSaveApp(t *testing.T, s *Store, app config.App) {
	t.Helper()
	if err := s.SaveApp(context.Background(), app); err != nil {
		t.Fatalf("SaveApp(%s): %v", app.ID, err)
	}
}

func testApp(id string) config.App {
	return config.App{
		ID:          id,
		Name:        "app " + id,
		Hostnames:   []string{id + ".example"},
		UpstreamURL: "http://127.0.0.1:9000",
		Enabled:     true,
		Capture:     config.DefaultCapture(),
		Redaction:   config.DefaultRedaction(),
		WAF:         config.DefaultWAF(),
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := newStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestAppRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	in := testApp("api")
	in.TrustedCIDRs = []string{"10.0.0.0/8"}
	in.Capture.BodyCapBytes = 4096
	in.WAF.Threshold = 7
	if err := s.SaveApp(ctx, in); err != nil {
		t.Fatalf("SaveApp: %v", err)
	}

	got, err := s.GetApp(ctx, "api")
	if err != nil {
		t.Fatalf("GetApp: %v", err)
	}
	if got.Name != in.Name || got.UpstreamURL != in.UpstreamURL {
		t.Errorf("basic fields lost: %+v", got)
	}
	if len(got.Hostnames) != 1 || got.Hostnames[0] != "api.example" {
		t.Errorf("Hostnames = %v", got.Hostnames)
	}
	if len(got.TrustedCIDRs) != 1 || got.TrustedCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("TrustedCIDRs = %v", got.TrustedCIDRs)
	}
	if got.Capture.BodyCapBytes != 4096 {
		t.Errorf("capture policy lost: %+v", got.Capture)
	}
	if got.WAF.Threshold != 7 {
		t.Errorf("waf policy lost: %+v", got.WAF)
	}
	if got.RetentionDays != 90 {
		t.Errorf("RetentionDays = %d", got.RetentionDays)
	}
}

func TestSaveAppUpserts(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	app := testApp("api")
	mustSaveApp(t, s, app)
	app.Name = "renamed"
	if err := s.SaveApp(ctx, app); err != nil {
		t.Fatalf("second SaveApp: %v", err)
	}
	got, _ := s.GetApp(ctx, "api")
	if got.Name != "renamed" {
		t.Errorf("Name = %q", got.Name)
	}
	apps, _ := s.ListApps(ctx)
	if len(apps) != 1 {
		t.Errorf("got %d apps, want 1", len(apps))
	}
}

func TestGetAppMissing(t *testing.T) {
	s := newStore(t)
	if _, err := s.GetApp(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleteApp(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	mustSaveApp(t, s, testApp("api"))
	if err := s.DeleteApp(ctx, "api"); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	if err := s.DeleteApp(ctx, "api"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete err = %v, want ErrNotFound", err)
	}
}

func TestConfigVersionBumpsOnChange(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	before, err := s.ConfigVersion(ctx)
	if err != nil {
		t.Fatalf("ConfigVersion: %v", err)
	}
	mustSaveApp(t, s, testApp("api"))
	after, _ := s.ConfigVersion(ctx)
	if after <= before {
		t.Errorf("version did not advance: %d -> %d", before, after)
	}
}

func genKeyPair(t *testing.T, name string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestCertificateEncryptedAtRest(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	mustSaveApp(t, s, testApp("api"))

	certPEM, keyPEM := genKeyPair(t, "api.example")
	saved, err := s.SaveCertificate(ctx, Certificate{AppID: "api", CertPEM: certPEM, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatalf("SaveCertificate: %v", err)
	}
	if saved.PrivateKeyPEM != "" {
		t.Error("private key returned after save")
	}
	if saved.Fingerprint == "" || saved.NotAfter.IsZero() {
		t.Errorf("metadata not derived: %+v", saved)
	}
	if len(saved.SNINames) == 0 || saved.SNINames[0] != "api.example" {
		t.Errorf("SNINames = %v", saved.SNINames)
	}

	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT key_encrypted FROM certificates`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || string(raw) == keyPEM {
		t.Error("private key was stored in cleartext")
	}

	certs, err := s.LoadTLSCertificates(ctx)
	if err != nil {
		t.Fatalf("LoadTLSCertificates: %v", err)
	}
	if len(certs) != 1 || certs[0].Cert == nil {
		t.Fatalf("got %d usable certificates", len(certs))
	}
	if certs[0].Cert.Leaf.Subject.CommonName != "api.example" {
		t.Errorf("wrong certificate decrypted: %s", certs[0].Cert.Leaf.Subject.CommonName)
	}
}

func TestCertificateRejectsMismatchedPair(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	certPEM, _ := genKeyPair(t, "a.example")
	_, otherKey := genKeyPair(t, "b.example")

	if _, err := s.SaveCertificate(ctx, Certificate{CertPEM: certPEM, PrivateKeyPEM: otherKey}); err == nil {
		t.Error("mismatched key pair was accepted")
	}
}

func TestCertificateDeleteAndCascade(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	mustSaveApp(t, s, testApp("api"))
	certPEM, keyPEM := genKeyPair(t, "api.example")
	s.SaveCertificate(ctx, Certificate{AppID: "api", CertPEM: certPEM, PrivateKeyPEM: keyPEM})

	if err := s.DeleteApp(ctx, "api"); err != nil {
		t.Fatal(err)
	}
	certs, _ := s.ListCertificates(ctx)
	if len(certs) != 0 {
		t.Errorf("certificates survived app deletion: %d", len(certs))
	}
}

func TestUserLifecycle(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "admin", "hash", RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := s.GetUserByUsername(ctx, "ADMIN")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got.ID != u.ID || got.Role != RoleAdmin || !got.Enabled {
		t.Errorf("user mismatch: %+v", got)
	}
	if err := s.UpdateUser(ctx, u.ID, RoleAnalyst, false); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got, _ = s.GetUser(ctx, u.ID)
	if got.Role != RoleAnalyst || got.Enabled {
		t.Errorf("update not applied: %+v", got)
	}
	if err := s.SetPassword(ctx, u.ID, "newhash"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetUser(ctx, u.ID)
	if got.PasswordHash != "newhash" {
		t.Error("password not updated")
	}
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUser(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCreateUserRejectsBadRole(t *testing.T) {
	s := newStore(t)
	if _, err := s.CreateUser(context.Background(), "someone", "h", Role("root")); err == nil {
		t.Error("invalid role accepted")
	}
}

func TestRoleAtLeast(t *testing.T) {
	if !RoleAdmin.AtLeast(RoleAnalyst) || !RoleAdmin.AtLeast(RoleAdmin) {
		t.Error("an admin should satisfy every role")
	}
	if !RoleAnalyst.AtLeast(RoleAnalyst) {
		t.Error("a role should satisfy itself")
	}
	if RoleAnalyst.AtLeast(RoleAdmin) {
		t.Error("an analyst must not satisfy admin")
	}
}

func TestOnlyTwoRolesAreValid(t *testing.T) {
	for _, r := range []Role{RoleAdmin, RoleAnalyst} {
		if !r.Valid() {
			t.Errorf("%q should be valid", r)
		}
	}
	for _, r := range []Role{"viewer", "root", ""} {
		if r.Valid() {
			t.Errorf("%q should not be valid", r)
		}
	}
}

func TestAppAccessScoping(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	mustSaveApp(t, s, testApp("a"))
	mustSaveApp(t, s, testApp("b"))
	u, _ := s.CreateUser(ctx, "analyst", "h", RoleAnalyst)

	if err := s.SetAppAccess(ctx, u.ID, []string{"a"}); err != nil {
		t.Fatalf("SetAppAccess: %v", err)
	}
	access, _ := s.AppAccess(ctx, u.ID)
	if len(access) != 1 || access[0] != "a" {
		t.Errorf("AppAccess = %v", access)
	}
	s.SetAppAccess(ctx, u.ID, nil)
	access, _ = s.AppAccess(ctx, u.ID)
	if len(access) != 0 {
		t.Errorf("AppAccess = %v, want empty", access)
	}
}

func TestBuildSecLangForms(t *testing.T) {
	cases := []struct {
		name string
		e    Exclusion
		want string
	}{
		{"whole rule", Exclusion{RuleID: 942100}, "SecRuleRemoveById 942100"},
		{"target", Exclusion{RuleID: 942100, Target: "ARGS:comment"},
			`SecRuleUpdateTargetById 942100 "!ARGS:comment"`},
		{"path", Exclusion{RuleID: 942100, Path: "/api/"},
			`SecRule REQUEST_URI "@beginsWith /api/" "id:10000000,phase:1,pass,nolog,ctl:ruleRemoveById=942100"`},
		{"path and target", Exclusion{RuleID: 942100, Path: "/api/", Target: "ARGS:q"},
			`SecRule REQUEST_URI "@beginsWith /api/" "id:10000000,phase:2,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:q"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := BuildSecLang(c.e, 10000000); got != c.want {
				t.Errorf("got  %s\nwant %s", got, c.want)
			}
		})
	}
}

func TestExclusionRoundTripAndRendering(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	mustSaveApp(t, s, testApp("api"))

	if _, err := s.SaveExclusion(ctx, Exclusion{
		AppID: "api", RuleID: 942100, Target: "ARGS:comment", Reason: "editor markup", Enabled: true,
	}); err != nil {
		t.Fatalf("SaveExclusion: %v", err)
	}
	if _, err := s.SaveExclusion(ctx, Exclusion{
		AppID: "api", RuleID: 941100, Path: "/wysiwyg/", Enabled: true,
	}); err != nil {
		t.Fatalf("SaveExclusion: %v", err)
	}
	disabled, _ := s.SaveExclusion(ctx, Exclusion{AppID: "api", RuleID: 930120, Enabled: false})

	list, err := s.ListExclusions(ctx, []string{"api"})
	if err != nil {
		t.Fatalf("ListExclusions: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("got %d exclusions, want 3", len(list))
	}
	var pathScoped bool
	for _, e := range list {
		if e.RuleID == 941100 {
			if e.Path != "/wysiwyg/" {
				t.Errorf("Path lost: %q", e.Path)
			}
			pathScoped = true
		}
	}
	if !pathScoped {
		t.Error("path-scoped exclusion not returned")
	}

	rules, err := s.ExclusionRules(ctx, "api")
	if err != nil {
		t.Fatalf("ExclusionRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rendered rules, want 2 (disabled excluded)", len(rules))
	}
	if rules[0] == rules[1] {
		t.Error("generated rules are identical")
	}

	if err := s.SetExclusionEnabled(ctx, disabled.ID, true); err != nil {
		t.Fatal(err)
	}
	rules, _ = s.ExclusionRules(ctx, "api")
	if len(rules) != 3 {
		t.Errorf("got %d rules after enabling, want 3", len(rules))
	}
}

func TestGeneratedExclusionIDsAreUnique(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	mustSaveApp(t, s, testApp("api"))
	for i := range 3 {
		s.SaveExclusion(ctx, Exclusion{
			AppID: "api", RuleID: int64(942100 + i), Path: fmt.Sprintf("/p%d/", i), Enabled: true,
		})
	}
	rules, _ := s.ExclusionRules(ctx, "api")
	seen := make(map[string]bool)
	for _, r := range rules {
		if seen[r] {
			t.Fatalf("duplicate rule generated: %s", r)
		}
		seen[r] = true
	}
	if len(rules) != 3 {
		t.Errorf("got %d rules", len(rules))
	}
}

func TestFPMarkUpsertAndSummary(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	mustSaveApp(t, s, testApp("api"))
	eventID := "11111111-1111-1111-1111-111111111111"

	if _, err := s.SaveFPMark(ctx, FPMark{
		EventID: eventID, AppID: "api", RuleID: 942100, Verdict: "true_positive",
	}); err != nil {
		t.Fatalf("SaveFPMark: %v", err)
	}
	if _, err := s.SaveFPMark(ctx, FPMark{
		EventID: eventID, AppID: "api", RuleID: 942100, Verdict: "false_positive", Note: "editor",
	}); err != nil {
		t.Fatalf("SaveFPMark upsert: %v", err)
	}

	marks, err := s.FPMarksForEvents(ctx, []string{eventID})
	if err != nil {
		t.Fatalf("FPMarksForEvents: %v", err)
	}
	if len(marks[eventID]) != 1 {
		t.Fatalf("got %d marks, want 1 after upsert", len(marks[eventID]))
	}
	if marks[eventID][0].Verdict != "false_positive" {
		t.Errorf("verdict = %q", marks[eventID][0].Verdict)
	}

	sums, _ := s.FPSummaries(ctx, []string{"api"})
	if len(sums) != 1 || sums[0].FalsePositive != 1 {
		t.Errorf("summaries = %+v", sums)
	}
}

func TestFPMarkRejectsBadVerdict(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_, err := s.SaveFPMark(ctx, FPMark{
		EventID: "11111111-1111-1111-1111-111111111111", AppID: "api", RuleID: 1, Verdict: "maybe",
	})
	if err == nil {
		t.Error("invalid verdict accepted")
	}
}

func TestAnnotationsAndBookmarks(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	id := "22222222-2222-2222-2222-222222222222"

	if err := s.SaveAnnotation(ctx, Annotation{
		EventID: id, AppID: "api", Tags: []string{"recon"}, Note: "scanner", Bookmarked: true,
	}); err != nil {
		t.Fatalf("SaveAnnotation: %v", err)
	}
	if err := s.SaveAnnotation(ctx, Annotation{
		EventID: id, AppID: "api", Tags: []string{"recon", "confirmed"}, Bookmarked: true,
	}); err != nil {
		t.Fatalf("SaveAnnotation update: %v", err)
	}

	got, err := s.AnnotationsForEvents(ctx, []string{id})
	if err != nil {
		t.Fatalf("AnnotationsForEvents: %v", err)
	}
	if len(got[id].Tags) != 2 {
		t.Errorf("Tags = %v", got[id].Tags)
	}
	ids, _ := s.BookmarkedEventIDs(ctx, []string{"api"}, 10)
	if len(ids) != 1 || ids[0] != id {
		t.Errorf("BookmarkedEventIDs = %v", ids)
	}
}

func TestSavedFilters(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	owner, _ := s.CreateUser(ctx, "owner", "h", RoleAnalyst)
	other, _ := s.CreateUser(ctx, "other", "h", RoleAnalyst)

	if _, err := s.SaveFilter(ctx, SavedFilter{
		UserID: owner.ID, Name: "private", Query: json.RawMessage(`{"status":404}`),
	}); err != nil {
		t.Fatalf("SaveFilter: %v", err)
	}
	if _, err := s.SaveFilter(ctx, SavedFilter{
		UserID: owner.ID, Name: "shared", Query: json.RawMessage(`{"would_block":true}`), Shared: true,
	}); err != nil {
		t.Fatal(err)
	}

	mine, _ := s.ListFilters(ctx, owner.ID)
	if len(mine) != 2 {
		t.Errorf("owner sees %d filters, want 2", len(mine))
	}
	theirs, _ := s.ListFilters(ctx, other.ID)
	if len(theirs) != 1 || theirs[0].Name != "shared" {
		t.Errorf("other user sees %+v, want only the shared filter", theirs)
	}
}

func TestDeleteFilterRequiresOwnership(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	owner, _ := s.CreateUser(ctx, "owner", "h", RoleAnalyst)
	other, _ := s.CreateUser(ctx, "other", "h", RoleAnalyst)
	f, _ := s.SaveFilter(ctx, SavedFilter{UserID: owner.ID, Name: "f", Query: json.RawMessage(`{}`), Shared: true})

	if err := s.DeleteFilter(ctx, f.ID, other.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("non-owner delete err = %v, want ErrNotFound", err)
	}
	if err := s.DeleteFilter(ctx, f.ID, owner.ID); err != nil {
		t.Errorf("owner delete: %v", err)
	}
}

func TestAlertRules(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	mustSaveApp(t, s, testApp("api"))

	r, err := s.SaveAlertRule(ctx, AlertRule{
		Name: "sqli", AppID: "api", Channel: "webhook", TargetURL: "https://hook.example",
		ThrottleSeconds: 60, Enabled: true,
		Condition: AlertCondition{RuleTags: []string{"attack-sqli"}, MinAnomaly: 5},
	})
	if err != nil {
		t.Fatalf("SaveAlertRule: %v", err)
	}
	list, _ := s.ListAlertRules(ctx)
	if len(list) != 1 {
		t.Fatalf("got %d rules", len(list))
	}
	if len(list[0].Condition.RuleTags) != 1 || list[0].Condition.MinAnomaly != 5 {
		t.Errorf("condition lost: %+v", list[0].Condition)
	}
	if err := s.TouchAlertFired(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListAlertRules(ctx)
	if list[0].LastFiredAt == nil {
		t.Error("LastFiredAt not recorded")
	}
	if err := s.DeleteAlertRule(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
}

func TestAlertRuleRejectsBadChannel(t *testing.T) {
	s := newStore(t)
	_, err := s.SaveAlertRule(context.Background(), AlertRule{
		Name: "x", Channel: "carrier-pigeon", TargetURL: "https://x.example",
	})
	if err == nil {
		t.Error("invalid channel accepted")
	}
}

func TestAuditLog(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "auditor", "h", RoleAdmin)

	if err := s.Audit(ctx, u.ID, "app.update", map[string]string{"app": "api"}); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if err := s.Audit(ctx, "", "system.start", nil); err != nil {
		t.Fatalf("Audit without user: %v", err)
	}
	entries, err := s.ListAudit(ctx, 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Action != "system.start" {
		t.Errorf("entries not newest-first: %+v", entries[0])
	}
}

func TestEncryptionRoundTrip(t *testing.T) {
	s := &Store{}
	if _, err := s.encrypt([]byte("x")); err == nil {
		t.Error("encryption without a key was allowed")
	}
	s2 := newStore(t)
	sealed, err := s2.encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s2.decrypt(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "secret" {
		t.Errorf("got %q", plain)
	}
	if _, err := s2.decrypt([]byte("short")); err == nil {
		t.Error("truncated ciphertext accepted")
	}
}

func TestValidatePEM(t *testing.T) {
	certPEM, _ := genKeyPair(t, "x.example")
	if err := ValidatePEM(certPEM); err != nil {
		t.Errorf("valid PEM rejected: %v", err)
	}
	if err := ValidatePEM("not a pem"); err == nil {
		t.Error("garbage accepted as PEM")
	}
}

func TestCertificateAuthorityIsCreatedOnceAndReused(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	first, err := s.EnsureCA(ctx, "test authority")
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	second, err := s.EnsureCA(ctx, "test authority")
	if err != nil {
		t.Fatalf("second EnsureCA: %v", err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Error("a second call generated a different authority")
	}

	info, err := s.CAInfo(ctx)
	if err != nil {
		t.Fatalf("CAInfo: %v", err)
	}
	if info.Fingerprint != first.Fingerprint() || info.CertPEM == "" {
		t.Errorf("info does not match the authority: %+v", info)
	}
	if info.NotAfter.Before(time.Now().AddDate(5, 0, 0)) {
		t.Errorf("authority expires %s, sooner than expected", info.NotAfter)
	}
}

func TestCertificateAuthorityKeyIsEncryptedAtRest(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ca, err := s.EnsureCA(ctx, "test authority")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := ca.KeyPEM()

	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT key_encrypted FROM certificate_authority`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) == string(keyPEM) {
		t.Error("the authority key was stored in cleartext")
	}
}

func TestRegenerateCertificateAuthority(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	before, _ := s.EnsureCA(ctx, "test authority")
	after, err := s.RegenerateCA(ctx, "test authority")
	if err != nil {
		t.Fatalf("RegenerateCA: %v", err)
	}
	if before.Fingerprint() == after.Fingerprint() {
		t.Error("regenerating produced the same authority")
	}
	loaded, _ := s.LoadCA(ctx)
	if loaded.Fingerprint() != after.Fingerprint() {
		t.Error("the stored authority is not the regenerated one")
	}
}

func TestCertificateAuthorityMissingBeforeCreation(t *testing.T) {
	s := newStore(t)
	if _, err := s.LoadCA(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestUsernameRules(t *testing.T) {
	for _, name := range []string{"a", "", "  ", "has space", "user@example.com", "sláinte", strings.Repeat("x", 41)} {
		if err := ValidUsername(name); err == nil {
			t.Errorf("ValidUsername(%q) accepted it", name)
		}
	}
	for _, name := range []string{"admin", "a.b", "first-last", "under_score", "user123"} {
		if err := ValidUsername(name); err != nil {
			t.Errorf("ValidUsername(%q): %v", name, err)
		}
	}
}

func TestUsernamesAreUniqueIgnoringCase(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if _, err := s.CreateUser(ctx, "Morgan", "hash", RoleAnalyst); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := s.CreateUser(ctx, "morgan", "hash", RoleAnalyst); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("err = %v, want ErrUsernameTaken", err)
	}
}

func TestSignInIgnoresCaseAndSurroundingSpace(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	created, err := s.CreateUser(ctx, "Morgan", "hash", RoleAnalyst)
	if err != nil {
		t.Fatal(err)
	}
	for _, typed := range []string{"Morgan", "morgan", "  MORGAN  "} {
		got, err := s.GetUserByUsername(ctx, typed)
		if err != nil {
			t.Errorf("GetUserByUsername(%q): %v", typed, err)
			continue
		}
		if got.ID != created.ID {
			t.Errorf("GetUserByUsername(%q) found a different account", typed)
		}
	}
}
