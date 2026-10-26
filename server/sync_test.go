package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"argus/db"
	"argus/dns_provider"
)

type mockProvider struct {
	records []dns_provider.Record
}

func (m *mockProvider) Type() string { return "mock_sync_test" }
func (m *mockProvider) Name() string { return "MockSyncTest" }
func (m *mockProvider) FetchRecords(ctx context.Context, cfg dns_provider.ProviderConfig, domain string) ([]dns_provider.Record, error) {
	return m.records, nil
}

func TestExecuteDNSSync_DeleteSubdomains(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "argus-test-sync-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.InitDB(dbPath)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()

	// 注册 Mock Provider
	mock := &mockProvider{
		records: []dns_provider.Record{
			{Name: "example.com", Type: "A", Value: "1.1.1.1"},
			{Name: "www.example.com", Type: "CNAME", Value: "example.com"},
			{Name: "legacy-sub.example.com", Type: "A", Value: "1.2.3.3"},
			{Name: "new-sub.example.com", Type: "A", Value: "1.2.3.4"},
			{Name: "blocked-sub.example.com", Type: "A", Value: "1.2.3.5"},
		},
	}
	dns_provider.RegisterProvider(mock, dns_provider.ProviderMeta{
		Type: "mock_sync_test",
		Name: "MockSyncTest",
	})

	var checkedDomains []string
	checkSingle := func(dom *db.Domain) (*db.Domain, error) {
		checkedDomains = append(checkedDomains, dom.Host)
		return dom, nil
	}

	srv := &Server{
		db:          database,
		checkSingle: checkSingle,
	}

	// 预先向数据库添加目标：
	// 1. example.com (根域名，check_domain = true)
	// 2. www.example.com (有效子域名)
	// 3. legacy-sub.example.com (有效子域名，历史遗留开启了 check_domain = true)
	// 4. deleted-sub.example.com (外部已删除的子域名，mock中不存在)
	// 5. blocked-sub.example.com (将被黑名单过滤的子域名)
	// 6. other.org (另一个主域名的子域名，不应被触碰)
	bTrue := true
	_, err = database.BatchAddDomains([]db.DomainImportItem{
		{Host: "example.com", Port: "443", CheckSSL: &bTrue, CheckDomain: true},
		{Host: "www.example.com", Port: "443", CheckSSL: &bTrue, CheckDomain: false},
		{Host: "legacy-sub.example.com", Port: "443", CheckSSL: &bTrue, CheckDomain: true},
		{Host: "deleted-sub.example.com", Port: "443", CheckSSL: &bTrue, CheckDomain: false},
		{Host: "blocked-sub.example.com", Port: "443", CheckSSL: &bTrue, CheckDomain: false},
		{Host: "api.other.org", Port: "443", CheckSSL: &bTrue, CheckDomain: false},
	})
	if err != nil {
		t.Fatalf("BatchAddDomains failed: %v", err)
	}

	// 执行同步，黑名单包含 "blocked-sub"
	cfg := dns_provider.ProviderConfig{
		ProviderType: "mock_sync_test",
		AuthKey:      "dummy_key",
	}
	blacklist := []string{"blocked-sub"}

	res, err := srv.ExecuteDNSSync("example.com", cfg, blacklist, "443", &bTrue, true, 0)
	if err != nil {
		t.Fatalf("ExecuteDNSSync failed: %v", err)
	}

	// 验证同步统计
	if res.Added != 1 {
		t.Errorf("expected Added=1 (new-sub), got %d", res.Added)
	}
	if res.Deleted != 2 {
		t.Errorf("expected Deleted=2 (deleted-sub and blocked-sub), got %d (deleted: %v)", res.Deleted, res.DeletedDomains)
	}

	// 验证数据库现有域名
	all, err := database.GetAllDomains()
	if err != nil {
		t.Fatalf("GetAllDomains failed: %v", err)
	}

	hosts := make(map[string]bool)
	checkDomainMap := make(map[string]bool)
	for _, d := range all {
		hosts[d.Host] = true
		checkDomainMap[d.Host] = d.CheckDomain
	}

	if !hosts["example.com"] {
		t.Errorf("example.com should be kept")
	}
	if !hosts["www.example.com"] {
		t.Errorf("www.example.com should be kept")
	}
	if !hosts["legacy-sub.example.com"] {
		t.Errorf("legacy-sub.example.com should be kept")
	}
	if !hosts["new-sub.example.com"] {
		t.Errorf("new-sub.example.com should be added")
	}
	if !hosts["api.other.org"] {
		t.Errorf("api.other.org should not be affected")
	}

	// 验证 CheckDomain 状态：子域名默认不检测注册日期，仅根域名检测
	if !checkDomainMap["example.com"] {
		t.Errorf("example.com (apex domain) should have CheckDomain=true")
	}
	if checkDomainMap["new-sub.example.com"] {
		t.Errorf("new-sub.example.com (subdomain) should have CheckDomain=false")
	}
	if checkDomainMap["legacy-sub.example.com"] {
		t.Errorf("legacy-sub.example.com (subdomain) should have CheckDomain corrected to false")
	}
	if checkDomainMap["www.example.com"] {
		t.Errorf("www.example.com should have CheckDomain=false")
	}

	if hosts["deleted-sub.example.com"] {
		t.Errorf("deleted-sub.example.com should have been deleted!")
	}
	if hosts["blocked-sub.example.com"] {
		t.Errorf("blocked-sub.example.com should have been deleted!")
	}

	// 测试 RunApexCheckAndSync 巡检
	checkedDomains = nil
	apexRes, err := srv.RunApexCheckAndSync("example.com")
	if err != nil {
		t.Fatalf("RunApexCheckAndSync failed: %v", err)
	}

	if apexRes.CheckCount != 4 {
		t.Errorf("expected 4 targets checked under example.com, got %d", apexRes.CheckCount)
	}

	for _, checked := range checkedDomains {
		if checked == "deleted-sub.example.com" || checked == "blocked-sub.example.com" {
			t.Errorf("deleted or blocked domain %s was checked during apex check!", checked)
		}
	}
}
