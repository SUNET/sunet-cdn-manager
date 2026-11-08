package components

import (
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
)

// dashboardServiceRow is one card of the dashboard's "Service versions"
// section.
type dashboardServiceRow struct {
	name string
	href string
	// header is the text of the card's <header>: the service name and,
	// for a disabled service, the "(disabled)" marker. It is trimmed
	// because templ emits a space after the name even without a marker.
	header string
	quota  string
	// progress is the progress bar's aria-label, empty without a bar.
	progress string
}

// dashboardServiceRows returns the cards of the "Service versions" section in
// page order, and false when the section is absent.
func dashboardServiceRows(t *testing.T, html string) ([]dashboardServiceRow, bool) {
	t.Helper()

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		t.Fatal(err)
	}
	heading := doc.Find("h2").FilterFunction(func(_ int, h *goquery.Selection) bool {
		return h.Text() == "Service versions"
	})
	if heading.Length() == 0 {
		return nil, false
	}

	var rows []dashboardServiceRow
	heading.Next().Find("article").Each(func(_ int, a *goquery.Selection) {
		link := a.Find("header a")
		href, _ := link.Attr("href")
		progress, _ := a.Find("progress").Attr("aria-label")
		rows = append(rows, dashboardServiceRow{
			name:     link.Text(),
			href:     href,
			header:   strings.TrimSpace(a.Find("header").Text()),
			quota:    a.Find(".quota-value").Text(),
			progress: progress,
		})
	})
	return rows, true
}

// TestDashboardServiceVersions checks the per-service version quota section:
// input order is kept, a quota of 0 shows 0/0 without a progress bar (no
// zero max), and the section is absent when the org has no services.
func TestDashboardServiceVersions(t *testing.T) {
	alphaID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	betaID := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}

	data := cdntypes.DashboardData{
		ResourceAccess: true,
		OrgDashboard:   true,
		OrgName:        "myorg",
		ServiceVersions: []cdntypes.ServiceVersionUsage{
			{ID: alphaID, Name: "alpha", Used: 3, Quota: 1000},
			{ID: betaID, Name: "beta", Used: 0, Quota: 0, Disabled: true},
		},
	}
	html := render(t, Dashboard(data))

	rows, ok := dashboardServiceRows(t, html)
	if !ok {
		t.Fatalf("missing Service versions section\n%s", html)
	}
	want := []dashboardServiceRow{
		{name: "alpha", href: "/console/org/myorg/services/" + alphaID.String(), header: "alpha", quota: "3/1000", progress: "alpha version quota"},
		{name: "beta", href: "/console/org/myorg/services/" + betaID.String(), header: "beta (disabled)", quota: "0/0", progress: ""},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(rows), len(want), rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d is %+v, want %+v", i, rows[i], want[i])
		}
	}

	data.ServiceVersions = nil
	if _, ok := dashboardServiceRows(t, render(t, Dashboard(data))); ok {
		t.Errorf("section rendered without services")
	}
}
