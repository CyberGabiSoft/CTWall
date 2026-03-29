package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParsePagination(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	page, pageSize, err := parsePagination(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if page != 1 || pageSize != defaultPageSize {
		t.Fatalf("unexpected defaults: page=%d pageSize=%d", page, pageSize)
	}

	req = httptest.NewRequest(http.MethodGet, "/?page=2&pageSize=10", nil)
	page, pageSize, err = parsePagination(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if page != 2 || pageSize != 10 {
		t.Fatalf("unexpected values: page=%d pageSize=%d", page, pageSize)
	}

	req = httptest.NewRequest(http.MethodGet, "/?page=0", nil)
	if _, _, err = parsePagination(req); err == nil {
		t.Fatalf("expected error for page=0")
	}

	req = httptest.NewRequest(http.MethodGet, "/?page=abc", nil)
	if _, _, err = parsePagination(req); err == nil {
		t.Fatalf("expected error for invalid page")
	}

	req = httptest.NewRequest(http.MethodGet, "/?pageSize=0", nil)
	if _, _, err = parsePagination(req); err == nil {
		t.Fatalf("expected error for pageSize=0")
	}

	req = httptest.NewRequest(http.MethodGet, "/?pageSize=abc", nil)
	if _, _, err = parsePagination(req); err == nil {
		t.Fatalf("expected error for invalid pageSize")
	}

	req = httptest.NewRequest(http.MethodGet, "/?pageSize=999", nil)
	_, pageSize, err = parsePagination(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if pageSize != maxPageSize {
		t.Fatalf("expected pageSize clamped to %d, got %d", maxPageSize, pageSize)
	}
}

func TestPaginate(t *testing.T) {
	items := []int{1, 2, 3, 4, 5}
	if got := paginate(items, 1, 2); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("unexpected page 1: %v", got)
	}
	if got := paginate(items, 3, 2); len(got) != 1 || got[0] != 5 {
		t.Fatalf("unexpected page 3: %v", got)
	}
	if got := paginate(items, 10, 2); len(got) != 0 {
		t.Fatalf("expected empty page, got %v", got)
	}
	if got := paginate(items, 0, 2); len(got) != 0 {
		t.Fatalf("expected empty page for invalid inputs")
	}
	if got := paginate(items, 1, 0); len(got) != 0 {
		t.Fatalf("expected empty page for invalid inputs")
	}
}
