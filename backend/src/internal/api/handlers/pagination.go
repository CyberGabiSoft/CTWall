package handlers

import (
	"fmt"
	"net/http"
	"strconv"
)

const (
	defaultPageSize = 50
	maxPageSize     = 200
)

func parsePagination(r *http.Request) (page int, pageSize int, err error) {
	page = 1
	pageSize = defaultPageSize

	if raw := r.URL.Query().Get("page"); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil {
			return 0, 0, parseErr
		}
		if parsed < 1 {
			return 0, 0, fmt.Errorf("page must be >= 1")
		}
		page = parsed
	}

	if raw := r.URL.Query().Get("pageSize"); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil {
			return 0, 0, parseErr
		}
		if parsed < 1 {
			return 0, 0, fmt.Errorf("pageSize must be >= 1")
		}
		if parsed > maxPageSize {
			parsed = maxPageSize
		}
		pageSize = parsed
	}

	return page, pageSize, nil
}

func paginate[T any](items []T, page, pageSize int) []T {
	if pageSize <= 0 || page <= 0 {
		return []T{}
	}
	start := (page - 1) * pageSize
	if start >= len(items) {
		return []T{}
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}
