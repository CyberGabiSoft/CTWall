package main

import (
	"backend/internal/core/alerting"
	"backend/internal/store"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	dbURL := strings.TrimSpace(os.Getenv("DB_URL"))
	if dbURL == "" {
		dbURL = "postgres://appuser:change-me-postgres@ctwall-postgres:5432/appdb?sslmode=disable"
	}
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		panic(err)
	}

	st, err := store.NewPostgresStore(db, "/tmp/ctwall-probe")
	if err != nil {
		panic(err)
	}
	defer st.Close()

	projectID := uuid.MustParse("1325aa1f-d29c-434a-979a-752a6a648697")
	cc, err := st.GetProjectConnectorConfig(projectID, store.ConnectorTypeJira)
	if err != nil {
		panic(err)
	}
	profile, err := alerting.ParseJiraConnectorProfile(cc.ConfigJSON)
	if err != nil {
		panic(err)
	}
	fmt.Printf("jira base=%s auth=%s email=%s tokenLen=%d\n", profile.BaseURL, profile.AuthMode, profile.Email, len(profile.APIToken))

	listEpics(profile)
	showIssue(profile, "KAN-101")
}

func jiraClient(timeoutSeconds int) *http.Client {
	t := 10 * time.Second
	if timeoutSeconds > 0 {
		t = time.Duration(timeoutSeconds) * time.Second
	}
	return &http.Client{Timeout: t}
}

func doReq(profile *alerting.JiraConnectorProfile, method, path string) []byte {
	client := jiraClient(profile.RequestTimeoutSeconds)
	u := strings.TrimRight(profile.BaseURL, "/") + path
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Accept", "application/json")
	switch profile.AuthMode {
	case alerting.JiraAuthModeAPIToken:
		req.SetBasicAuth(profile.Email, profile.APIToken)
	case alerting.JiraAuthModeBasic:
		req.SetBasicAuth(profile.Username, profile.Password)
	default:
		panic("unsupported auth mode")
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		panic(fmt.Sprintf("%s %s -> %d %s", method, path, resp.StatusCode, string(body)))
	}
	return body
}

func listEpics(profile *alerting.JiraConnectorProfile) {
	jql := url.QueryEscape(`project = KAN AND issuetype = Epic ORDER BY created DESC`)
	path := "/rest/api/3/search/jql?jql=" + jql + "&maxResults=20&fields=summary,status,issuetype"
	body := doReq(profile, http.MethodGet, path)
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		panic(err)
	}
	issues, _ := payload["issues"].([]any)
	fmt.Printf("epics found=%d\n", len(issues))
	for _, raw := range issues {
		item, _ := raw.(map[string]any)
		key, _ := item["key"].(string)
		fields, _ := item["fields"].(map[string]any)
		summary, _ := fields["summary"].(string)
		fmt.Printf("  %s | %s\n", key, summary)
	}
}

func showIssue(profile *alerting.JiraConnectorProfile, key string) {
	jql := url.QueryEscape("issuekey = " + key)
	path := "/rest/api/3/search/jql?jql=" + jql + "&maxResults=1&fields=summary,status,issuetype,parent"
	body := doReq(profile, http.MethodGet, path)
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		panic(err)
	}
	fmt.Printf("issue %s raw=%s\n", key, string(body))
}
