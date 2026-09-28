package main

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

func TestScopedSchedulerErrorWireContract(t *testing.T) {
	old := state.Load()
	t.Cleanup(func() { state.Store(old) })
	for _, name := range []string{"wrong-scope", "unknown-key", "missing-key", "missing-session", "unknown-source", "wrong-parent", "unavailable-candidate", "missing-state", "locked-state", "capacity", "authorized"} {
		t.Run(name, func(t *testing.T) {
			p := defaultPolicy()
			p.isolation = isolationFixture(t)
			p.isolation.requireScopeBoundKey = true
			p.unboundPassthrough = false
			p.byKey["test-key"] = &binding{patterns: []string{"p"}}
			state.Store(p)
			r := isolationRequest("request", "", "personal/codex-oauth/model")
			wantStatus := http.StatusForbidden
			wantCode := "scope_denied"
			switch name {
			case "wrong-scope":
				r.Model = "work/litellm/model"
			case "unknown-key":
				r.Options.Headers["Authorization"] = []string{"Bearer unknown-key"}
			case "missing-key":
				r.Options.Headers = nil
			case "missing-session":
				r.Options.Metadata = nil
			case "unknown-source":
				r.Model = "personal/not-configured/model"
			case "wrong-parent":
				r.Options.Metadata["parent_session_id"] = "unknown-parent"
			case "unavailable-candidate":
				r.Candidates = r.Candidates[1:]
				wantStatus, wantCode = http.StatusServiceUnavailable, "isolation_unavailable"
			case "missing-state":
				if err := os.Remove(p.isolation.file); err != nil {
					t.Fatal(err)
				}
				wantStatus, wantCode = http.StatusServiceUnavailable, "isolation_unavailable"
			case "locked-state":
				if err := os.WriteFile(p.isolation.file+".lock", nil, 0600); err != nil {
					t.Fatal(err)
				}
				wantStatus, wantCode = http.StatusServiceUnavailable, "isolation_unavailable"
			case "capacity":
				p.isolation.limit = 1
				if _, err := p.isolation.filter(isolationRequest("existing", "", r.Model), p.byKey["test-key"]); err != nil {
					t.Fatal(err)
				}
				wantStatus, wantCode = http.StatusServiceUnavailable, "isolation_unavailable"
			case "authorized":
				wantStatus = 0
			}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			// Decode the wire independently so production struct omissions cannot
			// make this test accept a missing HTTP status or retryable:false.
			var got struct {
				OK     bool                  `json:"ok"`
				Result schedulerPickResponse `json:"result"`
				Error  *struct {
					Code       string `json:"code"`
					HTTPStatus int    `json:"http_status"`
					Retryable  *bool  `json:"retryable"`
				} `json:"error"`
			}
			if err := json.Unmarshal(handlePick(raw), &got); err != nil {
				t.Fatal(err)
			}
			if wantStatus == 0 {
				if !got.OK || got.Error != nil || !got.Result.Handled || got.Result.AuthID != "p" {
					t.Fatalf("authorized pick = %+v", got)
				}
				return
			}
			if got.OK || got.Error == nil || got.Error.HTTPStatus != wantStatus || got.Error.Code != wantCode {
				t.Fatalf("error = %+v, want %d/%s", got.Error, wantStatus, wantCode)
			}
			if wantStatus == http.StatusForbidden && (got.Error.Retryable == nil || *got.Error.Retryable) {
				t.Fatal("policy denial must explicitly be nonretryable")
			}
		})
	}
}

func TestUnclassifiedErrorsKeepTheirExistingWireContract(t *testing.T) {
	for _, code := range []string{"invalid_request", "plugin_panic", "json_error"} {
		var got struct {
			Error map[string]json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(errorEnvelope(code, "synthetic failure"), &got); err != nil {
			t.Fatal(err)
		}
		if _, ok := got.Error["http_status"]; ok {
			t.Fatalf("%s was incorrectly classified as a policy denial", code)
		}
	}
}
