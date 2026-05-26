package models

import "time"

type SecuritySettings struct {
	UserID                 string    `db:"user_id"                  json:"user_id"`
	PromptScan             bool      `db:"prompt_scan"              json:"prompt_scan"`
	ToolIntercept          bool      `db:"tool_intercept"           json:"tool_intercept"`
	OutputScan             bool      `db:"output_scan"              json:"output_scan"`
	NetworkIntercept       bool      `db:"network_intercept"        json:"network_intercept"`
	FilesystemIntercept    bool      `db:"filesystem_intercept"     json:"filesystem_intercept"`
	BehavioralAlert        bool      `db:"behavioral_alert"         json:"behavioral_alert"`
	HallucinationDetection bool      `db:"hallucination_detection"  json:"hallucination_detection"`
	BrowserIntercept       bool      `db:"browser_intercept"        json:"browser_intercept"`
	CodeScan               bool      `db:"code_scan"                json:"code_scan"`
	UpdatedAt              time.Time `db:"updated_at"               json:"updated_at"`
}

// EnabledChecks converts the struct into the []string list expected by the runtime.
func (s SecuritySettings) EnabledChecks() []string {
	checks := []string{}
	if s.PromptScan {
		checks = append(checks, "PROMPT_SCAN")
	}
	if s.ToolIntercept {
		checks = append(checks, "TOOL_INTERCEPT")
	}
	if s.OutputScan {
		checks = append(checks, "OUTPUT_SCAN")
	}
	if s.NetworkIntercept {
		checks = append(checks, "NETWORK_INTERCEPT")
	}
	if s.FilesystemIntercept {
		checks = append(checks, "FILESYSTEM_INTERCEPT")
	}
	if s.BehavioralAlert {
		checks = append(checks, "BEHAVIORAL_ALERT")
	}
	if s.HallucinationDetection {
		checks = append(checks, "HALLUCINATION_DETECTION")
	}
	if s.BrowserIntercept {
		checks = append(checks, "BROWSER_INTERCEPT")
	}
	if s.CodeScan {
		checks = append(checks, "CODE_SCAN")
	}
	return checks
}

// DefaultSecuritySettings returns an all-enabled profile for users with no row yet.
func DefaultSecuritySettings(userID string) SecuritySettings {
	return SecuritySettings{
		UserID:                 userID,
		PromptScan:             true,
		ToolIntercept:          true,
		OutputScan:             true,
		NetworkIntercept:       true,
		FilesystemIntercept:    true,
		BehavioralAlert:        true,
		HallucinationDetection: true,
		BrowserIntercept:       true,
		CodeScan:               true,
	}
}
