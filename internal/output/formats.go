package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ir-netlify/netlify-scanner-go/internal/netlify"
)

type Format string

const (
	FormatJSONL Format = "jsonl"
	FormatCSV   Format = "csv"
	FormatSARIF Format = "sarif"
	FormatText  Format = "text"
)

func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "", "jsonl", "ndjson":
		return FormatJSONL, nil
	case "csv":
		return FormatCSV, nil
	case "sarif":
		return FormatSARIF, nil
	case "text", "txt":
		return FormatText, nil
	}
	return "", fmt.Errorf("unknown format: %s", s)
}

type Writer interface {
	Write(v netlify.Verdict) error
	Close() error
}

type jsonlW struct{ w io.Writer }

func (j *jsonlW) Write(v netlify.Verdict) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = j.w.Write(append(b, '\n'))
	return err
}
func (j *jsonlW) Close() error { return nil }

type csvW struct {
	c       *csv.Writer
	wroteHdr bool
}

func (cw *csvW) Write(v netlify.Verdict) error {
	if !cw.wroteHdr {
		_ = cw.c.Write([]string{"host", "score", "is_netlify", "cname_match", "apex_fallback", "header_match", "server", "tls_san", "asn", "addrs", "cname"})
		cw.wroteHdr = true
	}
	return cw.c.Write([]string{
		v.Host,
		fmt.Sprint(v.Score),
		fmt.Sprint(v.IsNetlify),
		v.Signals.CNAMEMatch,
		fmt.Sprint(v.Signals.APEXFallback),
		v.Signals.HeaderMatch,
		v.Signals.ServerHeader,
		v.Signals.TLSSANMatch,
		fmt.Sprint(v.Signals.ASNMatch),
		strings.Join(v.Addrs, ","),
		v.CNAME,
	})
}

func (cw *csvW) Close() error {
	cw.c.Flush()
	return cw.c.Error()
}

type sarifW struct {
	w        io.Writer
	verdicts []netlify.Verdict
}

func (s *sarifW) Write(v netlify.Verdict) error {
	s.verdicts = append(s.verdicts, v)
	return nil
}

func (s *sarifW) Close() error {
	doc := sarifDoc{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:    "netlify-scanner-go",
					Version: "3.0",
					Rules: []sarifRule{{
						ID:               "NF001",
						Name:             "NetlifyEdgeAsset",
						ShortDescription: sarifText{"Asset is fronted by Netlify edge"},
						HelpURI:          "https://docs.netlify.com/",
					}},
				},
			},
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: true,
				EndTimeUtc:          time.Now().UTC().Format(time.RFC3339),
			}},
			Results: s.results(),
		}},
	}
	enc := json.NewEncoder(s.w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func (s *sarifW) results() []sarifResult {
	out := make([]sarifResult, 0, len(s.verdicts))
	for _, v := range s.verdicts {
		out = append(out, sarifResult{
			RuleID:  "NF001",
			Level:   "note",
			Message: sarifText{fmt.Sprintf("%s is Netlify (score=%d): %+v", v.Host, v.Score, v.Signals)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysLoc{
					ArtifactLocation: sarifArtifact{URI: "https://" + v.Host},
				},
			}},
		})
	}
	return out
}

type textW struct{ w io.Writer }

func (t *textW) Write(v netlify.Verdict) error {
	_, err := fmt.Fprintf(t.w, "%-50s score=%-3d %+v\n", v.Host, v.Score, v.Signals)
	return err
}
func (t *textW) Close() error { return nil }

func NewWriter(format Format, w io.Writer) Writer {
	switch format {
	case FormatCSV:
		return &csvW{c: csv.NewWriter(w)}
	case FormatSARIF:
		return &sarifW{w: w}
	case FormatText:
		return &textW{w: w}
	}
	return &jsonlW{w: w}
}

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}
type sarifTool struct{ Driver sarifDriver `json:"driver"` }
type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
	HelpURI          string    `json:"helpUri,omitempty"`
}
type sarifText struct{ Text string `json:"text"` }
type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUtc          string `json:"endTimeUtc"`
}
type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   sarifText      `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifLocation struct{ PhysicalLocation sarifPhysLoc `json:"physicalLocation"` }
type sarifPhysLoc struct{ ArtifactLocation sarifArtifact `json:"artifactLocation"` }
type sarifArtifact struct{ URI string `json:"uri"` }
