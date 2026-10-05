package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LogListURL is Chrome's list of CT logs. It's the set crt.sh and every other monitor ingest.
const LogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

type Log struct {
	Name     string
	Operator string
	URL      string // submission URL for RFC 6962, monitoring prefix for tiled logs
	Tiled    bool
}

type logListJSON struct {
	Operators []struct {
		Name      string        `json:"name"`
		Logs      []logListItem `json:"logs"`
		TiledLogs []logListItem `json:"tiled_logs"`
	} `json:"operators"`
}

type logListItem struct {
	Description      string                     `json:"description"`
	URL              string                     `json:"url"`
	MonitoringURL    string                     `json:"monitoring_url"`
	State            map[string]json.RawMessage `json:"state"`
	TemporalInterval *struct {
		EndExclusive time.Time `json:"end_exclusive"`
	} `json:"temporal_interval"`
}

// FetchLogs returns the logs that still accept new certificates.
func FetchLogs(ctx context.Context, c *Client, now time.Time) ([]Log, error) {
	resp, err := c.Get(ctx, LogListURL, nil)
	if err != nil {
		return nil, fmt.Errorf("log list: %w", err)
	}
	return parseLogList(resp.Body, now)
}

func parseLogList(body []byte, now time.Time) ([]Log, error) {
	var ll logListJSON
	if err := json.Unmarshal(body, &ll); err != nil {
		return nil, fmt.Errorf("log list: %w", err)
	}
	var logs []Log
	for _, op := range ll.Operators {
		add := func(items []logListItem, tiled bool) {
			for _, it := range items {
				_, usable := it.State["usable"]
				_, qualified := it.State["qualified"]
				if !usable && !qualified {
					continue
				}
				// Logs are sharded by certificate expiry. A shard whose window has passed gets no new entries.
				if it.TemporalInterval != nil && it.TemporalInterval.EndExclusive.Before(now) {
					continue
				}
				u := it.URL
				if tiled {
					u = it.MonitoringURL
				}
				logs = append(logs, Log{
					Name: it.Description, Operator: op.Name, URL: strings.TrimSuffix(u, "/"), Tiled: tiled,
				})
			}
		}
		add(op.Logs, false)
		add(op.TiledLogs, true)
	}
	return logs, nil
}
