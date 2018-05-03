package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/apex/log"
)

func RightPad(str string, length int) string {
	return str + strings.Repeat(" ", length-len(str))
}

// XXX Copy-pasta from nettest/groups
// PerformanceSummary is the result summary for a performance test
type PerformanceSummary struct {
	Upload   int64
	Download int64
	Ping     float64
	Bitrate  int64
}

// MiddleboxSummary is the summary for the middlebox tests
type MiddleboxSummary struct {
	Detected bool
}

// IMSummary is the summary for the im tests
type IMSummary struct {
	Tested  uint
	Blocked uint
}

// WebsitesSummary is the summary for the websites test
type WebsitesSummary struct {
	Tested  uint
	Blocked uint
}

func formatSpeed(speed int64) string {
	if speed < 1000 {
		return fmt.Sprintf("%d Kbit/s", speed)
	} else if speed < 1000*1000 {
		return fmt.Sprintf("%.2f Mbit/s", float32(speed)/1000)
	} else if speed < 1000*1000*1000 {
		return fmt.Sprintf("%.2f Gbit/s", float32(speed)/(1000*1000))
	}
	// WTF, you crazy?
	return fmt.Sprintf("%.2f Tbit/s", float32(speed)/(1000*1000*1000))
}

var summarizers = map[string]func(string) []string{
	"websites": func(ss string) []string {
		var summary WebsitesSummary
		if err := json.Unmarshal([]byte(ss), &summary); err != nil {
			return nil
		}
		return []string{
			fmt.Sprintf("%d tested", summary.Tested),
			fmt.Sprintf("%d blocked", summary.Blocked),
			"",
		}
	},
	"performance": func(ss string) []string {
		var summary PerformanceSummary
		if err := json.Unmarshal([]byte(ss), &summary); err != nil {
			return nil
		}
		return []string{
			fmt.Sprintf("Download: %s", formatSpeed(summary.Download)),
			fmt.Sprintf("Upload: %s", formatSpeed(summary.Upload)),
			fmt.Sprintf("Ping: %.2fms", summary.Ping),
		}
	},
	"im": func(ss string) []string {
		var summary IMSummary
		if err := json.Unmarshal([]byte(ss), &summary); err != nil {
			return nil
		}
		return []string{
			fmt.Sprintf("%d tested", summary.Tested),
			fmt.Sprintf("%d blocked", summary.Blocked),
			"",
		}
	},
	"middlebox": func(ss string) []string {
		var summary MiddleboxSummary
		if err := json.Unmarshal([]byte(ss), &summary); err != nil {
			return nil
		}
		return []string{
			fmt.Sprintf("Detected: %v", summary.Detected),
			"",
			"",
		}
	},
}

func makeSummary(name string, ss string) []string {
	return summarizers[name](ss)
}

func logResultItem(w io.Writer, f log.Fields) error {
	colWidth := 24

	rID := f.Get("id").(int64)
	name := f.Get("name").(string)
	startTime := f.Get("start_time").(time.Time)
	networkName := f.Get("network_name").(string)
	asn := fmt.Sprintf("AS %s", f.Get("asn").(string))
	//runtime := f.Get("runtime").(float64)
	//dataUsageUp := f.Get("dataUsageUp").(int64)
	//dataUsageDown := f.Get("dataUsageDown").(int64)
	index := f.Get("index").(int)
	totalCount := f.Get("total_count").(int)
	if index == 0 {
		fmt.Fprintf(w, "┏"+strings.Repeat("━", colWidth*2+2)+"┓\n")
	} else {
		fmt.Fprintf(w, "┢"+strings.Repeat("━", colWidth*2+2)+"┪\n")
	}

	firstRow := RightPad(fmt.Sprintf("#%d - %s", rID, startTime.Format(time.RFC822)), colWidth*2)
	fmt.Fprintf(w, "┃ "+firstRow+" ┃\n")
	fmt.Fprintf(w, "┡"+strings.Repeat("━", colWidth*2+2)+"┩\n")

	summary := makeSummary(name, f.Get("summary").(string))

	fmt.Fprintf(w, fmt.Sprintf("│ %s %s│\n",
		RightPad(name, colWidth),
		RightPad(summary[0], colWidth)))
	fmt.Fprintf(w, fmt.Sprintf("│ %s %s│\n",
		RightPad(networkName, colWidth),
		RightPad(summary[1], colWidth)))
	fmt.Fprintf(w, fmt.Sprintf("│ %s %s│\n",
		RightPad(asn, colWidth),
		RightPad(summary[2], colWidth)))

	if index == totalCount-1 {
		fmt.Fprintf(w, "└┬──────────────┬──────────────┬──────────────┬")
		fmt.Fprintf(w, strings.Repeat("─", colWidth*2-44))
		fmt.Fprintf(w, "┘\n")
	}
	return nil
}