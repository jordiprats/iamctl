package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func printWarnings(warnings []string, w *os.File) {
	for _, warn := range warnings {
		fmt.Fprintln(w, warn)
	}
	if len(warnings) > 0 {
		fmt.Fprintln(w)
	}
}

func formatDateTimeForConsole(t time.Time) string {
	local := t.Local()
	_, offsetSec := local.Zone()
	sign := "+"
	if offsetSec < 0 {
		sign = "-"
		offsetSec = -offsetSec
	}
	hours := offsetSec / 3600
	minutes := (offsetSec % 3600) / 60
	return fmt.Sprintf("%s (UTC%s%02d:%02d)", local.Format("January 2, 2006, 15:04"), sign, hours, minutes)
}

func formatLastActivity(lastUsedAt *time.Time) string {
	if lastUsedAt == nil {
		return "No recent activity"
	}
	delta := time.Since(*lastUsedAt)
	if delta < time.Minute {
		return "just now"
	}
	if delta < time.Hour {
		m := int(delta / time.Minute)
		if m == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", m)
	}
	if delta < 24*time.Hour {
		h := int(delta / time.Hour)
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	}
	days := int(delta / (24 * time.Hour))
	if days == 1 {
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", days)
}

func formatSessionDuration(seconds int32) string {
	d := time.Duration(seconds) * time.Second
	h := int(d / time.Hour)
	if d%time.Hour == 0 {
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}
	m := int(d / time.Minute)
	if m == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", m)
}

func printDescribeField(label, value string) {
	fmt.Printf("%-22s %s\n", label+":", value)
}

func indentBlock(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}
