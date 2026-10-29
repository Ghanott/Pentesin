package render

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Reporting (reporting_renderer.py)
// ---------------------------------------------------------------------------

func renderVulnerabilityReport(args map[string]any, result any) string {
	return renderReport(args, result, "Laporan Kerentanan", "Membuat laporan...")
}

// A revision names the report it changes and carries only the fields it
// replaces, so it renders the same sections with the ones it left alone absent.
func renderVulnerabilityReportUpdate(args map[string]any, result any) string {
	return renderReport(args, result, "Laporan Kerentanan Diperbarui", "Memperbarui laporan...")
}

// A deletion names the report it withdraws and the reason; the result carries
// the title the report had, so the reader knows what left the scan.
func renderVulnerabilityReportDelete(args map[string]any, result any) string {
	resultMap, _ := result.(map[string]any)
	var b strings.Builder
	b.WriteString("🐞 " + Bold(ReportHdr).Render("Laporan Kerentanan Dihapus"))

	reportID := StringValue(args["report_id"])
	if reportID != "" {
		b.WriteString("\n\n" + Bold(Field).Render("Laporan: ") + reportID)
	}
	if title := StringValue(resultMap["title"]); title != "" {
		b.WriteString("\n\n" + Bold(Field).Render("Judul: ") + title)
	}
	if sev := StringValue(resultMap["severity"]); sev != "" {
		b.WriteString("\n\n" + Bold(Field).Render("Tingkat Keparahan: ") +
			lipgloss.NewStyle().Bold(true).Foreground(SeverityColor(sev)).Render(SeverityLabel(sev)))
	}
	if reason := StringValue(args["delete_reason"]); reason != "" {
		b.WriteString("\n\n" + Bold(Field).Render("Alasan") + "\n" + reason)
	}
	if errMsg := StringValue(resultMap["error"]); errMsg != "" {
		b.WriteString("\n\n" + Col(SevHigh).Render(errMsg))
	}
	if reportID == "" {
		b.WriteString("\n  " + Dim().Render("Menghapus laporan..."))
	}
	return "\n\n" + b.String() + "\n\n"
}

func renderReport(args map[string]any, result any, heading, pending string) string {
	resultMap, _ := result.(map[string]any)
	var b strings.Builder
	b.WriteString("🐞 " + Bold(ReportHdr).Render(heading))

	field := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + Bold(Field).Render(label+": ") + value)
		}
	}
	reportID := StringValue(args["report_id"])
	field("Laporan", reportID)
	title := StringValue(args["title"])
	field("Judul", title)

	if sev := StringValue(resultMap["severity"]); sev != "" {
		b.WriteString("\n\n" + Bold(Field).Render("Tingkat Keparahan: ") +
			lipgloss.NewStyle().Bold(true).Foreground(SeverityColor(sev)).Render(SeverityLabel(sev)))
	}
	if score, ok := NumericValue(resultMap["cvss_score"]); ok {
		b.WriteString("\n\n" + Bold(Field).Render("Skor CVSS: ") +
			lipgloss.NewStyle().Bold(true).Foreground(CVSSColor(score)).Render(StringValue(resultMap["cvss_score"])))
	}
	field("Sasaran", StringValue(args["target"]))
	field("Endpoint", StringValue(args["endpoint"]))
	field("Metode", StringValue(args["method"]))
	field("CVE", StringValue(args["cve"]))
	field("CWE", StringValue(args["cwe"]))

	if bd, ok := args["cvss_breakdown"].(map[string]any); ok && len(bd) > 0 {
		parts := CVSSVectorParts(bd)
		if len(parts) > 0 {
			b.WriteString("\n\n" + Bold(Field).Render("Vektor CVSS: ") + Dim().Render(strings.Join(parts, "/")))
		}
	}

	section := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + Bold(Field).Render(label) + "\n" + renderAssistantMarkdown(value))
		}
	}
	if confidence := StringValue(args["confidence"]); confidence != "" {
		b.WriteString("\n\n" + Bold(Field).Render("Tingkat Keyakinan: ") +
			lipgloss.NewStyle().Bold(true).Foreground(confidenceColor(confidence)).
				Render(strings.ToUpper(confidence)))
		if rationale := StringValue(args["confidence_rationale"]); rationale != "" {
			b.WriteString("\n" + Dim().Render(rationale))
		}
	}

	section("Alasan", StringValue(args["update_reason"]))
	section("Deskripsi", StringValue(args["description"]))
	section("Dampak", StringValue(args["impact"]))
	section("Analisis Teknis", StringValue(args["technical_analysis"]))
	// The case against the finding travels with the case for it: a reader
	// triaging this needs both to judge whether to act.
	section("Bukti Penyangkal", StringValue(args["counterevidence"]))
	section("Kondisi Perubahan Keparahan", StringValue(args["severity_change_conditions"]))
	renderCodeLocations(&b, args["code_locations"])
	section("Langkah Reproduksi PoC", StringValue(args["poc_description"]))
	if poc := StringValue(args["poc_script_code"]); poc != "" {
		b.WriteString("\n\n" + Bold(Field).Render("Kode PoC") + "\n" + Col(Text).Render(poc))
	}
	section("Rekomendasi Perbaikan", StringValue(args["remediation_steps"]))
	// Any applyable fix above is one click from the user's codebase, so how it
	// was verified belongs next to it rather than in the artifact alone.
	section("Verifikasi Perbaikan", StringValue(args["fix_verification"]))

	if title == "" && reportID == "" {
		b.WriteString("\n  " + Dim().Render(pending))
	}
	return "\n\n" + b.String() + "\n\n"
}

// SeverityLabel translates display text without changing the stored enum.
func SeverityLabel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "KRITIS"
	case "high":
		return "TINGGI"
	case "medium":
		return "SEDANG"
	case "low":
		return "RENDAH"
	case "info", "informational":
		return "INFORMASIONAL"
	}
	return strings.ToUpper(severity)
}

// confidenceColor grades how firm the agent's own call is. Anything below
// high is a claim the reader has to check, and should not read as settled.
func confidenceColor(confidence string) lipgloss.Color {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high":
		return Green
	case "medium":
		return SevMed
	case "low":
		return SevHigh
	}
	return Gray
}

var cvssKeys = [][2]string{
	{"attack_vector", "AV"}, {"attack_complexity", "AC"}, {"privileges_required", "PR"},
	{"user_interaction", "UI"}, {"scope", "S"}, {"confidentiality", "C"},
	{"integrity", "I"}, {"availability", "A"},
}

func CVSSVectorParts(bd map[string]any) []string {
	var parts []string
	for _, kp := range cvssKeys {
		if v := StringValue(bd[kp[0]]); v != "" {
			parts = append(parts, kp[1]+":"+v)
		}
	}
	return parts
}

func renderCodeLocations(b *strings.Builder, raw any) {
	locs, ok := raw.([]any)
	if !ok || len(locs) == 0 {
		return
	}
	b.WriteString("\n\n" + Bold(Field).Render("Lokasi Kode"))
	for i, l := range locs {
		loc, ok := l.(map[string]any)
		if !ok {
			continue
		}
		b.WriteString("\n\n" + Dim().Render(fmt.Sprintf("  Lokasi %d: ", i+1)))
		file := StringValue(loc["file"])
		if file == "" {
			file = "unknown"
		}
		b.WriteString(Bold(InfoBlue).Render(file))
		if start, ok := NumericValue(loc["start_line"]); ok {
			if end, ok := NumericValue(loc["end_line"]); ok && end != start {
				b.WriteString(Col(LineNum).Render(fmt.Sprintf(":%d-%d", int(start), int(end))))
			} else {
				b.WriteString(Col(LineNum).Render(fmt.Sprintf(":%d", int(start))))
			}
		}
		if label := StringValue(loc["label"]); label != "" {
			b.WriteString(lipgloss.NewStyle().Italic(true).Foreground(Label).Render("\n  " + label))
		}
		if snip := StringValue(loc["snippet"]); snip != "" {
			b.WriteString("\n  " + Col(Snippet).Render(snip))
		}
		before, after := StringValue(loc["fix_before"]), StringValue(loc["fix_after"])
		if before != "" || after != "" {
			b.WriteString("\n  " + Dim().Render("Perbaikan:"))
			if before != "" {
				b.WriteString("\n  " + Col(Red).Render("- ") + Col(Red).Render(before))
			}
			if after != "" {
				b.WriteString("\n  " + Col(Green).Render("+ ") + Col(Green).Render(after))
			}
		}
	}
}
