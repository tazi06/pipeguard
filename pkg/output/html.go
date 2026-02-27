package output

import (
	"html/template"
	"io"
	"time"
)

type HTMLFomatter struct {
	writer io.Writer
}

// creates a new HTMLFomatter with the provided writer.
func NewHTMLFormatter(w io.Writer) *HTMLFomatter {
	return &HTMLFomatter{writer: w}
}

// generates an HTML report based on the provided results and writes it to the formatter's writer.
func (f *HTMLFomatter) FormatReport(results []FileResult) {
	tmpl := template.Must(template.New("report").Parse(htmlTemplate))

	data := struct {
		Timestamp string
		Results   []FileResult
	}{
		Timestamp: time.Now().Format(time.RFC1123),
		Results:   results,
	}
	_ = tmpl.Execute(f.writer, data)
}

// HTML template for displaying the report.
const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>PipeGuard Report</title>
<style>
body {
	font-family: Arial, sans-serif;
	background-color: #f4f6f8;
	padding: 20px;
}
h1 {
	color: #333;
}
table {
	border-collapse: collapse;
	width: 100%;
	margin-bottom: 30px;
	background: white;
}
th, td {
	border: 1px solid #ddd;
	padding: 8px;
	text-align: left;
}
th {
	background-color: #222;
	color: white;
}
.CRITICAL { color: #b00020; font-weight: bold; }
.HIGH { color: #e65100; font-weight: bold; }
.MEDIUM { color: #f9a825; }
.LOW { color: #2e7d32; }
.INFO { color: #1565c0; }
.file-header {
	margin-top: 30px;
	font-size: 18px;
	font-weight: bold;
}
</style>
</head>
<body>

<h1>PipeGuard Scan Report</h1>
<p><strong>Generated:</strong> {{ .Timestamp }}</p>

{{ range .Results }}
<div class="file-header">{{ .Path }} ({{ .FileType }})</div>

<table>
<tr>
<th>Severity</th>
<th>Rule ID</th>
<th>Description</th>
<th>Line</th>
<th>Content</th>
</tr>

{{ range .Violations }}
<tr>
<td class="{{ .Rule.Severity }}">{{ .Rule.Severity }}</td>
<td>{{ .Rule.ID }}</td>
<td>{{ .Rule.Description }}</td>
<td>{{ .Line }}</td>
<td>{{ .Content }}</td>
</tr>
{{ end }}

</table>
{{ end }}

</body>
</html>
`
