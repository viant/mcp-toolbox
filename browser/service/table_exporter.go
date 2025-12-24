package service

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

type tableExporter struct {
	parser *tableParser
}

func newTableExporter(htmlContent string) (*tableExporter, error) {
	p, err := newTableParser(htmlContent)
	if err != nil {
		return nil, err
	}
	return &tableExporter{parser: p}, nil
}

func (e *tableExporter) Export(headers []string, format string) (any, error) {
	data := e.parser.ParseTable()
	switch format {
	case "json":
		return e.exportJSON(headers, data)
	case "csv":
		return e.exportCSV(headers, data)
	case "objects":
		return e.exportObjects(headers, data), nil
	case "tabular":
		return data, nil
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

func (e *tableExporter) exportJSON(headers []string, data [][]string) (string, error) {
	if len(data) < 1 {
		return "[]", nil
	}
	objects := e.exportObjects(headers, data)
	b, err := json.MarshalIndent(objects, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (e *tableExporter) exportObjects(headers []string, data [][]string) []map[string]any {
	offset := 0
	if len(headers) == 0 {
		headers = data[0]
		offset++
	}
	var objects []map[string]any
	for _, row := range data[offset:] {
		if len(row) != len(headers) {
			continue
		}
		obj := map[string]any{}
		for i, h := range headers {
			if h == "" {
				continue
			}
			obj[h] = row[i]
		}
		objects = append(objects, obj)
	}
	return objects
}

func (e *tableExporter) exportCSV(headers []string, data [][]string) (string, error) {
	buf := new(bytes.Buffer)
	w := csv.NewWriter(buf)
	if err := w.Write(headers); err != nil {
		return "", err
	}
	for _, record := range data {
		if err := w.Write(record); err != nil {
			return "", err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

type tableParser struct {
	document *html.Node
}

func newTableParser(htmlContent string) (*tableParser, error) {
	if strings.HasPrefix(htmlContent, "<table") {
		htmlContent = "<html><body>" + htmlContent + "</body></html>"
	}
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}
	return &tableParser{document: doc}, nil
}

func (p *tableParser) ParseTable() [][]string {
	var tableRows [][]string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "tr" {
			row := p.parseTableRow(n)
			if len(row) > 0 {
				tableRows = append(tableRows, row)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(p.document)
	return tableRows
}

func (p *tableParser) parseTableRow(tr *html.Node) []string {
	var row []string
	for cell := tr.FirstChild; cell != nil; cell = cell.NextSibling {
		if cell.Type == html.ElementNode && cell.Data == "td" {
			row = append(row, p.extractText(cell))
		}
	}
	return row
}

func (p *tableParser) extractText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var buf bytes.Buffer
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		buf.WriteString(p.extractText(c))
	}
	return strings.TrimSpace(buf.String())
}
