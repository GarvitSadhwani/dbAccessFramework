package views

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
)

type Template struct {
	HTMLTpl *template.Template
}

func Must(t Template, err error) Template {
	if err != nil {
		fmt.Printf("error in template")
	}
	return t
}

func ParseFS(fs fs.FS, pattern ...string) (Template, error) {
	tpl, err := template.ParseFS(fs, pattern...)
	if err != nil {
		fmt.Printf("error parsing")
	}
	return Template{
		HTMLTpl: tpl,
	}, nil
}

func Parse(filepath string) (Template, error) {
	tpl, err := template.ParseFiles(filepath)
	if err != nil {
		fmt.Printf("Error parsing")
	}
	return Template{
		HTMLTpl: tpl,
	}, nil
}

func (t Template) Execute(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := t.HTMLTpl.Execute(w, data)
	if err != nil {
		fmt.Printf("error executing")
	}
}
