package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strconv"

	semver "github.com/Masterminds/semver/v3"
)

func bumpVersion(fileName, varName, part string) error {
	absPath, err := filepath.Abs(fileName)
	if err != nil {
		return fmt.Errorf("unable to get absolute path: %v", err)
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, absPath, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("could not parse file: %w", err)
	}

	ast.Inspect(node, func(n ast.Node) bool {
		if v, ok := n.(*ast.GenDecl); ok {
			for _, spec := range v.Specs {
				if s, ok := spec.(*ast.ValueSpec); ok {
					for idx, id := range s.Names {
						if id.Name == varName {
							versionStr, _ := strconv.Unquote(s.Values[idx].(*ast.BasicLit).Value)
							v, err := semver.NewVersion(versionStr)
							if err != nil {
								return false
							}
							var vInc func() semver.Version
							switch part {
							case "major":
								vInc = v.IncMajor
							case "minor":
								vInc = v.IncMinor
							case "", "patch":
								vInc = v.IncPatch
							default:
								return false
							}
							s.Values[idx].(*ast.BasicLit).Value = fmt.Sprintf("`v%s`", vInc().String())
							return false
						}
					}
				}
			}
		}
		return true
	})

	f, err := os.OpenFile(fileName, os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}
	defer f.Close()

	if err := printer.Fprint(f, fset, node); err != nil {
		return fmt.Errorf("could not write to file: %w", err)
	}

	return nil
}

func main() {
	var (
		fileName string
		varName  string
		part     string
	)

	flag.StringVar(&fileName, "file", "", "Go source file to parse")
	flag.StringVar(&varName, "var", "", "Variable to update")
	flag.StringVar(&part, "part", "patch", "Version part to increment (major, minor, patch)")

	flag.Parse()

	if fileName == "" || varName == "" {
		fmt.Println("Error: Both -file and -var are required")
		os.Exit(1)
	}
	err := bumpVersion(fileName, varName, part)
	if err != nil {
		fmt.Printf("Error bumping version: %v\n", err)
		os.Exit(1)
	}
}
