package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/actiontech/sqle/sqle/driver"
	adaptor "github.com/actiontech/sqle/sqle/pkg/driver"
	parser "github.com/pganalyze/pg_query_go/v2"
	"github.com/pkg/errors"
)

var version string

var printVersion = flag.Bool("version", false, "Print version & exit")

func main() {
	flag.Parse()

	if *printVersion {
		fmt.Println(version)
		return
	}

	plugin := adaptor.NewAdaptor(&adaptor.PostgresDialector{})

	aviodSelectAllColumn := &driver.Rule{
		Name:     "aviod_select_all_column",
		Desc:     "避免查询所有的列",
		Category: "DQL规范",
		Level:    driver.RuleLevelError,
	}

	aviodSelectAllColumnHandler := func(ctx context.Context, rule *driver.Rule, ast interface{}) (string, error) {
		node, ok := ast.(*parser.RawStmt)
		if !ok {
			return "", errors.New("ast is not *parser.RawStmt")
		}

		switch stmt := node.GetStmt().GetNode().(type) {
		case *parser.Node_SelectStmt:
			for _, target := range stmt.SelectStmt.GetTargetList() {
				column, ok := target.GetResTarget().GetVal().GetNode().(*parser.Node_ColumnRef)
				if !ok {
					continue
				}
				for _, filed := range column.ColumnRef.GetFields() {
					_, ok = filed.GetNode().(*parser.Node_AStar)
					if ok {
						return rule.Desc, nil
					}
				}
			}
		}
		return "", nil
	}

	plugin.AddRuleWithSQLParser(aviodSelectAllColumn, aviodSelectAllColumnHandler)
	plugin.Serve(adaptor.WithSQLParser(func(sql string) (ast interface{}, err error) {
		result, err := parser.Parse(sql)
		if err != nil {
			return nil, errors.Wrap(err, "parse sql error")
		}
		if len(result.Stmts) != 1 {
			return nil, fmt.Errorf("unexpected statement count: %d", len(result.Stmts))
		}
		return result.Stmts[0], nil
	}))
}
