package inspector

import (
	"reflect"

	"github.com/actiontech/sqle/sqle/model"
	parser "github.com/pganalyze/pg_query_go/v2"
)

const (
	RuleTypeDMLConvention = "DML规范"
)

const (
	DMLDisableSelectAllColumn = "dml_disable_select_all_column"
)

type RuleHandler struct {
	Rule                 model.Rule
	Message              string
	Func                 func(model.Rule, *driverImpl, *parser.RawStmt) error
	AllowOffline         bool
	NotAllowOfflineStmts []interface{}
}

func (rh *RuleHandler) IsAllowOfflineRule(node *parser.RawStmt) bool {
	if !rh.AllowOffline {
		return false
	}
	for _, stmt := range rh.NotAllowOfflineStmts {
		if reflect.TypeOf(stmt).Kind() == reflect.TypeOf(node.GetStmt().GetNode()).Kind() {
			return false
		}
	}
	return true
}

var (
	RuleHandlerMap = map[string]RuleHandler{}
)

func init() {
	for _, rh := range RuleHandlers {
		RuleHandlerMap[rh.Rule.Name] = rh
	}
}

var RuleHandlers = []RuleHandler{
	{
		Rule: model.Rule{
			Name:      DMLDisableSelectAllColumn,
			Desc:      "不建议使用select *",
			Level:     model.RuleLevelNotice,
			Typ:       RuleTypeDMLConvention,
			IsDefault: true,
		},
		Message:              "不建议使用select *",
		Func:                 checkSelectAll,
		AllowOffline:         true,
		NotAllowOfflineStmts: nil,
		// example: NotAllowOfflineStmts: []interface{}{&parser.Node_SelectStmt{}},
	},
}

func checkSelectAll(rule model.Rule, i *driverImpl, node *parser.RawStmt) error {
	switch stmt := node.GetStmt().GetNode().(type) {
	case *parser.Node_SelectStmt:
		// check select all column
		for _, target := range stmt.SelectStmt.GetTargetList() {
			column, ok := target.GetResTarget().GetVal().GetNode().(*parser.Node_ColumnRef)
			if !ok {
				continue
			}
			for _, filed := range column.ColumnRef.GetFields() {
				_, ok = filed.GetNode().(*parser.Node_AStar)
				if ok {
					i.addResult(DMLDisableSelectAllColumn)
				}
			}
		}
	}
	return nil
}
