package inspector

import (
	"fmt"
	"github.com/actiontech/sqle/sqle/driver"
	parser "github.com/pganalyze/pg_query_go/v2"
	"log"
	"os"
	"reflect"
)

const (
	RuleTypeGlobalConfig       = "全局配置"
	RuleTypeNamingConvention   = "命名规范"
	RuleTypeIndexingConvention = "索引规范"
	RuleTypeDDLConvention      = "DDL规范"
	RuleTypeDMLConvention      = "DML规范"
	RuleTypeDQLConvention      = "DML规范"
	RuleTypeUsageSuggestion    = "使用建议"
	RuleTypeIndexOptimization  = "索引优化"
)
const (
	DMLCheckLeftJoinWhereColIsNull = "dml_checl_left_join_where_col_is_null"
	DMLCheckJoinCondition          = "dml_check_join_condition"
	DMLDisableSelectAllColumn      = "dml_disable_select_all_column"
	DMLCheckCreateTmpTable         = "dml_check_create_tmp_table"
	DMLNotUseCalculations          = "dml_not_use_calculations"
)

// inspector DDL rules

type RuleHandler struct {
	Rule                 driver.Rule
	Message              string
	Func                 func(driver.Rule, *driverImpl, *parser.RawStmt) error
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
	log.SetPrefix("[sqle-pg-logs]")
	logFile, err := os.OpenFile("/opt/sqle/logs/pgsql_logs.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("open log filed,err", err)
		return
	}
	log.SetOutput(logFile)
	log.SetFlags(log.Llongfile | log.Lmicroseconds | log.Ldate)
}

var RuleHandlers = []RuleHandler{
	{
		Rule: driver.Rule{
			Name:     DMLDisableSelectAllColumn,
			Desc:     "不建议使用select *",
			Level:    driver.RuleLevelError,
			Category: RuleTypeDMLConvention,
		},
		Message:              "不建议使用select *",
		Func:                 checkSelectAll,
		AllowOffline:         true,
		NotAllowOfflineStmts: nil,
		// example: NotAllowOfflineStmts: []interface{}{&parser.Node_SelectStmt{}},
	},
	{
		Rule: driver.Rule{
			Name:     DMLCheckJoinCondition,
			Desc:     "关联条件不允许有函数操作,用临时表或者子查询处理",
			Level:    driver.RuleLevelError,
			Category: RuleTypeDMLConvention,
		},
		Message:              "关联条件不允许有函数操作,用临时表或者子查询处理",
		Func:                 checkJoinCondition,
		AllowOffline:         true,
		NotAllowOfflineStmts: nil,
	},
	{
		Rule: driver.Rule{
			Name:     DMLCheckLeftJoinWhereColIsNull,
			Desc:     "强制要求使用内关联代替左关联在WHERE条件限制从表字段是非空的方式",
			Level:    driver.RuleLevelWarn,
			Category: RuleTypeDMLConvention,
		},
		Message:              "强制要求使用内关联代替左关联在WHERE条件限制从表字段是非空的方式",
		Func:                 checkLeftJoinWhereCondition,
		AllowOffline:         true,
		NotAllowOfflineStmts: nil,
	},
	{
		Rule: driver.Rule{
			Name:     DMLCheckCreateTmpTable,
			Desc:     "临时表定义时应指定选项\"WITH (appendonly=true,compresstype=zstd, compresslevel=5,orientation=column) ON COMMIT PRESERVE ROWS DISTRIBUTED BY (\"+分布键+\");\"",
			Level:    driver.RuleLevelWarn,
			Category: RuleTypeDMLConvention,
		},
		Message:              "临时表定义时应指定选项\"WITH (appendonly=true,compresstype=zstd, compresslevel=5,orientation=column) ON COMMIT PRESERVE ROWS DISTRIBUTED BY (\"+分布键+\");\"",
		Func:                 checkCreateTmpTable,
		AllowOffline:         true,
		NotAllowOfflineStmts: nil,
	},
	{
		Rule: driver.Rule{
			Name:     DMLNotUseCalculations,
			Desc:     "对于字段判断在某个条件范围内，代码使用数值判断，不使用计算公式，使用公式的结果值，提高性能，且要在注释中说明",
			Level:    driver.RuleLevelNotice,
			Category: RuleTypeDMLConvention,
		},
		Message:              "对于字段判断在某个条件范围内，代码使用数值判断，不使用计算公式，使用公式的结果值，提高性能，且要在注释中说明",
		Func:                 checkNotUseCalculations,
		AllowOffline:         true,
		NotAllowOfflineStmts: nil,
	},
}

func checkNotUseCalculations(rule driver.Rule, i *driverImpl, node *parser.RawStmt) error {
	switch stmt := node.GetStmt().GetNode().(type) {
	case *parser.Node_SelectStmt:
		sel := stmt.SelectStmt
		if sel.GetWhereClause() != nil {
			if sel.GetWhereClause().GetBoolExpr() != nil {
				//多个条件关联的情况,同样是判断每个条件的右边有没有计算表达式
				for _, arg := range sel.GetWhereClause().GetBoolExpr().GetArgs() {
					rexpr := arg.GetAExpr().GetRexpr()
					if rexpr.GetAExpr() != nil {
						if rexpr.GetAExpr().GetLexpr() != nil && rexpr.GetAExpr().GetRexpr() != nil {
							i.addResult(rule.Name)
						}
					}
				}
			} else if sel.GetWhereClause().GetAExpr() != nil {
				//只有一个条件的情况
				if sel.GetWhereClause().GetAExpr().GetRexpr().GetAExpr() != nil {
					//看右边的条件有没有计算表达式
					i.addResult(rule.Name)
				}
			}
		}
		if sel.GetHavingClause() != nil {
			aexpr := sel.GetHavingClause().GetAExpr()
			if aexpr.GetLexpr() != nil {
				if aexpr.GetLexpr().GetAExpr() != nil {
					i.addResult(rule.Name)
					return nil
				}
			}
			if aexpr.GetRexpr() != nil {
				if aexpr.GetRexpr().GetAExpr() != nil {
					i.addResult(rule.Name)
					return nil
				}

			}

		}
	case *parser.Node_InsertStmt:
		if stmt.InsertStmt.GetSelectStmt() != nil {
			selectStmt := stmt.InsertStmt.GetSelectStmt().GetSelectStmt()
			if selectStmt != nil {
				if selectStmt.GetWhereClause() != nil {
					if selectStmt.GetWhereClause().GetBoolExpr() != nil {
						//多个条件关联的情况,同样是判断每个条件的右边有没有计算表达式
						for _, arg := range selectStmt.GetWhereClause().GetBoolExpr().GetArgs() {
							rexpr := arg.GetAExpr().GetRexpr()
							if rexpr.GetAExpr() != nil {
								if rexpr.GetAExpr().GetLexpr() != nil && rexpr.GetAExpr().GetRexpr() != nil {
									i.addResult(rule.Name)
								}
							}
						}
					} else if selectStmt.GetWhereClause().GetAExpr() != nil {
						//只有一个条件的情况
						if selectStmt.GetWhereClause().GetAExpr().GetRexpr().GetAExpr() != nil {
							//看右边的条件有没有计算表达式
							i.addResult(rule.Name)
						}
					}
				}
				if selectStmt.GetHavingClause() != nil {
					aexpr := selectStmt.GetHavingClause().GetAExpr()
					if aexpr.GetLexpr() != nil {
						if aexpr.GetLexpr().GetAExpr() != nil {
							i.addResult(rule.Name)
							return nil
						}
					}
					if aexpr.GetRexpr() != nil {
						if aexpr.GetRexpr().GetAExpr() != nil {
							i.addResult(rule.Name)
							return nil
						}

					}

				}

			}
		}

	}
	return nil
}
func checkCreateTmpTable(rule driver.Rule, i *driverImpl, node *parser.RawStmt) error {
	switch stmt := node.GetStmt().GetNode().(type) {
	case *parser.Node_CreateStmt:
		relation := stmt.CreateStmt.GetRelation()
		//建表语句解析器有标记临时表的类型,但是这边使用的临时表有可能是正式表,用shell开头来标记
		if relation.GetRelpersistence() == "t" || relation.GetSchemaname() == "shell" {
			if len(stmt.CreateStmt.GetOptions()) == 0 {
				i.addResult(rule.Name)
			}
		}
	}
	return nil
}
func checkLeftJoinWhereCondition(rule driver.Rule, i *driverImpl, node *parser.RawStmt) error {
	switch stmt := node.GetStmt().GetNode().(type) {
	case *parser.Node_SelectStmt:
		if stmt.SelectStmt.GetWhereClause() != nil {
			nulltest := stmt.SelectStmt.GetWhereClause().GetNullTest()
			bool_expr := stmt.SelectStmt.GetWhereClause().GetBoolExpr()
			ch := make(chan string, 20)

			for _, fromcl := range stmt.SelectStmt.GetFromClause() {
				if fromcl.GetJoinExpr() != nil {
					checkLeftJoinType(fromcl.GetJoinExpr(), &ch)
				}
			}
			close(ch)

			if nulltest == nil && bool_expr == nil {
				return nil
			} else if nulltest != nil {
				if nulltest.GetNulltesttype().String() == "IS_NOT_NULL" {
					tbname := ""
					for _, curfield := range nulltest.GetArg().GetColumnRef().GetFields() {
						tbname = curfield.GetString_().GetStr()
						break
					}
					if tbname == <-ch {
						i.addResult(rule.Name)
						return nil
					}

					return nil
				}
			} else {
				args := bool_expr.GetArgs()
				flag := false
				myset := make(map[string]string, 20)
				for _, arg := range args {
					argNullTest := arg.GetNullTest()
					if argNullTest != nil && argNullTest.GetNulltesttype().String() == "IS_NOT_NULL" {
						flag = true
						for _, f1 := range arg.GetColumnRef().GetFields() {
							//添加所有is not null 判断的表名到set中

							myset[f1.GetString_().GetStr()] = ""
							break
						}
					}
				}
				if flag {
					for cur := range ch {
						_, ok := myset[cur]
						if ok {
							i.addResult(rule.Name)
							return nil
						}
					}
				}
			}
		}
	case *parser.Node_InsertStmt:
		if stmt.InsertStmt.GetSelectStmt() != nil {
			selectStmt := stmt.InsertStmt.GetSelectStmt().GetSelectStmt()
			if selectStmt.GetWhereClause() != nil {
				nulltest := selectStmt.GetWhereClause().GetNullTest()
				bool_expr := selectStmt.GetWhereClause().GetBoolExpr()
				ch := make(chan string, 20)

				for _, fromcl := range selectStmt.GetFromClause() {
					if fromcl.GetJoinExpr() != nil {
						checkLeftJoinType(fromcl.GetJoinExpr(), &ch)
					}
				}
				close(ch)

				if nulltest == nil && bool_expr == nil {
					return nil
				} else if nulltest != nil {
					if nulltest.GetNulltesttype().String() == "IS_NOT_NULL" {
						tbname := ""
						for _, curfield := range nulltest.GetArg().GetColumnRef().GetFields() {
							tbname = curfield.GetString_().GetStr()
							log.Printf("tbname====>" + tbname)
							break
						}
						if tbname == <-ch {
							i.addResult(rule.Name)
							return nil
						}

						return nil
					}
				} else {
					args := bool_expr.GetArgs()
					flag := false
					myset := make(map[string]string, 20)
					for _, arg := range args {
						argNullTest := arg.GetNullTest()
						if argNullTest != nil && argNullTest.GetNulltesttype().String() == "IS_NOT_NULL" {
							flag = true
							for _, f1 := range arg.GetNullTest().GetArg().GetColumnRef().GetFields() {
								//添加所有is not null 判断的表名到set中
								log.Printf("map key ============>" + f1.GetString_().GetStr())
								myset[f1.GetString_().GetStr()] = ""
								break
							}
						}
					}
					if flag {
						for cur := range ch {
							log.Printf("map key is exits ? ---->" + cur)
							_, ok := myset[cur]
							if ok {
								i.addResult(rule.Name)
								return nil
							}
						}
					}
				}
			}
		}
	}

	return nil
}
func checkSelectAll(rule driver.Rule, i *driverImpl, node *parser.RawStmt) error {

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
					i.addResult(rule.Name)

				}
			}
		}
	case *parser.Node_InsertStmt:
		if stmt.InsertStmt.GetSelectStmt() != nil {
			selectStmt := stmt.InsertStmt.GetSelectStmt().GetSelectStmt()
			for _, target := range selectStmt.GetTargetList() {
				column, ok := target.GetResTarget().GetVal().GetNode().(*parser.Node_ColumnRef)
				if !ok {
					continue
				}
				for _, filed := range column.ColumnRef.GetFields() {
					_, ok = filed.GetNode().(*parser.Node_AStar)
					if ok {
						i.addResult(rule.Name)

					}
				}
			}
		}

	}

	return nil
}
func checkJoinCondition(rule driver.Rule, i *driverImpl, node *parser.RawStmt) error {
	switch stmt := node.GetStmt().GetNode().(type) {
	case *parser.Node_SelectStmt:
		if stmt.SelectStmt.GetFromClause() != nil {
			for _, cur := range stmt.SelectStmt.GetFromClause() {
				if cur.GetJoinExpr() != nil {
					res := CheckJoinFunc(cur.GetJoinExpr())
					if res {
						i.addResult(rule.Name)
					}
				}
			}
		}
	case *parser.Node_InsertStmt:
		if stmt.InsertStmt.GetSelectStmt() != nil {
			selectStmt := stmt.InsertStmt.GetSelectStmt().GetSelectStmt()
			if selectStmt != nil {
				if selectStmt.GetFromClause() != nil {
					for _, cur := range selectStmt.GetFromClause() {
						if cur.GetJoinExpr() != nil {
							res := CheckJoinFunc(cur.GetJoinExpr())
							if res {
								i.addResult(rule.Name)
							}
						}
					}
				}
			}
		}

	}

	return nil
}
func checkLeftJoinType(expr *parser.JoinExpr, ch *chan string) {
	if expr.GetJointype() != parser.JoinType_JOIN_LEFT {
		return
	}

	if expr.GetLarg() != nil && expr.GetLarg().GetJoinExpr() != nil {
		checkLeftJoinType(expr.GetLarg().GetJoinExpr(), ch)
	}
	if expr.GetRarg() != nil {
		if expr.GetRarg().GetRangeVar() == nil || expr.GetRarg().GetRangeVar().GetAlias() == nil {
			return
		}
		b := expr.GetRarg().GetRangeVar().GetAlias().GetAliasname()
		log.Printf("checkLeftJoinType   ====>        " + b)
		*ch <- b
	}
	return

}
