package inspector

import (
	"context"
	"database/sql"
	_driver "database/sql/driver"
	"fmt"
	"os"

	"github.com/actiontech/sqle/sqle/pkg/params"

	"github.com/actiontech/sqle-pg-plugin/internal/executor"
	pkgParser "github.com/actiontech/sqle-pg-plugin/pkg/parser"
	"github.com/actiontech/sqle/sqle/driver"
	"github.com/hashicorp/go-hclog"
	parser "github.com/pganalyze/pg_query_go/v2"
)

var pluginName = "PostgreSQL"

type registererImpl struct{}

func NewRegisterer() driver.Registerer {
	return &registererImpl{}
}

func (s *registererImpl) Name() string {
	return pluginName
}

func (s *registererImpl) Rules() []*driver.Rule {
	var allRules []*driver.Rule
	for i := range RuleHandlers {
		allRules = append(allRules, &RuleHandlers[i].Rule)
	}
	return allRules
}

func (s *registererImpl) AdditionalParams() params.Params {
	return nil
}

type driverImpl struct {
	cfg         *driver.Config
	l           hclog.Logger
	result      *driver.AuditResult
	currentRule driver.Rule
	dbConn      *executor.Executor
	isConnected bool
}

func NewDriver(cfg *driver.Config) driver.Driver {
	d := &driverImpl{
		l: hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Trace,
			Output:     os.Stderr,
			JSONFormat: true,
		}),
		cfg:    cfg,
		result: driver.NewInspectResults(),
	}

	d.l.Info("NewDriver", "cfg.Rule", cfg.Rules, "cfg.DSN", cfg.DSN, "cfg.Rule length", len(cfg.Rules))

	return d
}

func (i *driverImpl) Exec(ctx context.Context, query string) (_driver.Result, error) {
	if i.cfg.DSN == nil {
		return nil, nil
	}

	conn, err := i.getDbConn()
	if err != nil {
		return nil, err
	}
	return conn.Db.Exec(query)
}

func (i *driverImpl) Tx(ctx context.Context, queries ...string) ([]_driver.Result, error) {
	if i.cfg.DSN == nil {
		return nil, nil
	}
	conn, err := i.getDbConn()
	if err != nil {
		return nil, err
	}
	return conn.Db.Transact(queries...)
}

func (i *driverImpl) Query(ctx context.Context, query string, args ...interface{}) ([]map[string]sql.NullString, error) {
	if i.cfg.DSN == nil {
		return nil, nil
	}

	conn, err := i.getDbConn()
	if err != nil {
		return nil, err
	}
	return conn.Db.Query(query, args...)
}

func (i *driverImpl) Parse(ctx context.Context, sqlText string) ([]driver.Node, error) {
	nodes, err := pkgParser.ParseSQL(sqlText)
	if err != nil {
		return nil, err
	}

	ns := make([]driver.Node, 0, len(nodes))

	for _, n := range nodes {
		typ := sqlType(n.Stmt.GetNode())
		sqlText, _ := parser.Deparse(&parser.ParseResult{Stmts: []*parser.RawStmt{n}})
		fingerprint, err := pkgParser.Fingerprint(sqlText)
		if err != nil {
			return nil, err
		}
		ns = append(ns, driver.Node{Text: sqlText, Type: typ, Fingerprint: fingerprint})
	}
	return ns, nil
}

func (i *driverImpl) Audit(ctx context.Context, sql string) (*driver.AuditResult, error) {
	i.l.Info("Audit", "sql", sql)
	i.result = driver.NewInspectResults()
	nodes, err := pkgParser.ParseSQL(sql)
	if err != nil {
		return nil, err
	}

	for _, rule := range i.cfg.Rules {
		i.l.Info("Audit rule", "rule", rule.Name)
		i.currentRule = *rule
		handler, ok := RuleHandlerMap[rule.Name]
		if !ok || handler.Func == nil {
			continue
		}
		if i.cfg.DSN == nil && !handler.IsAllowOfflineRule(nodes[0]) {
			continue
		}
		i.l.Info("begin handler ")
		if err := handler.Func(*rule, i, nodes[0]); err != nil {
			return nil, err
		}

		i.l.Info("handle result", "result level", i.result.Level(), "result message", i.result.Message())
	}

	return i.result, nil
}

// todo
func (i *driverImpl) GenRollbackSQL(ctx context.Context, sql string) (string, string, error) {
	return "", "", nil
}

func (i *driverImpl) Close(ctx context.Context) {
	if i.isConnected {
		i.dbConn.Db.Close()
		i.isConnected = false
	}
}

func (i *driverImpl) Ping(ctx context.Context) error {
	if i.cfg.DSN == nil {
		return nil
	}
	conn, err := i.getDbConn()
	if err != nil {
		return err
	}
	return conn.Db.Ping()
}

// Schemas 此方法在pg返回的是所有database列表
func (i *driverImpl) Schemas(ctx context.Context) ([]string, error) {
	if i.cfg.DSN == nil {
		return nil, nil
	}
	conn, err := i.getDbConn()
	if err != nil {
		return nil, err
	}
	return conn.ShowDatabases(true)
}

func (i *driverImpl) addResult(ruleName string, args ...interface{}) {
	// if rule is not current rule, ignore save the message.
	if ruleName != i.currentRule.Name {
		return
	}

	level := i.currentRule.Level
	message := RuleHandlerMap[ruleName].Message
	i.result.Add(level, message, args...)
}

// getDbConn get db conn and just connect once.
func (i *driverImpl) getDbConn() (*executor.Executor, error) {
	if i.isConnected {
		return i.dbConn, nil
	}
	conn, err := executor.NewExecutor(i.l, i.cfg.DSN, i.cfg.DSN.DatabaseName)
	if err == nil {
		i.isConnected = true
		i.dbConn = conn
	}
	return conn, err
}

func (i *driverImpl) isOfflineAudit() bool {
	return i.cfg.DSN == nil
}

func (i *driverImpl) SetConfig(cfg *driver.Config) {
	i.cfg = cfg
	return
}

func sqlType(typ interface{}) string {
	switch typ.(type) {
	case *parser.Node_CreateStmt,
		*parser.Node_CreatedbStmt,
		*parser.Node_CreateRoleStmt,
		*parser.Node_CreateAmStmt,
		*parser.Node_DropStmt,
		*parser.Node_DropdbStmt,
		*parser.Node_DropRoleStmt,
		*parser.Node_DropTableSpaceStmt,
		*parser.Node_AlterDatabaseStmt,
		*parser.Node_TruncateStmt,
		*parser.Node_CommentStmt,
		*parser.Node_RenameStmt:
		return driver.SQLTypeDDL

	case *parser.Node_SelectStmt,
		*parser.Node_FieldSelect,
		*parser.Node_InsertStmt,
		*parser.Node_UpdateStmt,
		*parser.Node_DeleteStmt,
		*parser.Node_CallStmt,
		*parser.Node_ExplainStmt:
		return driver.SQLTypeDML
	}
	return ""
}

/*将抽象语法树还原为sql*/
func Deparse(node *parser.RawStmt) (out string, err error) {
	stmts := make([]*parser.RawStmt, 1)
	stmts[0] = node
	result := &parser.ParseResult{
		Version: 130003,
		Stmts:   stmts,
	}
	output, err := parser.Deparse(result)
	if err != nil {

		return "", err
	}
	return output, nil

}

/*检查函数是否有函数调用*/
func CheckJoinFunc(expr *parser.JoinExpr) bool {
	if expr.GetQuals() != nil {
		if expr.GetQuals().GetAExpr() != nil {
			aexper := expr.GetQuals().GetAExpr()
			if aexper.GetLexpr() != nil {
				if aexper.GetLexpr().GetFuncCall() != nil {
					return true
				}
			}
			if aexper.GetRexpr() != nil {
				if aexper.GetRexpr().GetFuncCall() != nil {
					return true
				}
			}
		} else if expr.GetQuals().GetBoolExpr() != nil {
			for _, args := range expr.GetQuals().GetBoolExpr().GetArgs() {
				aexper := args.GetAExpr()
				if aexper.GetLexpr() != nil {
					if aexper.GetLexpr().GetFuncCall() != nil {
						return true
					}
				}
				if aexper.GetRexpr() != nil {
					if aexper.GetRexpr().GetFuncCall() != nil {
						return true
					}
				}
			}
		}

	}

	res := false
	if expr.GetLarg() != nil && expr.GetLarg().GetJoinExpr() != nil {
		res = res || CheckJoinFunc(expr.GetLarg().GetJoinExpr())
	}
	if expr.GetRarg() != nil && expr.GetRarg().GetJoinExpr() != nil {
		res = res || CheckJoinFunc(expr.GetRarg().GetJoinExpr())
	}
	return res
}

/*获取表的字段和字段对应的值*/
func (i *driverImpl) GetDescTable(tablename string) (map[string]string, []string) {
	query := i.getQuery(tablename)
	fileds := make([]string, len(query))
	resMap := make(map[string]string, len(query))
	for _, m := range query {
		resMap[m["field"].String] = m["type"].String
		fileds = append(fileds, m["field"].String)

	}

	return resMap, fileds
}
func (i *driverImpl) getQuery(tablename string) []map[string]sql.NullString {
	query, _ := i.Query(context.Background(), fmt.Sprintf("SELECT a.attnum, a.attname AS field, t.typname AS type, a.attlen AS length, a.atttypmod AS lengthvar , a.attnotnull AS notnull, b.description AS comment FROM pg_class c, pg_attribute a LEFT JOIN pg_description b ON a.attrelid = b.objoid AND a.attnum = b.objsubid, pg_type t WHERE c.relname = '%s' AND a.attnum > 0 AND a.attrelid = c.oid AND a.atttypid = t.oid ORDER BY a.attnum;", tablename))
	return query
}
