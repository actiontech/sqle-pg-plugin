package inspector

import (
	"context"
	"database/sql"
	_driver "database/sql/driver"
	"os"

	"github.com/actiontech/sqle-pg-plugin/internal/executor"
	pkgParser "github.com/actiontech/sqle-pg-plugin/pkg/parser"
	"github.com/actiontech/sqle/sqle/driver"
	"github.com/actiontech/sqle/sqle/model"
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

func (s *registererImpl) Rules() []*model.Rule {
	var allRules []*model.Rule
	for i := range RuleHandlers {
		RuleHandlers[i].Rule.DBType = pluginName
		allRules = append(allRules, &RuleHandlers[i].Rule)
	}
	return allRules
}

type driverImpl struct {
	cfg         *driver.Config
	l           hclog.Logger
	result      *driver.AuditResult
	currentRule model.Rule
	dbConn      *executor.Executor
	isConnected bool
}

func NewDriver(cfg *driver.Config) driver.Driver {
	return &driverImpl{
		l: hclog.New(&hclog.LoggerOptions{
			Level:      hclog.Trace,
			Output:     os.Stderr,
			JSONFormat: true,
		}),
		cfg:    cfg,
		result: driver.NewInspectResults(),
	}
}

func (i *driverImpl) Exec(ctx context.Context, query string) (_driver.Result, error) {
	if i.cfg.IsOfflineAudit {
		return nil, nil
	}

	conn, err := i.getDbConn()
	if err != nil {
		return nil, err
	}
	return conn.Db.Exec(query)
}

func (i *driverImpl) Tx(ctx context.Context, queries ...string) ([]_driver.Result, error) {
	if i.cfg.IsOfflineAudit {
		return nil, nil
	}
	conn, err := i.getDbConn()
	if err != nil {
		return nil, err
	}
	return conn.Db.Transact(queries...)
}

func (i *driverImpl) Query(ctx context.Context, query string, args ...interface{}) ([]map[string]sql.NullString, error) {
	if i.cfg.IsOfflineAudit {
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
	i.result = driver.NewInspectResults()
	nodes, err := pkgParser.ParseSQL(sql)
	if err != nil {
		return nil, err
	}

	for _, rule := range i.cfg.Rules {
		i.currentRule = *rule
		handler, ok := RuleHandlerMap[rule.Name]
		if !ok || handler.Func == nil {
			continue
		}
		if i.cfg.IsOfflineAudit && !handler.IsAllowOfflineRule(nodes[0]) {
			continue
		}
		if err := handler.Func(*rule, i, nodes[0]); err != nil {
			return nil, err
		}
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
	if i.cfg.IsOfflineAudit {
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
	if i.cfg.IsOfflineAudit {
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
	conn, err := executor.NewExecutor(i.l, i.cfg.Inst, i.cfg.Schema)
	if err == nil {
		i.isConnected = true
		i.dbConn = conn
	}
	return conn, err
}

func (i *driverImpl) isOfflineAudit() bool {
	return i.cfg.IsOfflineAudit
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
		return model.SQLTypeDDL

	case *parser.Node_SelectStmt,
		*parser.Node_FieldSelect,
		*parser.Node_InsertStmt,
		*parser.Node_UpdateStmt,
		*parser.Node_DeleteStmt,
		*parser.Node_CallStmt,
		*parser.Node_ExplainStmt:
		return model.SQLTypeDML
	}
	return ""
}
