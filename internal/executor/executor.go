package executor

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"time"

	mdriver "github.com/actiontech/sqle/sqle/driver"
	"github.com/actiontech/sqle/sqle/errors"

	"github.com/hashicorp/go-hclog"
	_ "github.com/jackc/pgx/v4/stdlib"
)

const (
	ConnectTimeOut = 5
	DialTimeOut    = 5 * time.Second
)

type Db interface {
	Close()
	Ping() error
	Exec(query string) (driver.Result, error)
	Transact(qs ...string) ([]driver.Result, error)
	Query(query string, args ...interface{}) ([]map[string]sql.NullString, error)
	Logger() hclog.Logger
}

type BaseConn struct {
	log  hclog.Logger
	host string
	port string
	user string
	db   *sql.DB
	conn *sql.Conn
}

func newConn(entry hclog.Logger, instance *mdriver.DSN, dbName string) (*BaseConn, error) {
	if dbName == "" { // todo remove
		dbName = "postgres"
	}
	var db *sql.DB
	var err error
	// refer: github.com/jackc/pgx/v4/stdlib/sql.go
	// urlExample := "postgres://username:password@host:port/database_name?connect_timeout=5"
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?connect_timeout=%d",
		instance.User, instance.Password, instance.Host, instance.Port, dbName, ConnectTimeOut)
	db, err = sql.Open("pgx", dsn)
	if err != nil {
		entry.Error(err.Error())
		return nil, errors.New(errors.ConnectRemoteDatabaseError, err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	entry.Info("connecting to", "host", instance.Host, "port", instance.Port)
	conn, err := db.Conn(context.Background())
	if err != nil {
		entry.Error(err.Error())
		return nil, errors.New(errors.ConnectRemoteDatabaseError, err)
	}
	entry.Info("connected to", "host", instance.Host, "port", instance.Port)
	return &BaseConn{
		log:  entry,
		host: instance.Host,
		port: instance.Port,
		user: instance.User,
		db:   db,
		conn: conn,
	}, nil
}

func (c *BaseConn) Close() {
	_ = c.conn.Close()
	_ = c.db.Close()
}

func (c *BaseConn) Ping() error {
	c.Logger().Info("ping", "host", c.host, "port", c.port)
	ctx, cancel := context.WithTimeout(context.Background(), DialTimeOut)
	defer cancel()
	err := c.conn.PingContext(ctx)
	if err != nil {
		c.Logger().Info("ping failed", "host", c.host, "port", c.port, "err", err)
	} else {
		c.Logger().Info("ping success", "host", c.host, "port", c.port)
	}
	return errors.New(errors.ConnectRemoteDatabaseError, err)
}

func (c *BaseConn) Exec(query string) (driver.Result, error) {
	result, err := c.conn.ExecContext(context.Background(), query)
	if err != nil {
		c.Logger().Error("exec sql failed", "host", c.host,
			"port", c.port,
			"user", c.user,
			"query", query,
			"err", err.Error())
	} else {
		c.Logger().Info("exec sql success", "host", c.host,
			"port", c.port,
			"user", c.user,
			"query", query)
	}
	c.Logger()
	return result, errors.New(errors.ConnectRemoteDatabaseError, err)
}

func (c *BaseConn) Transact(qs ...string) ([]driver.Result, error) {
	var err error
	var tx *sql.Tx
	var results []driver.Result
	c.Logger().Info("doing sql transact", "host", c.host, "port", c.port, "user", c.user)
	tx, err = c.conn.BeginTx(context.Background(), nil)
	if err != nil {
		return results, err
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			c.Logger().Error("rollback sql transact")
			panic(p)
		}
		if err != nil {
			tx.Rollback()
			c.Logger().Error("rollback sql transact")
			return
		}
		err = tx.Commit()
		if err != nil {
			c.Logger().Error("transact commit failed")
		} else {
			c.Logger().Info("done sql transact")
		}
	}()
	for _, query := range qs {
		var txResult driver.Result
		txResult, err = tx.Exec(query)
		if err != nil {
			c.Logger().Error("exec sql failed", "err", err, "query", query)
			return results, err
		} else {
			results = append(results, txResult)
			c.Logger().Info("exec sql success", "query", query)
		}
	}
	return results, nil
}

func (c *BaseConn) Query(query string, args ...interface{}) ([]map[string]sql.NullString, error) {
	rows, err := c.conn.QueryContext(context.Background(), query, args...)
	if err != nil {
		c.Logger().Error("query sql failed;", "host", c.host,
			"port", c.port,
			"user", c.user,
			"query", query,
			"err", err.Error(),
		)
		return nil, errors.New(errors.ConnectRemoteDatabaseError, err)
	} else {
		c.Logger().Info("query sql success;", "host", c.host,
			"port", c.port,
			"user", c.user,
			"query", query,
		)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		// unknown error
		c.Logger().Error(err.Error())
		return nil, err
	}
	result := make([]map[string]sql.NullString, 0)
	for rows.Next() {
		buf := make([]interface{}, len(columns))
		data := make([]sql.NullString, len(columns))
		for i := range buf {
			buf[i] = &data[i]
		}
		if err := rows.Scan(buf...); err != nil {
			c.Logger().Error(err.Error())
			return nil, err
		}
		value := make(map[string]sql.NullString, len(columns))
		for i := 0; i < len(columns); i++ {
			k := columns[i]
			v := data[i]
			value[k] = v
		}
		result = append(result, value)
	}
	return result, nil
}

func (c *BaseConn) Logger() hclog.Logger {
	return c.log
}

type Executor struct {
	Db Db
}

func NewExecutor(entry hclog.Logger, instance *mdriver.DSN, dbName string) (*Executor, error) {
	var executor = &Executor{}
	var conn Db
	var err error
	conn, err = newConn(entry, instance, dbName)
	if err != nil {
		return nil, err
	}
	executor.Db = conn
	return executor, nil
}

func Ping(entry hclog.Logger, instance *mdriver.DSN) error {
	conn, err := NewExecutor(entry, instance, "")
	if err != nil {
		return err
	}
	defer conn.Db.Close()
	return conn.Db.Ping()
}

func (c *Executor) ShowDatabases(ignoreSysDatabase bool) ([]string, error) {
	var query string
	if ignoreSysDatabase {
		query = "SELECT datname FROM pg_database WHERE datname NOT IN ('postgres', 'template1', 'template0');"
	} else {
		query = "SELECT datname FROM pg_database;"
	}
	result, err := c.Db.Query(query)
	if err != nil {
		return nil, err
	}
	dbs := make([]string, len(result))
	for n, v := range result {
		if len(v) != 1 {
			err := fmt.Errorf("show databases error, result not match")
			c.Db.Logger().Error(err.Error())
			return dbs, errors.New(errors.ConnectRemoteDatabaseError, err)
		}
		for _, db := range v {
			dbs[n] = db.String
			break
		}
	}
	return dbs, nil
}
