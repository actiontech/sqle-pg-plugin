package parser

import (
	parser "github.com/pganalyze/pg_query_go/v2"
)

func Fingerprint(oneSql string) (fingerprint string, err error) {
	fingerprint, err = parser.Normalize(oneSql)
	if err != nil {
		return "", err
	}
	return
}

func ParseSQL(sql string) ([]*parser.RawStmt, error) {
	result, err := parser.Parse(sql)
	if err != nil {
		return nil, err
	}
	stmts := make([]*parser.RawStmt, 0, len(result.Stmts))
	for _, stmt := range result.Stmts {
		stmts = append(stmts, stmt)
	}
	return stmts, nil
}
