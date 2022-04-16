package adapter

import (
	"context"
	"fmt"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/errors/gerror"
)

type Adapter struct {
	DB        gdb.DB
	TableName string
	Ctx       context.Context
}

func (a *Adapter) LoadPolicy(model model.Model) error {
	var lines []*casBinRule

	if err := a.DB.Ctx(a.Ctx).Model(a.TableName).Scan(&lines); err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}

	return nil
}

func (a *Adapter) SavePolicy(model model.Model) error {
	err := a.dropTable()
	if err != nil {
		return err
	}
	err = a.createTable()
	if err != nil {
		return err
	}

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			_, err := a.DB.Ctx(a.Ctx).Model(a.TableName).Data(&line).Insert()
			if err != nil {
				return err
			}
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			_, err := a.DB.Ctx(a.Ctx).Model(a.TableName).Data(&line).Insert()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	_, err := a.DB.Ctx(a.Ctx).Model(a.TableName).Data(&line).Insert()
	return err
}

func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	err := rawDelete(a, line)
	return err
}

func rawDelete(a *Adapter, line casBinRule) error {
	db := a.DB.Model(a.TableName)

	db.Where("ptype = ?", line.PType)
	if line.V0 != "" {
		db.Where("v0 = ?", line.V0)
	}
	if line.V1 != "" {
		db.Where("v1 = ?", line.V1)
	}
	if line.V2 != "" {
		db.Where("v2 = ?", line.V2)
	}
	if line.V3 != "" {
		db.Where("v3 = ?", line.V3)
	}
	if line.V4 != "" {
		db.Where("v4 = ?", line.V4)
	}
	if line.V5 != "" {
		db.Where("v5 = ?", line.V5)
	}

	_, err := db.Delete()
	return err
}

func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line := casBinRule{}

	line.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}
	err := rawDelete(a, line)
	return err
}

func New(db gdb.DB) (*Adapter, error) {
	if db == nil {
		return nil, gerror.New("db未初始化")
	}
	a := new(Adapter)
	a.TableName = "casbin_rule"
	a.DB = db
	a.Ctx = context.Background()
	if err := a.createTable(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Adapter) createTable() error {
	//PostgreSql 语句
	_, err := a.DB.Exec(a.Ctx, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (ptype VARCHAR(10), v0 VARCHAR(256), v1 VARCHAR(256), v2 VARCHAR(256), v3 VARCHAR(256), v4 VARCHAR(256), v5 VARCHAR(256))", a.TableName))
	return err
}

func (a *Adapter) dropTable() error {
	_, err := a.DB.Exec(a.Ctx, fmt.Sprintf("DROP TABLE %s", a.TableName))
	return err
}

type casBinRule struct {
	PType string `json:"ptype"`
	V0    string `json:"v0"`
	V1    string `json:"v1"`
	V2    string `json:"v2"`
	V3    string `json:"v3"`
	V4    string `json:"v4"`
	V5    string `json:"v5"`
}

func loadPolicyLine(line *casBinRule, model model.Model) {
	lineText := line.PType
	if line.V0 != "" {
		lineText += ", " + line.V0
	}
	if line.V1 != "" {
		lineText += ", " + line.V1
	}
	if line.V2 != "" {
		lineText += ", " + line.V2
	}
	if line.V3 != "" {
		lineText += ", " + line.V3
	}
	if line.V4 != "" {
		lineText += ", " + line.V4
	}
	if line.V5 != "" {
		lineText += ", " + line.V5
	}
	persist.LoadPolicyLine(lineText, model)
}

func savePolicyLine(ptype string, rule []string) casBinRule {
	line := casBinRule{}

	line.PType = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}
