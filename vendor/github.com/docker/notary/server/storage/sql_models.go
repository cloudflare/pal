package storage

import (
	"time"

	"github.com/jinzhu/gorm"
)

const (
	changeCategoryUpdate   = "update"
	changeCategoryDeletion = "deletion"
)

// TUFFile represents a TUF file in the database
type TUFFile struct {
	gorm.Model
	Gun     string `sql:"type:varchar(255);not null"`
	Role    string `sql:"type:varchar(255);not null"`
	Version int    `sql:"not null"`
	Sha256  string `sql:"type:varchar(64);"`
	Data    []byte `sql:"type:longblob;not null"`
}

// TableName sets a specific table name for TUFFile
func (g TUFFile) TableName() string {
	return "tuf_files"
}

// Change defines the the fields required for an object in the changefeed
type Change struct {
	ID        uint `gorm:"primary_key" sql:"not null" json:",string"`
	CreatedAt time.Time
	GUN       string `gorm:"column:gun" sql:"type:varchar(255);not null"`
	Version   int    `sql:"not null"`
	SHA256    string `gorm:"column:sha256" sql:"type:varchar(64);"`
	Category  string `sql:"type:varchar(20);not null;"`
}

// TableName sets a specific table name for Changefeed
func (c Change) TableName() string {
	return "changefeed"
}

// CreateTUFTable creates the DB table for TUFFile
func CreateTUFTable(db gorm.DB) error {
	// TODO: gorm
	query := db.Set("gorm:table_options", "ENGINE=InnoDB DEFAULT CHARSET=utf8").CreateTable(&TUFFile{})
	if query.Error != nil {
		return query.Error
	}
	query = db.Model(&TUFFile{}).AddUniqueIndex(
		"idx_gun", "gun", "role", "version")
	return query.Error
}

// CreateChangefeedTable creates the DB table for Changefeed
func CreateChangefeedTable(db gorm.DB) error {
	query := db.Set("gorm:table_options", "ENGINE=InnoDB DEFAULT CHARSET=utf8").CreateTable(&Change{})
	return query.Error
}
