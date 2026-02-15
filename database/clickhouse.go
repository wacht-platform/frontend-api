package database

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

var ClickHouseClient clickhouse.Conn

func InitClickHouseConnection() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr:     []string{os.Getenv("CLICKHOUSE_HOST")},
		Protocol: clickhouse.HTTP,
		Auth: clickhouse.Auth{
			Database: "wacht",
			Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		},
		TLS: &tls.Config{
			InsecureSkipVerify: false,
		},
	})
	if err != nil {
		return err
	}

	if err := conn.Ping(context.Background()); err != nil {
		return err
	}

	if err := conn.Ping(ctx); err != nil {
		return fmt.Errorf("failed to ping clickhouse: %w", err)
	}

	ClickHouseClient = conn

	return nil
}
