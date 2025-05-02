package database

import (
	"context"
	"log"
	"os"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PgStorage struct {
	Mu   sync.RWMutex
	Pool *pgxpool.Pool
}

func Init(ctx context.Context) *PgStorage {
	var err error
	pool, err := pgxpool.New(ctx, os.Getenv("postgresURL"))
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}

	log.Println("Postgres сonnect success")
	return &PgStorage{Pool: pool}
}
func (p *PgStorage) Close() {
	if p.Pool != nil {
		p.Pool.Close()
		log.Println("Database connect closed")
	}
}
