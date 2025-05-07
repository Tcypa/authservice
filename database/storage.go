package database

import (
	"authservice/internal"
	"context"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PgStorage struct {
	Mu   sync.RWMutex
	pool *pgxpool.Pool
}

var (
	storage  *PgStorage
	initOnce sync.Once
	initErr  error
)

func Init(ctx context.Context) (*PgStorage, error) {
	initOnce.Do(func() {
		pool, err := pgxpool.New(ctx, os.Getenv("postgresURL"))
		if err != nil {
			initErr = err
			log.Fatalf("Unable to connect to database: %v", err)
			return
		}
		log.Println("pg connect success")
		storage = &PgStorage{pool: pool}
	})
	return storage, initErr
}

func GetStorage() *PgStorage {
	if storage == nil {
		log.Fatal("call database.Init first")
	}
	return storage
}

func (p *PgStorage) Close() {
	if p.pool != nil {
		p.pool.Close()
		log.Println("db connection closed")
	}
}

func (p *PgStorage) Insert(guid string, tokenHash string, userAgent string, ipAddress string, issued time.Time) error {

	p.Mu.Lock()
	defer p.Mu.Unlock()
	var exists bool
	var err error
	err = p.pool.QueryRow(context.Background(), "SELECT EXISTS (SELECT 1 FROM refreshTokens WHERE uguid = $1)", guid).Scan(&exists)
	if err != nil {
		return err
	}
	if exists == true {
		var dbAnswer string
		err = p.pool.QueryRow(context.Background(), "INSERT INTO UrlShorter (uguid, tokenHash, userAgent, ipAddress, issued_at, expires_at)"+
			"VALUES ($1, $2, $3, $4, $5, $6)", guid, tokenHash, userAgent, ipAddress, issued, issued.Add(internal.RefreshLifetime)).Scan(&dbAnswer)
		return err
	} else {
		return errors.New("")
	}
}

func (p *PgStorage) Read(shortUrl string) (string, error) {
	p.Mu.Lock()
	defer p.Mu.Unlock()
	var origUrl string
	err := p.pool.QueryRow(context.Background(), "SELECT origUrl FROM UrlShorter WHERE shortUrl = $1", shortUrl).Scan(&origUrl)
	if err != nil {
		return "", errors.New("short URL not found")
	}
	return origUrl, nil
}
