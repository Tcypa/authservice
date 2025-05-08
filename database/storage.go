package database

import (
	"authservice/internal"
	"context"
	"errors"
	"log"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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

type refreshToken struct {
	Guid      string
	TokenHash string
	UserAgent string
	IPAddress string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

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
	_, err := p.pool.Exec(context.Background(), `
        INSERT INTO refreshTokens (uguid, tokenHash, userAgent, ipAddress, issued, expires)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (uguid) DO UPDATE SET
            tokenHash = EXCLUDED.tokenHash,
            userAgent = EXCLUDED.userAgent,
            ipAddress = EXCLUDED.ipAddress,
            issued = EXCLUDED.issued,
            expires = EXCLUDED.expires;`,
		guid, tokenHash, userAgent, ipAddress, issued, issued.Add(internal.RefreshLifetime))
	if err != nil {
		log.Printf("error insert: %v,", err)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Printf("pg error: %s", pgErr.Message)
		} else {
			log.Printf("unknown pg error: %v", err)
		}
		return errors.New("server error")
	}
	return nil

}

func (p *PgStorage) Read(guid string) (refreshToken, error) {
	p.Mu.RLock()
	defer p.Mu.RUnlock()
	var token refreshToken
	err := p.pool.QueryRow(context.Background(), `
        SELECT uguid, tokenHash, userAgent, ipAddress, issued, expires
        FROM refreshTokens
        WHERE uguid = $1`, guid).Scan(
		&token.Guid, &token.TokenHash, &token.UserAgent, &token.IPAddress, &token.IssuedAt, &token.ExpiresAt)
	if err != nil {
		return refreshToken{}, errors.New("token not found")
	}
	return token, nil
}

func (p *PgStorage) Delete(guid string) error {
	p.Mu.Lock()
	defer p.Mu.Unlock()
	_, err := p.pool.Exec(context.Background(), "DELETE FROM refreshTokens WHERE uguid = $1", guid)
	if err != nil {
		return errors.New("server error")
	}
	return nil
}
