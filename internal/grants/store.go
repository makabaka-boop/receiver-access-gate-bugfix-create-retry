// Package grants implements the receiver access gate: a PostgreSQL-backed
// grant store and the HTTP API shared by any number of API processes.
package grants

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	ModeShared    = "SHARED"
	ModeExclusive = "EXCLUSIVE"

	StatusActive   = "ACTIVE"
	StatusReleased = "RELEASED"
	// StatusUpgradePending marks a shared grant whose owner has requested
	// an in-place upgrade to exclusive. While any grant on a receiver is
	// in this state, new SHARED and EXCLUSIVE requests for that receiver
	// are refused; the pending grant is promoted to ACTIVE EXCLUSIVE by
	// the release that removes its last competitor.
	StatusUpgradePending = "UPGRADE_PENDING"
)

var (
	// ErrBusy reports a conflicting active grant on the receiver. The
	// transaction that produced it is always rolled back, so a busy
	// attempt never leaves a record behind.
	ErrBusy = errors.New("busy")
	// ErrForbidden reports an owner-token mismatch. Nothing is modified.
	ErrForbidden = errors.New("forbidden")
	// ErrNotFound reports an unknown grant identifier.
	ErrNotFound = errors.New("not found")
	// ErrReleased reports an upgrade attempt on an already released
	// grant. Nothing is modified.
	ErrReleased = errors.New("released")
	// ErrNotShared reports an upgrade attempt on a grant that is not an
	// active shared grant (a natively exclusive grant). Nothing is
	// modified.
	ErrNotShared = errors.New("not shared")
	// ErrUpgradePending reports that another grant on the receiver is
	// already waiting for promotion. At most one pending upgrade exists
	// per receiver; the losing attempt changes nothing.
	ErrUpgradePending = errors.New("upgrade pending")
)

// Grant is the public view of one access grant. It never carries the owner
// token or its digest.
type Grant struct {
	ID       string `json:"grant_id"`
	Receiver string `json:"receiver"`
	Mode     string `json:"mode"`
	Status   string `json:"status"`
}

// Store persists grants in PostgreSQL. All mutating operations run inside
// a single transaction that first takes a per-receiver advisory lock, so
// the conflict check and the write are atomic across every API process
// connected to the same database.
type Store struct {
	pool *pgxpool.Pool
}

// migrateLockID serializes schema setup between concurrently starting
// API processes.
const migrateLockID int64 = 0x67616E7467617465 // "grantgate"

func NewStore(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) migrate(ctx context.Context) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrateLockID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
CREATE TABLE IF NOT EXISTS grants (
    seq          BIGSERIAL PRIMARY KEY,
    id           TEXT        NOT NULL UNIQUE,
    receiver     TEXT        NOT NULL,
    mode         TEXT        NOT NULL CHECK (mode IN ('SHARED', 'EXCLUSIVE')),
    status       TEXT        NOT NULL,
    token_digest BYTEA       NOT NULL,
    upgraded_from_shared BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at  TIMESTAMPTZ
)`); err != nil {
			return err
		}
		// Upgrade databases created before upgrades existed: old records
		// gain the column with its default and the status check is
		// widened to admit UPGRADE_PENDING. Both statements are
		// idempotent, so fresh databases pass through harmlessly.
		if _, err := tx.Exec(ctx, `
ALTER TABLE grants ADD COLUMN IF NOT EXISTS upgraded_from_shared BOOLEAN NOT NULL DEFAULT FALSE`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
ALTER TABLE grants DROP CONSTRAINT IF EXISTS grants_status_check`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
ALTER TABLE grants ADD CONSTRAINT grants_status_check
CHECK (status IN ('ACTIVE', 'UPGRADE_PENDING', 'RELEASED'))`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
CREATE INDEX IF NOT EXISTS grants_receiver_seq ON grants (receiver, seq)`)
		return err
	})
}

// CreateGrant atomically checks for conflicting active grants on receiver
// and inserts a new ACTIVE grant. It returns the grant plus the owner
// token, which is shown to the caller exactly once; only its SHA-256
// digest is persisted.
func (s *Store) CreateGrant(ctx context.Context, receiver, mode string) (Grant, string, error) {
	var g Grant
	var token string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Serialize grant decisions per receiver across all API processes.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, receiver); err != nil {
			return err
		}
		// A SHARED request conflicts with any active EXCLUSIVE grant; an
		// EXCLUSIVE request conflicts with any active grant at all. A
		// pending upgrade bars every new admission to the receiver, so
		// the waiting owner is not starved by newcomers.
		var conflicts int
		if err := tx.QueryRow(ctx, `
SELECT count(*) FROM grants
WHERE receiver = $1
  AND (status = 'UPGRADE_PENDING'
       OR (status = 'ACTIVE' AND ($2 = 'EXCLUSIVE' OR mode = 'EXCLUSIVE')))`,
			receiver, mode).Scan(&conflicts); err != nil {
			return err
		}
		if conflicts > 0 {
			return ErrBusy // rollback: no record is left behind
		}

		id, err := newID()
		if err != nil {
			return err
		}
		tok, digest, err := newToken()
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
INSERT INTO grants (id, receiver, mode, status, token_digest)
VALUES ($1, $2, $3, 'ACTIVE', $4)
RETURNING id, receiver, mode, status`,
			id, receiver, mode, digest).
			Scan(&g.ID, &g.Receiver, &g.Mode, &g.Status); err != nil {
			return err
		}
		token = tok
		return nil
	})
	if err != nil {
		return Grant{}, "", err
	}
	return g, token, nil
}

// ListGrants returns every grant for receiver in stable insertion order.
func (s *Store) ListGrants(ctx context.Context, receiver string) ([]Grant, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, receiver, mode, status FROM grants
WHERE receiver = $1
ORDER BY seq`, receiver)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Grant, error) {
		var g Grant
		err := row.Scan(&g.ID, &g.Receiver, &g.Mode, &g.Status)
		return g, err
	})
}

// ReleaseGrant transitions an ACTIVE or UPGRADE_PENDING grant to RELEASED
// when presented with its owner token. A wrong token yields ErrForbidden
// and leaves both the record and the receiver's active set untouched.
//
// The release runs inside the receiver's serialization transaction: if a
// pending upgrade survives on the receiver and the released grant was its
// last competitor, the pending grant is promoted to ACTIVE EXCLUSIVE in
// the same commit, so no query can observe an intermediate state.
// Releasing the pending grant itself cancels the upgrade and lifts the
// admission barrier.
func (s *Store) ReleaseGrant(ctx context.Context, id, token string) (Grant, error) {
	var g Grant
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		receiver, err := lockReceiver(ctx, tx, id)
		if err != nil {
			return err
		}
		var digest []byte
		err = tx.QueryRow(ctx, `
SELECT id, receiver, mode, status, token_digest
FROM grants WHERE id = $1
FOR UPDATE`, id).
			Scan(&g.ID, &g.Receiver, &g.Mode, &g.Status, &digest)
		if err != nil {
			return err
		}

		sum := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(sum[:], digest) != 1 {
			return ErrForbidden // rollback: record and active set unchanged
		}
		if g.Status == StatusReleased {
			return nil // idempotent re-release
		}
		if _, err := tx.Exec(ctx, `
UPDATE grants SET status = 'RELEASED', released_at = now()
WHERE id = $1`, id); err != nil {
			return err
		}
		g.Status = StatusReleased
		return promotePendingLocked(ctx, tx, receiver)
	})
	if err != nil {
		return Grant{}, err
	}
	return g, nil
}

// UpgradeGrant converts an ACTIVE SHARED grant into the receiver's
// exclusive grant in place: the record is kept, the owner token stays
// valid, and no RELEASED/created pair is ever visible.
//
// If no other active grant remains on the receiver, the grant is promoted
// to ACTIVE EXCLUSIVE immediately. Otherwise it becomes UPGRADE_PENDING:
// the receiver stops admitting new grants, and the release of the last
// competing grant promotes it. Repeating the call with the same token is
// idempotent, both while waiting and after promotion.
func (s *Store) UpgradeGrant(ctx context.Context, id, token string) (Grant, error) {
	var g Grant
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		receiver, err := lockReceiver(ctx, tx, id)
		if err != nil {
			return err
		}
		var digest []byte
		var upgraded bool
		err = tx.QueryRow(ctx, `
SELECT id, receiver, mode, status, token_digest, upgraded_from_shared
FROM grants WHERE id = $1
FOR UPDATE`, id).
			Scan(&g.ID, &g.Receiver, &g.Mode, &g.Status, &digest, &upgraded)
		if err != nil {
			return err
		}

		sum := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(sum[:], digest) != 1 {
			return ErrForbidden // rollback: grant set unchanged
		}
		switch {
		case g.Status == StatusReleased:
			return ErrReleased
		case g.Status == StatusUpgradePending:
			return nil // idempotent retry of a waiting upgrade
		case upgraded:
			return nil // idempotent retry after promotion to EXCLUSIVE
		case g.Mode == ModeExclusive:
			return ErrNotShared
		}

		// At most one pending upgrade per receiver.
		var pending int
		if err := tx.QueryRow(ctx, `
SELECT count(*) FROM grants
WHERE receiver = $1 AND status = 'UPGRADE_PENDING'`, receiver).Scan(&pending); err != nil {
			return err
		}
		if pending > 0 {
			return ErrUpgradePending
		}

		// Competing active grants keep the upgrade waiting; with none
		// left the grant is promoted straight to ACTIVE EXCLUSIVE.
		var others int
		if err := tx.QueryRow(ctx, `
SELECT count(*) FROM grants
WHERE receiver = $1 AND id <> $2 AND status = 'ACTIVE'`,
			receiver, id).Scan(&others); err != nil {
			return err
		}
		if others == 0 {
			return tx.QueryRow(ctx, `
UPDATE grants
SET mode = 'EXCLUSIVE', status = 'ACTIVE', upgraded_from_shared = TRUE
WHERE id = $1
RETURNING id, receiver, mode, status`, id).
				Scan(&g.ID, &g.Receiver, &g.Mode, &g.Status)
		}
		return tx.QueryRow(ctx, `
UPDATE grants SET status = 'UPGRADE_PENDING'
WHERE id = $1
RETURNING id, receiver, mode, status`, id).
			Scan(&g.ID, &g.Receiver, &g.Mode, &g.Status)
	})
	if err != nil {
		return Grant{}, err
	}
	return g, nil
}

// lockReceiver resolves the grant's receiver and takes the per-receiver
// advisory transaction lock shared by every mutating operation. The row
// is read without a lock first so that lock ordering is always
// "advisory lock, then row locks", which keeps concurrent operations on
// one receiver deadlock-free. It returns ErrNotFound for unknown ids.
func lockReceiver(ctx context.Context, tx pgx.Tx, id string) (string, error) {
	var receiver string
	err := tx.QueryRow(ctx, `SELECT receiver FROM grants WHERE id = $1`, id).Scan(&receiver)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, receiver); err != nil {
		return "", err
	}
	return receiver, nil
}

// promotePendingLocked promotes the receiver's pending upgrade to ACTIVE
// EXCLUSIVE when no competing grant remains. The caller must hold the
// per-receiver advisory lock inside the current transaction.
func promotePendingLocked(ctx context.Context, tx pgx.Tx, receiver string) error {
	var pendingID string
	err := tx.QueryRow(ctx, `
SELECT id FROM grants
WHERE receiver = $1 AND status = 'UPGRADE_PENDING'`, receiver).Scan(&pendingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var others int
	if err := tx.QueryRow(ctx, `
SELECT count(*) FROM grants
WHERE receiver = $1 AND id <> $2 AND status IN ('ACTIVE', 'UPGRADE_PENDING')`,
		receiver, pendingID).Scan(&others); err != nil {
		return err
	}
	if others > 0 {
		return nil
	}
	_, err = tx.Exec(ctx, `
UPDATE grants
SET mode = 'EXCLUSIVE', status = 'ACTIVE', upgraded_from_shared = TRUE
WHERE id = $1`, pendingID)
	return err
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newToken() (token string, digest []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}
