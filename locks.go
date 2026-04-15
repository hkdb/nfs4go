package nfs4go

import (
	"sync"
	"time"

	"github.com/hkdb/nfs4go/msg"
)

// Lock types per RFC 7530
const (
	READ_LT  = uint32(1) // Read lock (shared)
	WRITE_LT = uint32(2) // Write lock (exclusive)
	READW_LT = uint32(3) // Read lock with wait (treated as READ_LT)
	WRITEW_LT = uint32(4) // Write lock with wait (treated as WRITE_LT)
)

// FileLock represents a single byte-range lock on a file.
type FileLock struct {
	Offset   uint64
	Length   uint64 // 0 means lock to EOF
	LockType uint32
	ClientID uint64
	Owner    []byte // opaque lock owner
	StateID  msg.StateId4
}

// LockManager tracks all file locks across all clients.
// Advisory locking only — locks don't prevent READ/WRITE operations,
// they only prevent conflicting lock grants.
type LockManager struct {
	// filePath -> list of locks
	locks      map[string][]FileLock
	mu         sync.RWMutex
	nextSeqID  uint32
	graceEnd   time.Time
	gracePeriod time.Duration
}

// NewLockManager creates a lock manager with a grace period for lock reclamation.
func NewLockManager(gracePeriod time.Duration) *LockManager {
	return &LockManager{
		locks:       make(map[string][]FileLock),
		nextSeqID:   1,
		graceEnd:    time.Now().Add(gracePeriod),
		gracePeriod: gracePeriod,
	}
}

// InGracePeriod returns true if the server is still in the post-restart grace period.
func (lm *LockManager) InGracePeriod() bool {
	return time.Now().Before(lm.graceEnd)
}

// Lock acquires a byte-range lock. Returns the assigned stateid and any error.
func (lm *LockManager) Lock(filePath string, lockType uint32, offset, length uint64, clientID uint64, owner []byte) (msg.StateId4, uint32) {
	// Normalize wait types to regular types
	normalType := lockType
	if normalType == READW_LT {
		normalType = READ_LT
	}
	if normalType == WRITEW_LT {
		normalType = WRITE_LT
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check for conflicts
	existing := lm.locks[filePath]
	for _, lock := range existing {
		if isSameOwner(lock.ClientID, lock.Owner, clientID, owner) {
			continue // same owner can upgrade/extend
		}
		if !rangesOverlap(offset, length, lock.Offset, lock.Length) {
			continue
		}
		// Overlapping ranges from different owner — check for conflict
		if normalType == WRITE_LT || lock.LockType == WRITE_LT {
			return msg.StateId4{}, msg.NFS4ERR_DENIED
		}
	}

	// Remove any existing lock from same owner on overlapping range (upgrade)
	cleaned := make([]FileLock, 0, len(existing))
	for _, lock := range existing {
		if isSameOwner(lock.ClientID, lock.Owner, clientID, owner) && rangesOverlap(offset, length, lock.Offset, lock.Length) {
			continue // remove — will be replaced by new lock
		}
		cleaned = append(cleaned, lock)
	}

	// Create new lock
	stateID := lm.allocateStateID()
	newLock := FileLock{
		Offset:   offset,
		Length:   length,
		LockType: normalType,
		ClientID: clientID,
		Owner:    owner,
		StateID:  stateID,
	}

	lm.locks[filePath] = append(cleaned, newLock)
	return stateID, 0
}

// LockTest checks if a lock would conflict without acquiring it.
// Returns 0 on success, NFS4ERR_DENIED if conflict exists.
func (lm *LockManager) LockTest(filePath string, lockType uint32, offset, length uint64, clientID uint64, owner []byte) (uint32, *FileLock) {
	normalType := lockType
	if normalType == READW_LT {
		normalType = READ_LT
	}
	if normalType == WRITEW_LT {
		normalType = WRITE_LT
	}

	lm.mu.RLock()
	defer lm.mu.RUnlock()

	for _, lock := range lm.locks[filePath] {
		if isSameOwner(lock.ClientID, lock.Owner, clientID, owner) {
			continue
		}
		if !rangesOverlap(offset, length, lock.Offset, lock.Length) {
			continue
		}
		if normalType == WRITE_LT || lock.LockType == WRITE_LT {
			conflicting := lock // copy
			return msg.NFS4ERR_DENIED, &conflicting
		}
	}

	return 0, nil
}

// Unlock releases a byte-range lock identified by stateid.
func (lm *LockManager) Unlock(filePath string, stateID msg.StateId4, offset, length uint64) uint32 {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	existing := lm.locks[filePath]
	found := false
	cleaned := make([]FileLock, 0, len(existing))

	for _, lock := range existing {
		if lock.StateID.SeqId == stateID.SeqId && lock.StateID.Other == stateID.Other &&
			lock.Offset == offset && lock.Length == length {
			found = true
			continue // remove this lock
		}
		cleaned = append(cleaned, lock)
	}

	if !found {
		return msg.NFS4ERR_BAD_STATEID
	}

	lm.locks[filePath] = cleaned
	return 0
}

// ReleaseClientLocks removes all locks held by a client (called on lease expiry).
func (lm *LockManager) ReleaseClientLocks(clientID uint64) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	for filePath, locks := range lm.locks {
		cleaned := make([]FileLock, 0, len(locks))
		for _, lock := range locks {
			if lock.ClientID != clientID {
				cleaned = append(cleaned, lock)
			}
		}
		if len(cleaned) == 0 {
			delete(lm.locks, filePath)
			continue
		}
		lm.locks[filePath] = cleaned
	}
}

// ReleaseFileLocks removes all locks on a file (called on file close).
func (lm *LockManager) ReleaseFileLocks(filePath string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	delete(lm.locks, filePath)
}

func (lm *LockManager) allocateStateID() msg.StateId4 {
	lm.nextSeqID++
	return msg.StateId4{
		SeqId: lm.nextSeqID,
		Other: [3]uint32{lm.nextSeqID, 0, 0},
	}
}

func isSameOwner(clientID1 uint64, owner1 []byte, clientID2 uint64, owner2 []byte) bool {
	if clientID1 != clientID2 {
		return false
	}
	if len(owner1) != len(owner2) {
		return false
	}
	for i := range owner1 {
		if owner1[i] != owner2[i] {
			return false
		}
	}
	return true
}

func rangesOverlap(off1, len1, off2, len2 uint64) bool {
	// Length 0 means "lock to end of file" per RFC 7530
	maxUint64 := ^uint64(0)

	var end1, end2 uint64
	if len1 == 0 || off1 > maxUint64-len1 {
		end1 = maxUint64
	}
	if len1 != 0 && off1 <= maxUint64-len1 {
		end1 = off1 + len1
	}
	if len2 == 0 || off2 > maxUint64-len2 {
		end2 = maxUint64
	}
	if len2 != 0 && off2 <= maxUint64-len2 {
		end2 = off2 + len2
	}

	return off1 < end2 && off2 < end1
}
