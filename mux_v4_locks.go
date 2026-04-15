package nfs4go

import (
	"github.com/hkdb/nfs4go/msg"
	"github.com/hkdb/nfs4go/xdr"
)

// Lock implements the NFSv4 LOCK operation (RFC 7530 Section 14.2.12).
// Advisory byte-range locking.
func (x *Compound) Lock(in, out Bytes) (uint32, error) {
	decoder := xdr.NewDecoder(in)

	var lockType uint32
	var reclaim uint32
	var offset uint64
	var length uint64
	if err := decoder.DecodeAll(&lockType, &reclaim, &offset, &length); err != nil {
		return OperationResponse(out, msg.OP4_LOCK, msg.NFS4ERR_BADXDR)
	}

	// Check grace period
	if x.Locks != nil && x.Locks.InGracePeriod() && reclaim == 0 {
		return OperationResponse(out, msg.OP4_LOCK, msg.NFS4ERR_GRACE)
	}

	// Read lock owner info — simplified: we read a boolean for new lock owner,
	// then either new or existing lock owner data
	var isNewLockOwner uint32
	if err := decoder.DecodeAll(&isNewLockOwner); err != nil {
		return OperationResponse(out, msg.OP4_LOCK, msg.NFS4ERR_BADXDR)
	}

	var clientID uint64
	var owner []byte

	if isNewLockOwner != 0 {
		// New lock owner: open_stateid + lock_seqid + lock_owner
		var openStateID msg.StateId4
		var lockSeqID uint32
		if err := decoder.DecodeAll(&openStateID, &lockSeqID); err != nil {
			return OperationResponse(out, msg.OP4_LOCK, msg.NFS4ERR_BADXDR)
		}
		// lock_owner: clientid + opaque owner
		if err := decoder.DecodeAll(&clientID); err != nil {
			return OperationResponse(out, msg.OP4_LOCK, msg.NFS4ERR_BADXDR)
		}
		var ownerErr error
		owner, ownerErr = decoder.Bytes()
		if ownerErr != nil {
			return OperationResponse(out, msg.OP4_LOCK, msg.NFS4ERR_BADXDR)
		}
	}
	if isNewLockOwner == 0 {
		// Existing lock owner: lock_stateid + lock_seqid
		var lockStateID msg.StateId4
		var lockSeqID uint32
		if err := decoder.DecodeAll(&lockStateID, &lockSeqID); err != nil {
			return OperationResponse(out, msg.OP4_LOCK, msg.NFS4ERR_BADXDR)
		}
		// Use the stateid to identify the owner (simplified)
		clientID = uint64(lockStateID.Other[0])
		owner = []byte{byte(lockStateID.SeqId)}
	}

	if x.CurrentHandle == nil {
		return OperationResponse(out, msg.OP4_LOCK, msg.NFS4ERR_NOFILEHANDLE)
	}

	if x.Locks == nil {
		return OperationResponse(out, msg.OP4_LOCK, msg.NFS4ERR_SERVERFAULT)
	}

	stateID, nfsErr := x.Locks.Lock(x.CurrentHandle.Path, lockType, offset, length, clientID, owner)
	if nfsErr != 0 {
		// Return denied with empty lock denied info
		encoder := xdr.NewEncoder(out)
		encoder.EncodeAll(msg.OP4_LOCK, nfsErr)
		return nfsErr, nil
	}

	// Success: return lock stateid
	encoder := xdr.NewEncoder(out)
	encoder.EncodeAll(msg.OP4_LOCK, uint32(0)) // NFS4_OK
	stateID.Encode(encoder)
	return 0, nil
}

// LockTest implements the NFSv4 LOCKT operation (RFC 7530 Section 14.2.13).
// Tests if a lock would conflict without acquiring it.
func (x *Compound) LockTest(in, out Bytes) (uint32, error) {
	decoder := xdr.NewDecoder(in)

	var lockType uint32
	var offset uint64
	var length uint64
	var clientID uint64
	if err := decoder.DecodeAll(&lockType, &offset, &length, &clientID); err != nil {
		return OperationResponse(out, msg.OP4_LOCKT, msg.NFS4ERR_BADXDR)
	}
	owner, ownerErr := decoder.Bytes()
	if ownerErr != nil {
		return OperationResponse(out, msg.OP4_LOCKT, msg.NFS4ERR_BADXDR)
	}

	if x.CurrentHandle == nil {
		return OperationResponse(out, msg.OP4_LOCKT, msg.NFS4ERR_NOFILEHANDLE)
	}

	if x.Locks == nil {
		return OperationResponse(out, msg.OP4_LOCKT, msg.NFS4ERR_SERVERFAULT)
	}

	nfsErr, _ := x.Locks.LockTest(x.CurrentHandle.Path, lockType, offset, length, clientID, owner)
	if nfsErr != 0 {
		return OperationResponse(out, msg.OP4_LOCKT, nfsErr)
	}

	return OperationResponse(out, msg.OP4_LOCKT, 0)
}

// LockUnlock implements the NFSv4 LOCKU operation (RFC 7530 Section 14.2.14).
// Releases a previously acquired lock.
func (x *Compound) LockUnlock(in, out Bytes) (uint32, error) {
	decoder := xdr.NewDecoder(in)

	var lockType uint32
	var seqID uint32
	var lockStateID msg.StateId4
	var offset uint64
	var length uint64
	if err := decoder.DecodeAll(&lockType, &seqID); err != nil {
		return OperationResponse(out, msg.OP4_LOCKU, msg.NFS4ERR_BADXDR)
	}
	if err := lockStateID.Decode(decoder); err != nil {
		return OperationResponse(out, msg.OP4_LOCKU, msg.NFS4ERR_BADXDR)
	}
	if err := decoder.DecodeAll(&offset, &length); err != nil {
		return OperationResponse(out, msg.OP4_LOCKU, msg.NFS4ERR_BADXDR)
	}

	if x.CurrentHandle == nil {
		return OperationResponse(out, msg.OP4_LOCKU, msg.NFS4ERR_NOFILEHANDLE)
	}

	if x.Locks == nil {
		return OperationResponse(out, msg.OP4_LOCKU, msg.NFS4ERR_SERVERFAULT)
	}

	nfsErr := x.Locks.Unlock(x.CurrentHandle.Path, lockStateID, offset, length)
	if nfsErr != 0 {
		return OperationResponse(out, msg.OP4_LOCKU, nfsErr)
	}

	// Return new stateid (same as input for simplicity)
	encoder := xdr.NewEncoder(out)
	encoder.EncodeAll(msg.OP4_LOCKU, uint32(0)) // NFS4_OK
	lockStateID.Encode(encoder)
	return 0, nil
}
