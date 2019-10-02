// Copyright 2016 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package etcdserver

import (
	"sync"

	"github.com/coreos/etcd/auth"
	pb "github.com/coreos/etcd/etcdserver/etcdserverpb"
	"github.com/coreos/etcd/lease"
	"github.com/coreos/etcd/mvcc"
)

type authApplierV3 struct {
	applierV3
	as     auth.AuthStore
	lessor lease.Lessor

	// mu serializes Apply so that user isn't corrupted and so that
	// serialized requests don't leak data from TOCTOU errors
	mu sync.Mutex

	authInfo auth.AuthInfo
}

func newAuthApplierV3(as auth.AuthStore, base applierV3, lessor lease.Lessor) *authApplierV3 {
	return &authApplierV3{applierV3: base, as: as, lessor: lessor}
}

func (aa *authApplierV3) Apply(r *pb.InternalRaftRequest) *applyResult {
	aa.mu.Lock()
	defer aa.mu.Unlock()
	if r.Header != nil {
		// backward-compatible with pre-3.0 releases when internalRaftRequest
		// does not have header field
		aa.authInfo.Username = r.Header.Username
		aa.authInfo.Revision = r.Header.AuthRevision
	}
	if needAdminPermission(r) {
		if err := aa.as.IsAdminPermitted(&aa.authInfo); err != nil {
			aa.authInfo.Username = ""
			aa.authInfo.Revision = 0
			return &applyResult{err: err}
		}
	}
	ret := aa.applierV3.Apply(r)
	aa.authInfo.Username = ""
	aa.authInfo.Revision = 0
	return ret
}

func (aa *authApplierV3) Put(txn mvcc.TxnWrite, cs *auth.CapturedState, r *pb.PutRequest) (*pb.PutResponse, error) {
	cs, err := aa.as.IsPutPermitted(&aa.authInfo, r.Key)
	if err != nil {
		return nil, err
	}

	if err := checkLeasePuts(aa.lessor, aa.as, &aa.authInfo, lease.LeaseID(r.Lease)); err != nil {
		// The specified lease is already attached with a key that cannot
		// be written by this user. It means the user cannot revoke the
		// lease so attaching the lease to the newly written key should
		// be forbidden.
		return nil, err
	}

	if r.PrevKv {
		cs, err = aa.as.IsRangePermitted(&aa.authInfo, r.Key, nil)
		if err != nil {
			return nil, err
		}
	}

	return aa.applierV3.Put(txn, cs, r)
}

func (aa *authApplierV3) Range(txn mvcc.TxnRead, cs *auth.CapturedState, r *pb.RangeRequest) (*pb.RangeResponse, error) {
	cs, err := aa.as.IsRangePermitted(&aa.authInfo, r.Key, r.RangeEnd)
	if err != nil {
		return nil, err
	}
	return aa.applierV3.Range(txn, cs, r)
}

func (aa *authApplierV3) DeleteRange(txn mvcc.TxnWrite, cs *auth.CapturedState, r *pb.DeleteRangeRequest) (*pb.DeleteRangeResponse, error) {
	cs, err := aa.as.IsDeleteRangePermitted(&aa.authInfo, r.Key, r.RangeEnd)
	if err != nil {
		return nil, err
	}
	if r.PrevKv {
		cs, err = aa.as.IsRangePermitted(&aa.authInfo, r.Key, r.RangeEnd)
		if err != nil {
			return nil, err
		}
	}

	return aa.applierV3.DeleteRange(txn, cs, r)
}

func checkTxnReqsPermission(lessor lease.Lessor, as auth.AuthStore, ai *auth.AuthInfo, reqs []*pb.RequestOp) (*auth.CapturedState, error) {
	var cs *auth.CapturedState
	var err error
	for _, requ := range reqs {
		switch tv := requ.Request.(type) {
		case *pb.RequestOp_RequestRange:
			if tv.RequestRange == nil {
				continue
			}

			cs, err = as.IsRangePermitted(ai, tv.RequestRange.Key, tv.RequestRange.RangeEnd)
			if err != nil {
				return cs, err
			}

		case *pb.RequestOp_RequestPut:
			if tv.RequestPut == nil {
				continue
			}

			cs, err = as.IsPutPermitted(ai, tv.RequestPut.Key)
			if err != nil {
				return cs, err
			}

			err = checkLeasePuts(lessor, as, ai, lease.LeaseID(tv.RequestPut.Lease))
			if err != nil {
				return cs, err
			}

			if tv.RequestPut.PrevKv {
				cs, err = as.IsRangePermitted(ai, tv.RequestPut.Key, nil)
				if err != nil {
					return cs, err
				}
			}

		case *pb.RequestOp_RequestDeleteRange:
			if tv.RequestDeleteRange == nil {
				continue
			}

			if tv.RequestDeleteRange.PrevKv {
				cs, err = as.IsRangePermitted(ai, tv.RequestDeleteRange.Key, tv.RequestDeleteRange.RangeEnd)
				if err != nil {
					return cs, err
				}
			}

			cs, err = as.IsDeleteRangePermitted(ai, tv.RequestDeleteRange.Key, tv.RequestDeleteRange.RangeEnd)
			if err != nil {
				return cs, err
			}
		}
	}

	return cs, nil
}

func checkTxnAuth(lessor lease.Lessor, as auth.AuthStore, ai *auth.AuthInfo, rt *pb.TxnRequest) (*auth.CapturedState, error) {
	var cs *auth.CapturedState
	var err error
	for _, c := range rt.Compare {
		cs, err = as.IsRangePermitted(ai, c.Key, c.RangeEnd)
		if err != nil {
			return cs, err
		}
	}
	cs2, err := checkTxnReqsPermission(lessor, as, ai, rt.Success)
	if err != nil {
		return cs2, err
	}
	if cs2 != nil {
		cs = cs2
	}
	cs2, err = checkTxnReqsPermission(lessor, as, ai, rt.Failure)
	if err != nil {
		return cs2, err
	}
	if cs2 != nil {
		cs = cs2
	}
	return cs, nil
}

func (aa *authApplierV3) Txn(cs *auth.CapturedState, rt *pb.TxnRequest) (*pb.TxnResponse, error) {
	cs2, err := checkTxnAuth(aa.lessor, aa.as, &aa.authInfo, rt)
	if err != nil {
		return nil, err
	}
	if cs2 != nil {
		cs = cs2
	}
	return aa.applierV3.Txn(cs, rt)
}

func (aa *authApplierV3) LeaseRevoke(lc *pb.LeaseRevokeRequest) (*pb.LeaseRevokeResponse, error) {
	if err := checkLeasePuts(aa.lessor, aa.as, &aa.authInfo, lease.LeaseID(lc.ID)); err != nil {
		return nil, err
	}
	return aa.applierV3.LeaseRevoke(lc)
}

func checkLeasePuts(lessor lease.Lessor, as auth.AuthStore, ai *auth.AuthInfo, leaseID lease.LeaseID) error {
	lease := lessor.Lookup(leaseID)
	if lease != nil {
		for _, it := range lease.Items() {
			cs, err := as.IsPutPermitted(ai, []byte(it.Key))
			if err != nil {
				return err
			}
			if !mvcc.CheckLease(cs, &it) {
				return auth.ErrPermissionDenied
			}
		}
	}

	return nil
}

func (aa *authApplierV3) UserGet(r *pb.AuthUserGetRequest) (*pb.AuthUserGetResponse, error) {
	err := aa.as.IsAdminPermitted(&aa.authInfo)
	if err != nil && r.Name != aa.authInfo.Username {
		aa.authInfo.Username = ""
		aa.authInfo.Revision = 0
		return &pb.AuthUserGetResponse{}, err
	}

	return aa.applierV3.UserGet(r)
}

func (aa *authApplierV3) RoleGet(r *pb.AuthRoleGetRequest) (*pb.AuthRoleGetResponse, error) {
	err := aa.as.IsAdminPermitted(&aa.authInfo)
	if err != nil && !aa.as.HasRole(aa.authInfo.Username, r.Role) {
		aa.authInfo.Username = ""
		aa.authInfo.Revision = 0
		return &pb.AuthRoleGetResponse{}, err
	}

	return aa.applierV3.RoleGet(r)
}

func (aa *authApplierV3) UserListAcl(r *pb.AuthUserListAclRequest) (*pb.AuthUserListAclResponse, error) {
	err := aa.as.IsAdminPermitted(&aa.authInfo)
	if err != nil && len(r.User) > 0 && r.User != aa.authInfo.Username {
		aa.authInfo.Username = ""
		aa.authInfo.Revision = 0
		return &pb.AuthUserListAclResponse{}, err
	}

	if len(r.User) <= 0 {
		r = &pb.AuthUserListAclRequest{User: aa.authInfo.Username}
	}

	return aa.applierV3.UserListAcl(r)
}

func needAdminPermission(r *pb.InternalRaftRequest) bool {
	switch {
	case r.AuthEnable != nil:
		return true
	case r.AuthDisable != nil:
		return true
	case r.AuthUserAdd != nil:
		return true
	case r.AuthUserDelete != nil:
		return true
	case r.AuthUserChangePassword != nil:
		return true
	case r.AuthUserGrantRole != nil:
		return true
	case r.AuthUserRevokeRole != nil:
		return true
	case r.AuthRoleAdd != nil:
		return true
	case r.AuthRoleGrantPermission != nil:
		return true
	case r.AuthRoleRevokePermission != nil:
		return true
	case r.AuthRoleDelete != nil:
		return true
	case r.AuthUserList != nil:
		return true
	case r.AuthRoleList != nil:
		return true
	case r.AuthPrototypeUpdate != nil:
		return true
	case r.AuthPrototypeDelete != nil:
		return true
	case r.AuthPrototypeList != nil:
		return true
	case r.AuthUserUpdateAcl != nil:
		return true
	case r.Compaction != nil:
		return true
	case r.Alarm != nil:
		return true
	default:
		return false
	}
}
