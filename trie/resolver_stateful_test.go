package trie

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/ledgerwatch/turbo-geth/common"
	"github.com/ledgerwatch/turbo-geth/common/dbutils"
	"github.com/ledgerwatch/turbo-geth/common/pool"
	"github.com/ledgerwatch/turbo-geth/core/types/accounts"
	"github.com/ledgerwatch/turbo-geth/crypto"
	"github.com/ledgerwatch/turbo-geth/ethdb"
	"github.com/ledgerwatch/turbo-geth/rlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRebuild(t *testing.T) {
	t.Skip("should be restored. skipped for turbo-geth")

	db := ethdb.NewMemDatabase()
	defer db.Close()
	bucket := dbutils.AccountsBucket
	tr := New(common.Hash{})

	keys := []string{
		"FIRSTFIRSTFIRSTFIRSTFIRSTFIRSTFI",
		"SECONDSECONDSECONDSECONDSECONDSE",
		"FISECONDSECONDSECONDSECONDSECOND",
		"FISECONDSECONDSECONDSECONDSECONB",
		"THIRDTHIRDTHIRDTHIRDTHIRDTHIRDTH",
	}
	values := []string{
		"FIRST",
		"SECOND",
		"THIRD",
		"FORTH",
		"FIRTH",
	}

	for i := 0; i < len(keys); i++ {
		key := []byte(keys[i])
		value := []byte(values[i])
		v1, err := rlp.EncodeToBytes(bytes.TrimLeft(value, "\x00"))
		if err != nil {
			t.Errorf("Could not encode value: %v", err)
		}
		tr.Update(key, v1)
		tr.PrintTrie()
		root1 := tr.Root()
		//fmt.Printf("Root1: %x\n", tr.Root())
		v1, err = EncodeAsValue(v1)
		if err != nil {
			t.Errorf("Could not encode value: %v", err)
		}
		err = db.Put(bucket, key, v1)
		require.NoError(t, err)
		t1 := New(common.BytesToHash(root1))
		_ = t1.Rebuild(db, 0)
	}
}

// Put 1 embedded entry into the database and try to resolve it
func TestResolve1(t *testing.T) {
	require, assert, db := require.New(t), assert.New(t), ethdb.NewMemDatabase()
	tr := New(common.Hash{})
	putStorage := func(k string, v string) {
		err := db.Put(dbutils.StorageBucket, common.Hex2Bytes(k), common.Hex2Bytes(v))
		require.NoError(err)
	}
	putStorage("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")

	req := &ResolveRequest{
		t:           tr,
		resolveHex:  keybytesToHex(common.Hex2Bytes("aaaaabbbbbaaaaabbbbbaaaaabbbbbaa")),
		resolvePos:  10, // 5 bytes is 10 nibbles
		resolveHash: hashNode(common.HexToHash("bfb355c9a7c26a9c173a9c30e1fb2895fd9908726a8d3dd097203b207d852cf5").Bytes()),
	}
	r := NewResolver(0, false, 0)
	r.AddRequest(req)
	err := r.ResolveWithDb(db, 0)
	require.NoError(err)

	_, ok := tr.Get(common.Hex2Bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	assert.True(ok)
}

func TestResolve2(t *testing.T) {
	require, assert, db := require.New(t), assert.New(t), ethdb.NewMemDatabase()
	tr := New(common.Hash{})
	putStorage := func(k string, v string) {
		err := db.Put(dbutils.StorageBucket, common.Hex2Bytes(k), common.Hex2Bytes(v))
		require.NoError(err)
	}
	putStorage("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
	putStorage("aaaaaccccccccccccccccccccccccccc", "")

	req := &ResolveRequest{
		t:           tr,
		resolveHex:  keybytesToHex(common.Hex2Bytes("aaaaabbbbbaaaaabbbbbaaaaabbbbbaa")),
		resolvePos:  10, // 5 bytes is 10 nibbles
		resolveHash: hashNode(common.HexToHash("38eb1d28b717978c8cb21b6939dc69ba445d5dea67ca0e948bbf0aef9f1bc2fb").Bytes()),
	}
	r := NewResolver(0, false, 0)
	r.AddRequest(req)
	err := r.ResolveWithDb(db, 0)
	require.NoError(err)

	_, ok := tr.Get(common.Hex2Bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	assert.True(ok)
}

func TestResolve2Keep(t *testing.T) {
	require, assert, db := require.New(t), assert.New(t), ethdb.NewMemDatabase()
	tr := New(common.Hash{})
	putStorage := func(k string, v string) {
		err := db.Put(dbutils.StorageBucket, common.Hex2Bytes(k), common.Hex2Bytes(v))
		require.NoError(err)
	}
	putStorage("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
	putStorage("aaaaaccccccccccccccccccccccccccc", "")

	req := &ResolveRequest{
		t:           tr,
		resolveHex:  keybytesToHex(common.Hex2Bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
		resolvePos:  10, // 5 bytes is 10 nibbles
		resolveHash: hashNode(common.HexToHash("38eb1d28b717978c8cb21b6939dc69ba445d5dea67ca0e948bbf0aef9f1bc2fb").Bytes()),
	}
	r := NewResolver(0, false, 0)
	r.AddRequest(req)
	err := r.ResolveWithDb(db, 0)
	require.NoError(err)

	_, ok := tr.Get(common.Hex2Bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	assert.True(ok)
}

func TestResolve3Keep(t *testing.T) {
	require, assert, db := require.New(t), assert.New(t), ethdb.NewMemDatabase()
	tr := New(common.Hash{})
	putStorage := func(k string, v string) {
		err := db.Put(dbutils.StorageBucket, common.Hex2Bytes(k), common.Hex2Bytes(v))
		require.NoError(err)
	}
	putStorage("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
	putStorage("aaaaabbbbbbbbbbbbbbbbbbbbbbbbbbb", "")
	putStorage("aaaaaccccccccccccccccccccccccccc", "")

	req := &ResolveRequest{
		t:           tr,
		resolveHex:  keybytesToHex(common.Hex2Bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
		resolvePos:  10, // 5 bytes is 10 nibbles
		resolveHash: hashNode(common.HexToHash("b780e7d2bc3b7ab7f85084edb2fff42facefa0df9dd1e8190470f277d8183e7c").Bytes()),
	}
	r := NewResolver(0, false, 0)
	r.AddRequest(req)
	err := r.ResolveWithDb(db, 0)
	require.NoError(err, "resolve error")

	_, ok := tr.Get(common.Hex2Bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	assert.True(ok)
}

func TestTrieResolver(t *testing.T) {
	require, assert, db := require.New(t), assert.New(t), ethdb.NewMemDatabase()
	tr := New(common.Hash{})
	putStorage := func(k string, v string) {
		err := db.Put(dbutils.StorageBucket, common.Hex2Bytes(k), common.Hex2Bytes(v))
		require.NoError(err)
	}
	putStorage("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
	putStorage("aaaaaccccccccccccccccccccccccccc", "")
	putStorage("baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
	putStorage("bbaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
	putStorage("bbaaaccccccccccccccccccccccccccc", "")
	putStorage("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "")
	putStorage("bccccccccccccccccccccccccccccccc", "")

	req1 := &ResolveRequest{
		t:           tr,
		resolveHex:  keybytesToHex(common.Hex2Bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
		resolvePos:  10, // 5 bytes is 10 nibbles
		resolveHash: hashNode(common.HexToHash("38eb1d28b717978c8cb21b6939dc69ba445d5dea67ca0e948bbf0aef9f1bc2fb").Bytes()),
	}
	req2 := &ResolveRequest{
		t:           tr,
		resolveHex:  keybytesToHex(common.Hex2Bytes("bbaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
		resolvePos:  2, // 1 bytes is 2 nibbles
		resolveHash: hashNode(common.HexToHash("dc2332366fcf65ad75d09901e199e3dd52a5389ad85ff1d853803c5f40cbde56").Bytes()),
	}
	req3 := &ResolveRequest{
		t:           tr,
		resolveHex:  keybytesToHex(common.Hex2Bytes("bbbaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
		resolvePos:  2, // 1 bytes is 2 nibbles
		resolveHash: hashNode(common.HexToHash("df6fd126d62ec79182d9ab6f879b63dfacb9ce2e1cb765b17b9752de9c2cbaa7").Bytes()),
	}
	resolver := NewResolver(0, false, 0)
	resolver.AddRequest(req3)
	resolver.AddRequest(req2)
	resolver.AddRequest(req1)

	err := resolver.ResolveWithDb(db, 0)
	require.NoError(err, "resolve error")

	_, ok := tr.Get(common.Hex2Bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	assert.True(ok)
}

func TestTwoStorageItems(t *testing.T) {
	require, assert, db := require.New(t), assert.New(t), ethdb.NewMemDatabase()
	tr := New(common.Hash{})

	key1 := common.Hex2Bytes("d7b6990105719101dabeb77144f2a3385c8033acd3af97e9423a695e81ad1eb5")
	key2 := common.Hex2Bytes("df6966c971051c3d54ec59162606531493a51404a002842f56009d7e5cf4a8c7")
	val1 := common.Hex2Bytes("02")
	val2 := common.Hex2Bytes("03")

	require.NoError(db.Put(dbutils.StorageBucket, key1, val1))
	require.NoError(db.Put(dbutils.StorageBucket, key2, val2))

	leaf1 := shortNode{Key: keybytesToHex(key1[1:]), Val: valueNode(val1)}
	leaf2 := shortNode{Key: keybytesToHex(key2[1:]), Val: valueNode(val2)}
	var branch fullNode
	branch.Children[0x7] = &leaf1
	branch.Children[0xf] = &leaf2
	root := shortNode{Key: []byte{0xd}, Val: &branch}

	hasher := newHasher(false)
	defer returnHasherToPool(hasher)
	rootRlp, err := hasher.hashChildren(&root, 0)
	require.NoError(err, "failed ot hash children")

	// Resolve the root node

	rootHash := common.HexToHash("d06f3adc0b0624495478b857a37950d308d6840b349fe2c9eb6dcb813e0ccfb8")
	assert.Equal(rootHash, crypto.Keccak256Hash(rootRlp))

	req := &ResolveRequest{
		t:           tr,
		resolveHex:  []byte{},
		resolvePos:  0,
		resolveHash: hashNode(rootHash.Bytes()),
	}
	resolver := NewResolver(0, false, 0)
	resolver.AddRequest(req)

	err = resolver.ResolveWithDb(db, 0)
	require.NoError(err, "resolve error")

	assert.Equal(rootHash.String(), tr.Hash().String())

	// Resolve the branch node

	branchRlp, err := hasher.hashChildren(&branch, 0)
	if err != nil {
		t.Errorf("failed ot hash children: %v", err)
	}

	req2 := &ResolveRequest{
		t:           tr,
		resolveHex:  []byte{0xd},
		resolvePos:  1,
		resolveHash: hashNode(crypto.Keccak256(branchRlp)),
	}
	resolver2 := NewResolver(0, false, 0)
	resolver2.AddRequest(req2)

	err = resolver2.ResolveWithDb(db, 0)
	require.NoError(err, "resolve error")

	assert.Equal(rootHash.String(), tr.Hash().String())

	_, ok := tr.Get(key1)
	assert.True(ok)
}

func TestTwoAccounts(t *testing.T) {
	require, assert, db := require.New(t), assert.New(t), ethdb.NewMemDatabase()
	tr := New(common.Hash{})
	key1 := common.Hex2Bytes("03601462093b5945d1676df093446790fd31b20e7b12a2e8e5e09d068109616b")
	err := db.Put(dbutils.AccountsBucket, key1, common.Hex2Bytes("020502540be400"))
	require.NoError(err)
	err = db.Put(dbutils.AccountsBucket, common.Hex2Bytes("0fbc62ba90dec43ec1d6016f9dd39dc324e967f2a3459a78281d1f4b2ba962a6"), common.Hex2Bytes("120164204f1593970e8f030c0a2c39758181a447774eae7c65653c4e6440e8c18dad69bc"))
	require.NoError(err)

	expect := common.HexToHash("925002c3260b44e44c3edebad1cc442142b03020209df1ab8bb86752edbd2cd7")

	buf := pool.GetBuffer(64)
	buf.Reset()
	defer pool.PutBuffer(buf)

	DecompressNibbles(common.Hex2Bytes("03601462093b5945d1676df093446790fd31b20e7b12a2e8e5e09d068109616b"), &buf.B)

	req := &ResolveRequest{
		t:           tr,
		resolveHex:  buf.Bytes(),
		resolvePos:  0,
		resolveHash: hashNode(expect.Bytes()),
	}

	resolver := NewResolver(0, true, 0)
	resolver.AddRequest(req)
	err = resolver.ResolveWithDb(db, 0)
	require.NoError(err, "resolve error")

	assert.Equal(expect.String(), tr.Hash().String())

	_, ok := tr.GetAccount(key1)
	assert.True(ok)
}

func TestReturnErrOnWrongRootHash(t *testing.T) {
	require, db := require.New(t), ethdb.NewMemDatabase()
	tr := New(common.Hash{})
	putAccount := func(k string) {
		a := accounts.Account{}
		v := make([]byte, a.EncodingLengthForStorage())
		a.EncodeForStorage(v)
		err := db.Put(dbutils.AccountsBucket, common.Hex2Bytes(k), v)
		require.NoError(err)
	}

	putAccount("0000000000000000000000000000000000000000000000000000000000000000")

	req := &ResolveRequest{
		t:           tr,
		resolveHex:  []byte{},
		resolvePos:  0,
		resolveHash: hashNode(common.HexToHash("wrong hash").Bytes()),
	}
	resolver := NewResolver(0, true, 0)
	resolver.AddRequest(req)
	err := resolver.ResolveWithDb(db, 0)
	require.NotNil(t, err)
}

func TestApiDetails(t *testing.T) {
	const Stateful = "stateful"
	const StatefulCached = "stateful_cached"

	require, assert, db := require.New(t), assert.New(t), ethdb.NewMemDatabase()

	storageKey := func(k string) []byte {
		return dbutils.GenerateCompositeStorageKey(common.HexToHash(k), 1, common.HexToHash(k))
	}
	putCache := func(k string, v string) {
		require.NoError(db.Put(dbutils.IntermediateTrieHashBucket, common.Hex2Bytes(k), common.Hex2Bytes(v)))
	}

	// Test attempt handle cases when: Trie root hash is same for Cached and non-Cached Resolvers
	// Test works with keys like: {base}{i}{j}{zeroes}
	// base = 0 or f - it covers edge cases - first/last subtrees
	//
	// i=0 - has data, has cache, no resolve. Tree must have Hash.
	// i=1 - has cache with empty value. Tree must have Nil.
	// i=2 - has accounts and storage, no cache. Tree must have Account nodes.
	// i>2 - no data, no cache, no resolve.
	// i=f - has data, has cache, no resolve. Edge case - last subtree.
	for _, base := range []string{"0", "f"} {
		for _, i := range []int{0, 1, 2, 15} {
			for _, j := range []int{0, 1, 2, 15} {
				k := fmt.Sprintf(base+"%x%x%061x", i, j, 0)
				storageV := common.Hex2Bytes(fmt.Sprintf("%x%x", i, j))
				if i == 1 {
					storageV = []byte{}
					putCache(k, "") // mark accounts as deleted
				}

				a := accounts.Account{
					// Using Nonce field as an ID of account.
					// Will check later if value which we .Get() from Trie has expected ID.
					Nonce:          uint64(i*10 + j),
					Initialised:    true,
					Root:           EmptyRoot,
					CodeHash:       EmptyCodeHash,
					Balance:        *big.NewInt(0),
					StorageSize:    uint64(len(storageV)),
					HasStorageSize: len(storageV) > 0,
				}
				v := make([]byte, a.EncodingLengthForStorage())
				a.EncodeForStorage(v)

				require.NoError(db.Put(dbutils.AccountsBucket, common.Hex2Bytes(k), v))
				require.NoError(db.Put(dbutils.StorageBucket, storageKey(k), storageV))
			}
		}
	}

	putCache("00", "06e98f77330d54fa691a724018df5b2c5689596c03413ca59717ea9bd8a98893")
	putCache("ff", "ad4f92ca84a5980e14a356667eaf0db5d9ff78063630ebaa3d00a6634cd2a3fe")

	// this cache key must not be used, because such key is in ResolveRequest
	putCache("01", "0000000000000000000000000000000000000000000000000000000000000000")

	t.Run("account resolver from scratch", func(t *testing.T) {
		tries := []*Trie{New(common.Hash{}), New(common.Hash{})}
		for i, resolverName := range []string{Stateful, StatefulCached} {
			resolver := NewResolver(5, true, 0)
			expectRootHash := common.HexToHash("1af5daf4281e4e5552e79069d0688492de8684c11b1e983f9c3bbac500ad694a")

			resolver.AddRequest(tries[i].NewResolveRequest(nil, nil, 0, expectRootHash.Bytes()))

			if resolverName == Stateful {
				err := resolver.ResolveStateful(db, 0)
				//fmt.Printf("%x\n", tries[i].root.(*fullNode).Children[15].(*fullNode).Children[15].hash())
				assert.NoError(err)
			} else {
				err := resolver.ResolveStatefulCached(db, 0)
				//fmt.Printf("%x\n", tries[i].root.(*shortNode).Val.(*fullNode).Children[15].hash())
				assert.NoError(err)
			}
			assert.Equal(expectRootHash.String(), tries[i].Hash().String(), resolverName)
		}

		//tries[0].PrintDiff(tries[1], os.Stdout)
	})

	t.Run("account resolver", func(t *testing.T) {
		tries := []*Trie{New(common.Hash{}), New(common.Hash{})}
		for i, resolverName := range []string{Stateful, StatefulCached} {
			resolver := NewResolver(0, true, 0)
			expectRootHash := common.HexToHash("1af5daf4281e4e5552e79069d0688492de8684c11b1e983f9c3bbac500ad694a")

			resolver.AddRequest(tries[i].NewResolveRequest(nil, append(common.Hex2Bytes(fmt.Sprintf("000101%0122x", 0)), 16), 0, expectRootHash.Bytes()))
			resolver.AddRequest(tries[i].NewResolveRequest(nil, common.Hex2Bytes("000202"), 0, expectRootHash.Bytes()))
			resolver.AddRequest(tries[i].NewResolveRequest(nil, common.Hex2Bytes("0f"), 0, expectRootHash.Bytes()))

			if resolverName == Stateful {
				err := resolver.ResolveStateful(db, 0)
				//fmt.Printf("%x\n", tries[i].root.(*fullNode).Children[0].(*fullNode).Children[0].hash())
				assert.NoError(err)
			} else {
				err := resolver.ResolveStatefulCached(db, 0)
				//fmt.Printf("%x\n", tries[i].root.(*fullNode).Children[0].(*fullNode).Children[0].hash())
				assert.NoError(err)
			}

			assert.Equal(expectRootHash.String(), tries[i].Hash().String(), resolverName)

			_, found := tries[i].GetAccount(common.Hex2Bytes(fmt.Sprintf("000%061x", 0)))
			assert.False(found) // exists in DB but resolved, there is hashNode

			acc, found := tries[i].GetAccount(common.Hex2Bytes(fmt.Sprintf("011%061x", 0)))
			assert.True(found)
			require.NotNil(acc)              // cache bucket has empty value, but self-destructed Account still available
			assert.Equal(int(acc.Nonce), 11) // i * 10 + j

			acc, found = tries[i].GetAccount(common.Hex2Bytes(fmt.Sprintf("021%061x", 0)))
			assert.True(found)
			require.NotNil(acc)              // exists in db and resolved
			assert.Equal(int(acc.Nonce), 21) // i * 10 + j

			//acc, found = tr.GetAccount(common.Hex2Bytes(fmt.Sprintf("051%061x", 0)))
			//assert.True(found)
			//assert.Nil(acc) // not exists in DB

			//assert.Panics(func() {
			//	tr.UpdateAccount(common.Hex2Bytes(fmt.Sprintf("001%061x", 0)), &accounts.Account{})
			//})
			//assert.NotPanics(func() {
			//	tr.UpdateAccount(common.Hex2Bytes(fmt.Sprintf("011%061x", 0)), &accounts.Account{})
			//	tr.UpdateAccount(common.Hex2Bytes(fmt.Sprintf("021%061x", 0)), &accounts.Account{})
			//	tr.UpdateAccount(common.Hex2Bytes(fmt.Sprintf("051%061x", 0)), &accounts.Account{})
			//})
		}

		//tries[0].PrintDiff(tries[1], os.Stdout)
	})

	t.Run("storage resolver", func(t *testing.T) {
		putCache("00", "9e3571a3a3a75d023799452cfacea4d268b109bc685b9e8b63a50b55be81c7a3")
		putCache("ff", "8d2b73f47eb0e6c79ca4f48ba551bfd62f058c9d1cff7e1ab72ba3b2d63aefed")
		putCache("01", "")

		for _, resolverName := range []string{Stateful, StatefulCached} {
			tr, resolver := New(common.Hash{}), NewResolver(1, false, 0)
			expectRootHash := common.HexToHash("b7861b26269e04ae4a865ed3900f56472ad248ffd2976cddef8018cc9700f846")

			resolver.AddRequest(tr.NewResolveRequest(nil, common.Hex2Bytes("00020100"), 0, expectRootHash.Bytes()))

			if resolverName == Stateful {
				err := resolver.ResolveStateful(db, 0)
				require.NoError(err)
			} else {
				err := resolver.ResolveStatefulCached(db, 0)
				require.NoError(err)
			}
			assert.Equal(expectRootHash.String(), tr.Hash().String())

			_, found := tr.Get(storageKey(fmt.Sprintf("000%061x", 0)))
			assert.False(found) // exists in DB but not resolved, there is hashNode

			storage, found := tr.Get(storageKey(fmt.Sprintf("011%061x", 0)))
			assert.True(found)
			require.Nil(storage) // deleted by empty value in cache bucket

			storage, found = tr.Get(storageKey(fmt.Sprintf("021%061x", 0)))
			assert.True(found)
			require.Equal(storage, common.Hex2Bytes("21"))

			storage, found = tr.Get(storageKey(fmt.Sprintf("051%061x", 0)))
			assert.True(found)
			assert.Nil(storage) // not exists in DB

			assert.Panics(func() {
				tr.Update(storageKey(fmt.Sprintf("001%061x", 0)), nil)
			})
			assert.NotPanics(func() {
				tr.Update(storageKey(fmt.Sprintf("011%061x", 0)), nil)
				tr.Update(storageKey(fmt.Sprintf("021%061x", 0)), nil)
				tr.Update(storageKey(fmt.Sprintf("051%061x", 0)), nil)
			})
		}
	})
}

func TestKeyIsBefore(t *testing.T) {
	assert := assert.New(t)

	is, minKey := keyIsBefore([]byte("a"), []byte("b"))
	assert.Equal(true, is)
	assert.Equal("a", fmt.Sprintf("%s", minKey))

	is, minKey = keyIsBefore([]byte("b"), []byte("a"))
	assert.Equal(false, is)
	assert.Equal("a", fmt.Sprintf("%s", minKey))

	is, minKey = keyIsBefore([]byte("b"), []byte(""))
	assert.Equal(false, is)
	assert.Equal("", fmt.Sprintf("%s", minKey))

	is, minKey = keyIsBefore(nil, []byte("b"))
	assert.Equal(false, is)
	assert.Equal("b", fmt.Sprintf("%s", minKey))

	is, minKey = keyIsBefore([]byte("b"), nil)
	assert.Equal(true, is)
	assert.Equal("b", fmt.Sprintf("%s", minKey))

	contract := fmt.Sprintf("2%063x", 0)
	storageKey := common.Hex2Bytes(contract + "ffffffff" + fmt.Sprintf("10%062x", 0))
	cacheKey := common.Hex2Bytes(contract + "20")
	is, minKey = keyIsBefore(cacheKey, storageKey)
	assert.False(is)
	assert.Equal(fmt.Sprintf("%x", storageKey), fmt.Sprintf("%x", minKey))

	storageKey = common.Hex2Bytes(contract + "ffffffffffffffff" + fmt.Sprintf("20%062x", 0))
	cacheKey = common.Hex2Bytes(contract + "10")
	is, minKey = keyIsBefore(cacheKey, storageKey)
	assert.True(is)
	assert.Equal(fmt.Sprintf("%x", cacheKey), fmt.Sprintf("%x", minKey))
}

func TestHexIncrement(t *testing.T) {
	assert := assert.New(t)
	k := common.Hex2Bytes("f2fd")

	k, ok := nextSubtree(k)
	assert.True(ok)
	assert.Equal("f2fe", common.Bytes2Hex(k))
	k, ok = nextSubtree(k)
	assert.True(ok)
	assert.Equal("f2ff", common.Bytes2Hex(k))
	k, ok = nextSubtree(k)
	assert.True(ok)
	assert.Equal("f300", common.Bytes2Hex(k))

	k = common.Hex2Bytes("ffffff")
	assert.Nil(nextSubtree(k))
	k = common.Hex2Bytes("ffff")
	assert.Nil(nextSubtree(k))
	k = common.Hex2Bytes("ff")
	assert.Nil(nextSubtree(k))
	k = common.Hex2Bytes("")
	assert.Nil(nextSubtree(k))
}

func TestCmpWithoutIncarnation(t *testing.T) {
	assert := assert.New(t)
	type TestCase struct {
		k1     string
		k2     string
		expect int
	}
	cases := []TestCase{
		{
			k1:     "f2fd",
			k2:     "f2ff",
			expect: -1,
		},
		{
			k1:     "f2fd",
			k2:     "f2f0",
			expect: 1,
		},
		{
			k1:     "f2ff",
			k2:     "f2ff",
			expect: 0,
		},
		{
			k1:     fmt.Sprintf("%064x1%063x", 0, 0),
			k2:     fmt.Sprintf("%064x00000000000000006%063x", 0, 0),
			expect: -1,
		},
		{
			k1:     fmt.Sprintf("%064x7%063x", 0, 0),
			k2:     fmt.Sprintf("%064x00000000000000006%063x", 0, 0),
			expect: 1,
		},
		{
			k1:     fmt.Sprintf("%064x6%063x", 0, 0),
			k2:     fmt.Sprintf("%064x00000000000000006%063x", 0, 0),
			expect: 0,
		},
		{
			k1:     fmt.Sprintf("%064x1", 0),
			k2:     fmt.Sprintf("%064x00000000000000006%063x", 0, 0),
			expect: -1,
		},
		{
			k1:     fmt.Sprintf("%064x70", 0),
			k2:     fmt.Sprintf("%064x00000000000000006%063x", 0, 0),
			expect: 1,
		},
	}

	for _, tc := range cases {
		r := cmpWithoutIncarnation(common.Hex2Bytes(tc.k1), common.Hex2Bytes(tc.k2))
		assert.Equal(tc.expect, r, fmt.Sprintf("k1: %s\nk2: %s", tc.k1, tc.k2))
	}
}

func TestRealScenario1(t *testing.T) {
	_, assert, db := require.New(t), assert.New(t), ethdb.NewMemDatabase()
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5016d3e9ffd7f0bda33f26f1cd73e56ef1d230953a82e40f62bb19ffe180c"), common.FromHex("010101"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f50dd305f0756ca690a73ead13c22eafdca1a334a72d6d62faea705d600dda"), common.FromHex("03010207016bcc41e90000"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f50fdd86b3a05ca74b30eea119672a64deea1efd98042a6cb1b9fb0d0870fa"), common.FromHex("1f01010803311fc80a5700000101209a8221a6457daed39645df92ce5a202121ac0622669767e464c77de0b0b034b8209cf4100dc54b4bd5e52ecde8ef8a513d1b824d836da0dc1cce7f34b3b722b7de"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f511153f252f4155812fcbc74a55afad24443bee1d953e8629526045bca13e"), common.FromHex("0207470de4df820000"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5154e800808bca87a7a44ca26585baf6fb72f568ba6cbbac53e47f6c77c2c"), common.FromHex("0301030701e4eca4805800"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f52677dca0b1ebd7604aa6d424469f1303c4e5977a8495a13fd7fd7bbbb2a2"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f52c0fa4642b3b07d4d026038bc95db3a73e525e52244962e5ad47fc8481e6"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f52ebca84fa95bf228747c17b04727c88d49f18526b4adb01e1e583822680a"), common.FromHex("010101"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f52f1ffb9ae29f1d209b464a9c55ed6db93051133ebbcbd6fd61b4e1625794"), common.FromHex("010104"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f53143112636ff91903e579e9d6a11d42095d6cfe9838c0a50dcf2a8a4a819"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5337932a48639095cbe94212c86eef9f7254042086ac20d7bb1a9167e0e76"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5367ab59da5980a35d083a13ee880dc0bb5bca615a0381619051884f61b9d"), common.FromHex("030113086fa51bc7eacf0100"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f53d1993ebe6e75f6ac37f36816a59e86a0f8523215fece3450f7cdf7bc669"), common.FromHex("1d010101012003ed3f1efcd3590d904d9636a7411bfad92b473d5c2e5ff1ddb3b0d87bd056e520dcf182706ef7caf1dfa3ff3529136ec4e3be7dcc63bc11da5930a45aa2e59b05"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f53d7899f16af80f976b8a5861354bc4bc6dc730ce4b8cdb132cc9299ce4ff"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f53d7caf197bbe377800d56b4ca6dc71614d38e232ccc577647ec556608ad2"), common.FromHex("010102"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f53e8f2091581be34ffead681a604c84bad954fa66b6ea8aa4fc88c09f65a6"), common.FromHex("030101070587229612b700"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f54105abdf04185433e4490a9f16b39a3f71bd08dea0d13ce20b0b972e18c1"), common.FromHex("0301010702166d3ed77a70"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f54290167d6f6245bbbd6d0bf2128416fb02cc0c2fb4cb9c9cd8422fb56d96"), common.FromHex("1d010101012088f6c90814631203ebcd879b9b2a01f894d317d77528d0a411dcdc9664a288fb20f0b332bc44312957c41e1c20a16725fe869fe75441fd6ffd6bd0e13f2703d1ea"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f543cec3a04dc141c0017b7e80d15ded641745ae22be2a8b2180464d10d89f"), common.FromHex("010114"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5486ec874227d924a8e21329674cbd1b3ddad9a04b6e059d43bfe8abdc4a6"), common.FromHex("010104"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5487e82a6a54fe5c7dfaa4911b4d25759c80f8d6b0372766a7f2eb35c453a"), common.FromHex("1d0101010120a2518d94738645fceab4c3ee7ee68bcf544bd27bae72d3779dfc17014187cbc920dcf182706ef7caf1dfa3ff3529136ec4e3be7dcc63bc11da5930a45aa2e59b05"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f54df28157acef451f3a655fb10b58976b5051f1f0e31457ff124e9191abe9"), common.FromHex("03010106befe6f672004"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f556eb1837e38144f6d3b87ed6fc8284a769a76a6353960b7834ce88ada992"), common.FromHex("010106"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f55704f96a9665f177c5bdebb4c661b7d303014c19234e752671ef34985ee6"), common.FromHex("02076a94d74f430000"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f55eb688a94e72ac870952385de75e45999c971122d4ed62cc7b0fcbb37fcf"), common.FromHex("1f0101072386f26fc10000010120d64de325aa52414b9132107955042ef6f4bbfd9b955a733032135ba43d7cadf6201e4366082444073b4bea23568c108c4288f2293bf126f5cd6359c41ec52fc7fe"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f55f0ff8e9f10b2b27b898068a2da52fe024b293eee530ae65665fc308b8bc"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5632992c1f1f913af3fc43a216b0d3153586252f1d2537ac49897ab701063"), common.FromHex("010102"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f564e03d38802c227a7092a9e76deeae81906ebff737a7795f27ede3870a99"), common.FromHex("01010c"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f567a0b2831a2a45e804185513e9c9d0528b69bf1ea4e0910d513196daab44"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f56d397df85cdb46140f173da0778652324cd60eebe04ec925d5186826a89c"), common.FromHex("03010106b5e620f4d000"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f56f492f0775521a3b78df238a8aaaea8e6c80d6e859eee390dd53d26970be"), common.FromHex("010102"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5722456f61a0f3ba40bdd891857541eec2b996bd692163bab45394787f77b"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f57968d3b02ac7bbab7a1e328491739ff2b330156b45c8f05fd316311fb4d8"), common.FromHex("010101"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f57c16fe86792e2d5b035cfe3c3b4c03c3ed86715f69e49cf207a9afb41a65"), common.FromHex("1d0101010120c5b727bf09bb460c692cc797bb1cfc4edb79ec57e86322d1dbc95cbbed35f4f820a05fc946278f27029157571be9b363c0f9a66e866e2bc779e1f64e9cf60fd70a"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f57e43185753443fa8ef0ed7bbc8689456de0c052f29b262d79e633c543e73"), common.FromHex("1d01010101202a997e7222765b4b16a0f03f09e0cea9ca4811980b3501a70748cbb1daf11abc20337c29fd9976d67b66b28034c1414c04861ce13b19a267c6e01d66f2cdb6bfba"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f580a360374d05256ebee2240362555579b1787ad57eb75673ed83d7617faa"), common.FromHex("0209056bc75e2d63100000"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f580b26d6c9842f7b9bb55b906c74844cdfdbe90e04062edd646e82b08b441"), common.FromHex("030102070e78513de43800"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5838c9af543ef8c6ce5e91407e5e56ec845d45815f48479f016337a017c1a"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f585f1560dc349d20638503680c4a0e11c81b7d119634c5af9b911066330c9"), common.FromHex("030101070ff5734054c000"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f586450a210acde0c5dfad22877c4ddfa0155073d3fc45a7035b20382bdb8d"), common.FromHex("1d0101010120c0de84fcc32953889b241ee483d72c0695a368404196704c37e03189fa114d4520dcf182706ef7caf1dfa3ff3529136ec4e3be7dcc63bc11da5930a45aa2e59b05"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5871bbb319faa623aaaaf099aa1f7dbedb9b356413d482f7fb75abda7bf0f"), common.FromHex("03010307071aff1ee89402"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f58989a95d82e76e6528a36e7b34b097477098d1539ed946e1c9a3d36fa020"), common.FromHex("010102"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f58ad2303bd4933c66fba132bd52a21229c45ecc72edcffd23b46ea812cf5f"), common.FromHex("1d01010101209a8221a6457daed39645df92ce5a202121ac0622669767e464c77de0b0b034b820f5a025aa1836ecb6d628d1ccf313a6c1f12566b798a7214750c4b83317fc6dba"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f58b653902a341b496abbba906742c0bf8680fa277792ddd62dd7f8933c2e9"), common.FromHex("010101"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f58e8a9553f8cc5bf67c95c5403ed6496174cb7b1a64ded5da09b726b66a7d"), common.FromHex("03010607125057032e2e8f"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5948cf8969560cdb37381ebd3561d278eea296652db5eb19859551acc973c"), common.FromHex("010102"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f59501b137fe77ee4aa20b5256c4f016e194c514f8f367990c8c8f1774b848"), common.FromHex("03010b0712505731487000"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5978646b8c6790c7679d6c3968ea3d7ae9ec8a127f01b294431fff4cc6479"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f598a47a936f4bda51a1266598675df6e5c2d12a3a30ba339dc0cea8530836"), common.FromHex("03010106b5e620f78d24"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f59d3fa6d79e3d0764b9ef595c557e92e2458f3538354b4bfc4338cf9360a9"), common.FromHex("0301010705118458662e00"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f59d5987bfd6e4bb4785e5556707ccac11431e6eba364dfbb6d77ae42c425a"), common.FromHex("010104"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5a238bce7dfc2f88470a4c4709bed35fe218db008779ac08293e1f8116043"), common.FromHex("03010208013b34d3949e4200"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5a4b2e916015c1fe9e50b1c38fe78881e185b4ac6dbd47695ef93ecd8aea1"), common.FromHex("1c0101201fc09808178a80141b792a6263da8ec0525c369c31052f23dbf390b8b60fa2b1204092c8a5fb6487e931a5679ab058788c99bdb84fb49fdbf8cd5dc131e8a2f19f"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5a4b2e91652346e72fdfa88a6d93e8059b7f1c82aaeb60b124fa9d649280f"), common.FromHex("020101"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5a8d902df36d505a80e16fa94dd9c7d83a29d6c1ccf99626b3fd9fb535274"), common.FromHex("1f01010874c952e03ed029d50101209a8221a6457daed39645df92ce5a202121ac0622669767e464c77de0b0b034b820cf991db76896c91579ffd41c1e7f9e1e990d77738292fe12249da5122e47c121"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5ab3facdfbc8d89b44bfea0b321d6d256ff2ce10913c8539bfc2de040e86f"), common.FromHex("0301020902201c67114dea4800"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5ada727303e407bd53fb21f6dfb503c60b14a3227a60bda321d5704b0dce9"), common.FromHex("1d0101010120709eb5dda2147c4fb819a20da7a29219edf23b78b89a76895cb5bb987352df302007be01e7e7206fe31ecee91ad75dada65ad6ba433ae647a1b9330469f7c6677c"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5b7a661afe4d321d25ccaca31dde828d2c19a089d06ccfc67e9833c780375"), common.FromHex("03010108015ba7f7e1768800"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5ba68c73055ee5e261db346481742796919a66d61f1773c32e1b5f3f7a860"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720"), common.FromHex("1c01012034f344c58250c618f085c3dbd2d6cc719a780e9e1b8b3c025e9dcc72d588960120eca86627efbcaa746ead709522efa484332ac4cd5cddefa67ca2302ce1b8a4c5"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5c46ae26ffbb4c4bc6ed9bc3cbc1cdba1cd76cd6e9fa6167525cf398058ec"), common.FromHex("0208033984366ca78732"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5c8edc3b0dd8d9fefa7c5fef2a662f77e7149bf14a7b09af13f9c190dc7c6"), common.FromHex("0301010702de2e3572d000"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5c9b8c6db2da703da8553517e764b68a20bb67dad51a4df2e44c4e0c475d1"), common.FromHex("010101"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5cb1e1dee6b677933b886c056293bd70344ff0015f99a707c3ac7ef2b6a66"), common.FromHex("03011c071030dc0f6987e4"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5ccc7adc2f6200bca9dc0cb9baffe6d7b4ac342936473423e917157236de3"), common.FromHex("010102"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5ce38ba247fc548899c1000a88abfffc409b0fc8fc05bb1fe45b5ad77ebc9"), common.FromHex("030111071250585b492184"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5d25799dc2b040c167dca85fd93c275e8f6af5b51463f37231dd895d175ec"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5d2c9841380c7daf953caca021b0b740dcfe6584609bf485b8c064979fb46"), common.FromHex("03010307719c7e116e2038"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5d4c4b013b7add258eb8631f15a6707da2e1ce8b91a26e64b70315c2406f8"), common.FromHex("010104"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5d5584b69ab852f6d22e485b946d6961b58783436ec9c5d56631c36c41c5f"), common.FromHex("010101"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5e0a8261517c749dca8e866c4830f60d3a37a15d591f0e3057852bf045175"), common.FromHex("030109071a14c54b5d5e00"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5e38c114e54b7b7ed99a64f5d834f899f757e1a457798bc481a621983d33e"), common.FromHex("030101050ece0d3c00"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5e3d8ca837c7220efa20c67ebc710a70bbc9854be3a9dddbce3622bb788a7"), common.FromHex("010101"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5e5c4e8f9b118b0c01b7b4793e72b15961ba2ac64e0d1ef795fb818ce2a8e"), common.FromHex("010101"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5f2dcab808797f745353bdc252030ee11e77a72e1c1c9970de37a48744cc6"), common.FromHex("010103"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5fad198d3437bed1da81686d96d0da5aa850992620eb09a199b2277adeda2"), common.FromHex("030102072386f26fc10000"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5fb3314ab3c99b3044c233221d2c4d37e250bea65f5f1534c7fea0ac4de14"), common.FromHex("030106080ad48a29333f0a00"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5fd1a7b68b4cb6b799416ea90c56aa424f89d60d0e17882bae55194a2e4bf"), common.FromHex("0301010710292a006ed800"))
	db.Put(dbutils.AccountsBucket, common.FromHex("d5f5fd9b1891138c9f7cefc7ef4b669bcc985cdbce35c6c66b651393e5075e05"), common.FromHex("030202fe070226c0d7a5b4b9"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f50fdd86b3a05ca74b30eea119672a64deea1efd98042a6cb1b9fb0d0870fafffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("42da8a05cb7ed9a43572b5ba1b8f82a0a6e263dc"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe0371ec0f5e5237a0fa70708311439859109939709f9ffb40cdf15bbff09a8584"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe03f5659f257210b7b89da6db5c873016a4ad9edc95c7b72eda1719e366516c12"), common.FromHex("64"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe0df76ccb16f9505eebbd5404f22f735b05b8185a908f8c76f2bab7593a322e25"), common.FromHex("c98429e8edbe13346daa12f44a0453cbe2805a65"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe0e7aae4a3a572b2a8388e60ce171626645425ac19b07e873ed3bbb1c18255698"), common.FromHex("3571d34e9dc1d40a8eadc36b4fd1cc91eba9e6c7"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe1116a53f3efc81f37df14c3f2de8e34f3ed58d7ce4d0423cd077933ec97c6430"), common.FromHex("06"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe12bfb3bbd273bafebac90aaf2958996879d7fd2cd929205293d102be2431eb19"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe1d0aad4737cb7cafd64eb2d8729fc798ec795e82dcf0cb2d9c6141a3907371b1"), common.FromHex("08"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe1efb66c43e2b4ecddf60b7d3c93a3a9898d515b97d06f33fe4760dc24f0091b4"), common.FromHex("96e25a669fe729f67392d26c140c3fcca3d3c29e"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe22083b231715f01b82134bcef4cca1676c5709eea9aea65d46734ad15d352e54"), common.FromHex("04"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe24c85e1889156fac2bccd4295a4e5cc1a764d0473793e0995407ffc07a144d6a"), common.FromHex("02"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe25ad9732d92991f6049d26877bd85cd2d38e5c1483f5ac40fa0f09750a2d1446"), common.FromHex("270e"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe26eae8ee796c739c38405bcf5b0b546755c401915207e764d0947caf1fd21ec5"), common.FromHex("3571d34e9dc1d40a8eadc36b4fd1cc91eba9e6c7"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("3571d34e9dc1d40a8eadc36b4fd1cc91eba9e6c7"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe2ad842f5056725b687a41205c8ce80584477d11d73bab310f43016ed0d63bf23"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe2f8fb49ddb8d875c683fb632973436150fb7a6e8b962f1a752d51a721867b234"), common.FromHex("e6a16f01b191c3dd3f0b416b3f01e2dc5ea2f4a6"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe2fc7941cecc943bf2000c5d7068f2b8c8e9a29be62acd583fe9e6e90489a8c82"), common.FromHex("03"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe31b0c4fcfef3c109f2afa201e3534f360ee1503cd5a3be775f2d43854a59480b"), common.FromHex("0c"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe346e7afe20b3c80024078b855c355b0115247ac0c8907cf5196cf34d2c6ad99f"), common.FromHex("2328"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe36453cac58a4906122bd90086f162821d93b6f307788c4d6298f36e423cf28c7"), common.FromHex("0f"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe3a96e6ac3d45eed29dbf01c0b33ffacf9b2e5f2f23fe0df24b6ecbff3dad4f8c"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe41e9bb0abf7555179dc9fe4b298d27daeae8720f2bc62af0ea032ae75ed7db10"), common.FromHex("2710"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe4564fe97fb894b0111338dfb0b3314115e021001538a821b4cde6df02a5c6cdb"), common.FromHex("06f567ac940f6438aaa40c78226a914915298260"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe47e042d4fea63ec0443baa88b67922db0a77feee019c62c7db581de52e05a5c3"), common.FromHex("62"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe48dc4ad9223692dd7e3f87db70d3a5173a4ccb6b26343094391c535156e3270d"), common.FromHex("02"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe4b8fb2babe49b8cfc1817996d2cd5ef74db981a80d7f5eb9e646831be0704150"), common.FromHex("dc54d4c21f9b2024dbbc837c16e8bb70e753011e"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe5950b3d4eb157adda25c43ca9c5b1c7ed3c0103881851cfabe1d5890186292d8"), common.FromHex("c98429e8edbe13346daa12f44a0453cbe2805a65"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe5e04a0888e3ab636965dbe9aa38887fd9b3074921df61312fd796683c37ff4c2"), common.FromHex("0d"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe6502d3b6b12d4463d21f1670be290f261bc491d2d9b9e976b22f9b055a686fc3"), common.FromHex("04"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe664b084b78b869a8ca56f588bc203e819eceaa1ed2ac476deab366ced4ae75e2"), common.FromHex("05"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe74ed2d5022c396100ccbda68a9ebe2f88eb0baceb11c3814c72007df04a25cd4"), common.FromHex("05"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe74f079c42ebfd3881bf051b4a5c4d3bac90488fa58f975482af82ce190d9d096"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe7613dffd80ba7541d4ea05a3202a3f515d93c4b983db32843fbe26e885c3d900"), common.FromHex("07"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe7de92ef26cd19f232283d4500dbf5e4aa19aec676f3eedf26e1dfe28faf608ec"), common.FromHex("07"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe7fef4bf8f63cf9dd467136c679c02b5c17fcf6322d9562512bf5eb952cf7cc53"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe803d5b5d1ad3248ad60cb3f5e40865a0ef3de45e8d6b158ee7bc0cf66fce1d81"), common.FromHex("06"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe82a6ccc336fe97ce9554f46b4123833d2dc1547d8f9dba7e27112779552cb75b"), common.FromHex("06"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe842ac0009080797e405e6f386cb815e37985f1bb7e1fa0a9b688c4e50694e9af"), common.FromHex("09"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe8468a68661251079564f967aba375c1adcecaddde9fbfa1c736620bcaaaa8516"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe8b493bf403c63e0a640129c1b520aa4000991ea9c18d0c46c9ae3e514bf0f83b"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe8ca69cc158e7bf2a36e7e978ed46b574da3c6a29c12e9f457daa874ac51d54c0"), common.FromHex("dc54d4c21f9b2024dbbc837c16e8bb70e753011e"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe8d350a94de1b2317e774a618bba21e7e1b12bf8d3047e6838131ff3d9faad7c3"), common.FromHex("26fa"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe92437f88ed6509fa72a06f1abe12f0694677acef3fd9f8126b6fa518f41d8e6e"), common.FromHex("02"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffe994f87a949ead3131ef7649097ad873a1d43f2272b40cfa3527d7933992feefd"), common.FromHex("04"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffea001a15d0dd7bdfc23df88aa19d98dafffaa86702e818679971f75e8440b157b"), common.FromHex("dc54d4c21f9b2024dbbc837c16e8bb70e753011e"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffea9e1565b8e6ef1e22cd6edfa71a45d0aafd0f6699aa82cc0ed80b979f0b669ea"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffeaa1ed09d97b5d66c215492bccd4266fb9e0f61bb7af4cf8d771974274bf0f6da"), common.FromHex("64"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffeac239de2928a28a27b1c56e5bd4e305cd02933b83fd65ef881be366a4efa5e79"), common.FromHex("dc54d4c21f9b2024dbbc837c16e8bb70e753011e"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffeae1970c5ace7e4c414cba71962bc6e7e0e58d9dc7f66b617732a34c4478d3adf"), common.FromHex("d11c3da9a57e135970fb7940828cb1bd280040c4"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffeae1f6f36060f166f063fb01d63adab80297f56b5a444cab19384c535141dbd8b"), common.FromHex("0a"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffeb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), common.FromHex("8a815db6fb6234d54011b699ca731681ec503d92"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffeb19d9dd409d7995bdfdcfcf96f577784f03d7d9bff7efad132384a971b0ab81d"), common.FromHex("05"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffeb2c9fb9c352bff417dc44c1b439dec6414429701cacd33efe6b2dc7767dd3b87"), common.FromHex("05"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffeb376ebd972b8f04029562a3149574f80c6089a26629c712f7baee408b3dcb8ea"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffeb96130974cb5b2908db1b11a78609df2e3a28a3f554c3a107270569dfe3c7563"), common.FromHex("04"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffeba2f9fe32e8218da336271097dbab376a990b14acdf9a450f1a70324e2228b62"), common.FromHex("c98429e8edbe13346daa12f44a0453cbe2805a65"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffebcaf64e089911a16484a90efd7b500297f4994772a653be8ce90780bf301244d"), common.FromHex("05"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffec2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b"), common.FromHex("10"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffec3cade453ae4f3ddd41df6efad1650adc1c0b649ac31c4dbb2217813fe232849"), common.FromHex("0a"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffec69c1647012d38cd7ee312daa1107d2c483e774d36d0c4d978097296b8b49c9d"), common.FromHex("05"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffec8a72e88bf3e6eba304affc9e505f65144f5c23e8575d5608e97c8857d9dc79f"), common.FromHex("05"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffecc6aa2a08d9e8793dee28db7627f0ec74b54801bc30f440b4f9a630a5949feec"), common.FromHex("2406"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffed70731c4fc4bf9cd8fc2be4d898bd67fd357eb0135035bf4500364b4c42c4fa5"), common.FromHex("02"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffee103cafce0029e9a98824f4fe93aaff40496aaa1857c0ab7ce43c0e52802feb1"), common.FromHex("63"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffee3865db9f8972b0c230b315170485003aa10993ccb5b6ec9b112342ac1e4343a"), common.FromHex("03"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffee7acd8d905a18da59a6657120d175465fa6dfa15701505c2f2f9b4d61b08cbab"), common.FromHex("02"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffee9b15f85d838e2f1ae641c326e08115a4f6a2940bacbab568a090216164b5b2f"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffeebfd6de24591b42f30ce04aa4ab8c7bf028a77aef85c9d0f085b788e944f8b96"), common.FromHex("0e"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffef2a0fc0df1b679f3afe38c632fecf8d8d1945e3c27d5102dd1a69d36fa20d999"), common.FromHex("0a"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffef38bda3655e14bf41d0b2f1f77ef405f89ed73e613ce93ebcef774e887d808a8"), common.FromHex("dc54d4c21f9b2024dbbc837c16e8bb70e753011e"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffef739a8f58e4fb0c9336060b1ecef694b452d28f545dc0ae97b39456698f4621c"), common.FromHex("02"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffef86d5893d6186626dbf4a84761c0a038b94a38f77f48308e0a1867b9613b2f02"), common.FromHex("184480cb31034b736e72c66ca2acf7deae44d0a7"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffef992dab2820266ca9664ab42ef2fc3bfb330178173a94c5b0333385663d1b8c1"), common.FromHex("0b"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffefa12a7341db3e608e6e31eba253e2694eddd8264e0768d9266e24f496fd48816"), common.FromHex("05"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fefffffffffffffffefc2be5bb68d71344b39526b5f8e3529bd1e95830e32e7552df3d9b7ec6b7d64a"), common.FromHex("2328"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53d1993ebe6e75f6ac37f36816a59e86a0f8523215fece3450f7cdf7bc669fffffffffffffffe1b2bc7a119479c055f2811cddc8faa607ccdf68d8cf9a11f1bb8ce60a40a1a0f"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53d1993ebe6e75f6ac37f36816a59e86a0f8523215fece3450f7cdf7bc669fffffffffffffffe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"), common.FromHex("9ce18e6a141819c2f03f4356f140953ab470293c"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f53d1993ebe6e75f6ac37f36816a59e86a0f8523215fece3450f7cdf7bc669fffffffffffffffeb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), common.FromHex("e6a4f92579facb4026096f017243ee839ff72fd1"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f54290167d6f6245bbbd6d0bf2128416fb02cc0c2fb4cb9c9cd8422fb56d96fffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("edce883162179d4ed5eb9bb2e7dccf494d75b3a0"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5487e82a6a54fe5c7dfaa4911b4d25759c80f8d6b0372766a7f2eb35c453afffffffffffffffe1b2bc7a119479c055f2811cddc8faa607ccdf68d8cf9a11f1bb8ce60a40a1a0f"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5487e82a6a54fe5c7dfaa4911b4d25759c80f8d6b0372766a7f2eb35c453afffffffffffffffe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"), common.FromHex("f9b4196773e058f314425151cb24949a16aecd19"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5487e82a6a54fe5c7dfaa4911b4d25759c80f8d6b0372766a7f2eb35c453afffffffffffffffeb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), common.FromHex("e6a4f92579facb4026096f017243ee839ff72fd1"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f55eb688a94e72ac870952385de75e45999c971122d4ed62cc7b0fcbb37fcffffffffffffffffe036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f55eb688a94e72ac870952385de75e45999c971122d4ed62cc7b0fcbb37fcffffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("6090a6e47849629b7245dfa1ca21d94cd15878ef"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f55eb688a94e72ac870952385de75e45999c971122d4ed62cc7b0fcbb37fcffffffffffffffffe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"), common.FromHex("2acd20810b405fc4d01896871a6a7ba4b279fa"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f55eb688a94e72ac870952385de75e45999c971122d4ed62cc7b0fcbb37fcffffffffffffffffe8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b"), common.FromHex("2386f26fc10000"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f55eb688a94e72ac870952385de75e45999c971122d4ed62cc7b0fcbb37fcffffffffffffffffeb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), common.FromHex("597e3f5b"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f57c16fe86792e2d5b035cfe3c3b4c03c3ed86715f69e49cf207a9afb41a65fffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("feb90ab5ffd715c04aec06a654828bad6216765e"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f57e43185753443fa8ef0ed7bbc8689456de0c052f29b262d79e633c543e73fffffffffffffffe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"), common.FromHex("88a71b6f7dbbe0be6fdad077ed0973e400bd61f3"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f57e43185753443fa8ef0ed7bbc8689456de0c052f29b262d79e633c543e73fffffffffffffffeb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), common.FromHex("7a30f7736e48d6599356464ba4c150d8da0302ff"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f57e43185753443fa8ef0ed7bbc8689456de0c052f29b262d79e633c543e73fffffffffffffffedd8f86156b465220bc4497ceff2bffd633147bf9b548bcbe53a4fba23baeb974"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f586450a210acde0c5dfad22877c4ddfa0155073d3fc45a7035b20382bdb8dfffffffffffffffe1b2bc7a119479c055f2811cddc8faa607ccdf68d8cf9a11f1bb8ce60a40a1a0f"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f586450a210acde0c5dfad22877c4ddfa0155073d3fc45a7035b20382bdb8dfffffffffffffffe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"), common.FromHex("bc43a2f6b8a18a078e685b20970e21c953f4338e"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f586450a210acde0c5dfad22877c4ddfa0155073d3fc45a7035b20382bdb8dfffffffffffffffeb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), common.FromHex("e6a4f92579facb4026096f017243ee839ff72fd1"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f58ad2303bd4933c66fba132bd52a21229c45ecc72edcffd23b46ea812cf5ffffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("42da8a05cb7ed9a43572b5ba1b8f82a0a6e263dc"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5a4b2e916015c1fe9e50b1c38fe78881e185b4ac6dbd47695ef93ecd8aea1fffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("8b3b3b624c3c0397d3da8fd861512393d51dcbac"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5a4b2e916015c1fe9e50b1c38fe78881e185b4ac6dbd47695ef93ecd8aea1fffffffffffffffeb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), common.FromHex("bb9bc244d798123fde783fcc1c72d3bb8c189413"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5a8d902df36d505a80e16fa94dd9c7d83a29d6c1ccf99626b3fd9fb535274fffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("42da8a05cb7ed9a43572b5ba1b8f82a0a6e263dc"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5ada727303e407bd53fb21f6dfb503c60b14a3227a60bda321d5704b0dce9fffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("209c4784ab1e8183cf58ca33cb740efbf3fc18ef"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5ada727303e407bd53fb21f6dfb503c60b14a3227a60bda321d5704b0dce9fffffffffffffffeb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), common.FromHex("b42b20ddbeabdc2a288be7ff847ff94fb48d2579"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffe1ab0c6948a275349ae45a06aad66a8bd65ac18074615d53676c09b67809099e0"), common.FromHex("55"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("4fad5f9451ba7e842ae5a18a7878c70a8f683d4c"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffe4aee6d38ad948303a0117a3e3deee4d912b62481681bd892442a7d720eee5d2c"), common.FromHex("312e333030303030000000000000000000000000000000000000000000000010"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffe83fae7d88d3202765861d3bf8af4fff3ab5293dab6070c6fa8f55d3c5e93a72c"), common.FromHex("696172696f272c7472783a27277d2c0000000000000000000000000000000000"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffeb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), common.FromHex("011f"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffeb32787652f8eacc66cda8b4b73a1b9c31381474fe9e723b0ba866bfbd5dde02b"), common.FromHex("646f723a27272c63616e74696461643a27312e333030303030272c7469656d70"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffeb5d9d894133a730aa651ef62d26b0ffa846233c74177a591a4a896adfda97d22"), common.FromHex("7b736f6c6963697461646f723a27307834666164354639343531624137653834"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffeb6b7834d611e25670b584f73a3e810d0a47c773fe173fc6975449e876b0a6a70"), common.FromHex("3330000000000000000000000000000000000000000000000000000000000004"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffec7c06de7e7d060da46f9721814db6bb8a757e1990dfeffbc755bf904891267a5"), common.FromHex("3078346661643546393435316241376538343261453541313861373837384337"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffecc034019b449ad16908580172ec972745a229ec6575a8d785eaa22043f92c453"), common.FromHex("302e303100000000000000000000000000000000000000000000000000000008"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffee5126a4d711f2dd98aa7df46b100c291503dddb43ad8180ae07f600704524a9d"), common.FromHex("64696172696f000000000000000000000000000000000000000000000000000c"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffeea7809e925a8989e20c901c4c1da82f0ba29b26797760d445a0ce4cf3c6fbd31"), common.FromHex("326145354131386137383738433730413866363833443463272c707265737461"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffeeec2ab63f4cd97b3799d9fb76fab247ec6b49ef064d9b5e6c242d49631a19ee9"), common.FromHex("6f3a273330272c696e74657265733a27302e3031272c706572696f646f3a2764"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5c0f7243fabf97f7aaeb04271aaae22d9910e5cd5f7e4d3d2f89fd2077720fffffffffffffffef76728ee203b7869385938b10d9d385e883ea5378fc8ce427206a4af1c4a4d56"), common.FromHex("3041386636383344346300000000000000000000000000000000000000000000"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5e9fe82a4e3417ee6ee9ae3849ea5b3bf0775b389702350e4deb26a840864fffffffffffffffe036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5e9fe82a4e3417ee6ee9ae3849ea5b3bf0775b389702350e4deb26a840864fffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("6090a6e47849629b7245dfa1ca21d94cd15878ef"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5e9fe82a4e3417ee6ee9ae3849ea5b3bf0775b389702350e4deb26a840864fffffffffffffffe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"), common.FromHex("daedbbbfe54ca160687b576b20ad07d92204921c"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5e9fe82a4e3417ee6ee9ae3849ea5b3bf0775b389702350e4deb26a840864fffffffffffffffe8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b"), common.FromHex("470de4df820000"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5e9fe82a4e3417ee6ee9ae3849ea5b3bf0775b389702350e4deb26a840864fffffffffffffffeb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), common.FromHex("59256385"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5edad29c97322a16da6a4018e5f9bbfb3faa334d30c7f9e884027f6641e72fffffffffffffffe036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"), common.FromHex("01"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5edad29c97322a16da6a4018e5f9bbfb3faa334d30c7f9e884027f6641e72fffffffffffffffe290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"), common.FromHex("6090a6e47849629b7245dfa1ca21d94cd15878ef"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5edad29c97322a16da6a4018e5f9bbfb3faa334d30c7f9e884027f6641e72fffffffffffffffe405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace"), common.FromHex("7d0ce0a73c314bc52f1fa294a6d1be72fb0b4061"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5edad29c97322a16da6a4018e5f9bbfb3faa334d30c7f9e884027f6641e72fffffffffffffffe8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b"), common.FromHex("03311fc80a570000"))
	db.Put(dbutils.StorageBucket, common.FromHex("d5f5edad29c97322a16da6a4018e5f9bbfb3faa334d30c7f9e884027f6641e72fffffffffffffffeb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), common.FromHex("5925ea4f"))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fe"), common.FromHex(""))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fe03"), common.FromHex("493514c23d330024734064bc01f9b1b8d06515384313b4b5ff6fc583ffa90d07"))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fe2f"), common.FromHex("b0972cc625233790575f7adc5d292ce1fb2840c507de008134e989af702e3961"))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f53118ca6b46ee351687e841c56dcf6c28b94fe3cd677e9e3819c5db0845fe74"), common.FromHex("5ab7c23abe24b020f53c8546ec1a9168afce4a4a4cfdebc652d9410635f2e8d6"))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f53d"), common.FromHex("5eeb508dd00ba7ad5de8efb18cad0da5fac6d5540817993e514de0fa0cfc40e8"))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f548"), common.FromHex("3981e83334facff539e2ad4041f8d75e4c2fc76377dfdbf4cb7b7c5ec3bf6901"))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f580"), common.FromHex("73f14d227cb392473641d282076596ca2c8e5b652685b9d9dff283d19da41e8d"))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f59d"), common.FromHex("c8f307b75506bc89e9f898568934145ddec3760a0afab2d468fc89a5f395ae46"))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f5d2"), common.FromHex("695e44d35f8c28e4e2eff849a55af89b3eab6f7109fcecd11772273f1087cb74"))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f5e3"), common.FromHex("ea6ca199f0858a3d8d6cd947fc3736e68e5e8eef9e495b4ac29d43603cf1ab90"))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f5e9fe82a4e3417ee6ee9ae3849ea5b3bf0775b389702350e4deb26a840864"), common.FromHex(""))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f5edad29c97322a16da6a4018e5f9bbfb3faa334d30c7f9e884027f6641e72"), common.FromHex(""))
	db.Put(dbutils.IntermediateTrieHashBucket, common.FromHex("d5f5fd"), common.FromHex("3ccc5f2a6ba23bfa0f405ce7439eac4037a9f5d6b922b9562e16476f5c144a8e"))	
	{
		// Resolver with just 1 request
		resolver := NewResolver(0, true, 0)
		tr := New(common.Hash{})
		resolver.AddRequest(tr.NewResolveRequest(nil, common.FromHex("0d050f0503"), 5, common.FromHex("8894372f37cc47e5b342f1caca60668089cf12c95a7984f1d73d220c325fffa9")))
		err := resolver.ResolveStateful(db, 0)
		assert.NoError(err)
	}
	{
		// Resolver with just 2 requests
		resolver := NewResolver(0, true, 0)
		tr := New(common.Hash{})
		resolver.AddRequest(tr.NewResolveRequest(nil, common.FromHex("0d050f0500"), 5, common.FromHex("c2c50923bc4eaafa0bbe534d9f15b8c17193852c055ebf0d84a413ca1aa15459")))
		resolver.AddRequest(tr.NewResolveRequest(nil, common.FromHex("0d050f0503"), 5, common.FromHex("8894372f37cc47e5b342f1caca60668089cf12c95a7984f1d73d220c325fffa9")))
		err := resolver.ResolveStatefulCached(db, 0)
		assert.NoError(err)
	}
}
