package ethdb

import (
	"context"
	"fmt"
	"strconv"

	"github.com/dgraph-io/badger/v2"
	"github.com/ledgerwatch/bolt"
	"github.com/ledgerwatch/turbo-geth/common/dbutils"
	"github.com/ledgerwatch/turbo-geth/ethdb/remote"
)

type DbProvider uint8

const (
	Bolt DbProvider = iota
	Badger
	Remote
)

const DefaultProvider = Bolt

type Options struct {
	provider DbProvider
	Remote   remote.DbOpts
	Bolt     *bolt.Options
	Badger   badger.Options

	path string
}

func Opts() Options {
	return ProviderOpts(DefaultProvider)
}

func (opts Options) Path(path string) Options {
	opts.path = path
	switch opts.provider {
	case Bolt:
		// nothing to do
	case Badger:
		opts.Badger.WithDir(path).WithValueDir(path)
	case Remote:
		opts.Remote.Addr(path)
	}
	return opts
}

func (opts Options) InMemory(val bool) Options {
	switch opts.provider {
	case Bolt:
		opts.Bolt.MemOnly = val
	case Badger:
		opts.Badger.WithInMemory(val)
	case Remote:
		panic("not supported")
	}
	return opts
}

func ProviderOpts(provider DbProvider) Options {
	opts := Options{}
	switch opts.provider {
	case Bolt:
		opts.Bolt = bolt.DefaultOptions
	case Badger:
		opts.Badger = badger.DefaultOptions(opts.path)
	case Remote:
		opts.Remote = remote.DefaultOpts
	default:
		panic("unknown db provider: " + strconv.Itoa(int(provider)))
	}

	return opts
}

type DB struct {
	opts   Options
	bolt   *bolt.DB
	badger *badger.DB
	remote *remote.DB
}

var buckets = [][]byte{
	dbutils.IntermediateTrieHashBucket,
}

func Open(ctx context.Context, opts Options) (db *DB, err error) {
	db = &DB{opts: opts}

	switch db.opts.provider {
	case Bolt:
		db.bolt, err = bolt.Open(opts.path, 0600, opts.Bolt)
		if err != nil {
			return nil, err
		}
		err = db.bolt.Update(func(tx *bolt.Tx) error {
			for _, name := range buckets {
				_, createErr := tx.CreateBucketIfNotExists(name, false)
				if createErr != nil {
					return createErr
				}
			}
			return nil
		})
	case Badger:
		db.badger, err = badger.Open(opts.Badger)
	case Remote:
		db.remote, err = remote.Open(ctx, opts.Remote)
	}
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Close closes DB
// All transactions must be closed before closing the database.
func (db *DB) Close() error {
	switch db.opts.provider {
	case Bolt:
		return db.bolt.Close()
	case Badger:
		return db.badger.Close()
	case Remote:
		return db.remote.Close()
	}
	return nil
}

type Tx struct {
	db *DB

	bolt   *bolt.Tx
	badger *badger.Txn
	remote *remote.Tx

	badgerIterators []*badger.Iterator
}

type Bucket struct {
	tx *Tx

	bolt         *bolt.Bucket
	badgerPrefix []byte
	nameLen      uint
	remote       *remote.Bucket
}

type Cursor struct {
	opts   CursorOpts
	bucket *Bucket

	bolt   *bolt.Cursor
	badger *badger.Iterator
	remote *remote.Cursor

	k []byte
	v []byte
}

func (db *DB) View(ctx context.Context, f func(tx *Tx) error) (err error) {
	t := &Tx{db: db}
	switch db.opts.provider {
	case Bolt:
		return db.bolt.View(func(tx *bolt.Tx) error {
			defer t.cleanup()
			t.bolt = tx
			return f(t)
		})
	case Badger:
		return db.badger.View(func(tx *badger.Txn) error {
			defer t.cleanup()
			t.badger = tx
			return f(t)
		})
	case Remote:
		return db.remote.View(ctx, func(tx *remote.Tx) error {
			t.remote = tx
			return f(t)
		})
	}
	return err
}

func (db *DB) Update(ctx context.Context, f func(tx *Tx) error) (err error) {
	t := &Tx{db: db}
	switch db.opts.provider {
	case Bolt:
		return db.bolt.Update(func(tx *bolt.Tx) error {
			defer t.cleanup()
			t.bolt = tx
			return f(t)
		})
	case Badger:
		return db.badger.Update(func(tx *badger.Txn) error {
			defer t.cleanup()
			t.badger = tx
			return f(t)
		})
	case Remote:
		return fmt.Errorf("remote db provider doesn't support .Update method")
	}
	return err
}

func (tx *Tx) Bucket(name []byte) (b *Bucket, err error) {
	b = &Bucket{tx: tx, nameLen: uint(len(name))}
	switch tx.db.opts.provider {
	case Bolt:
		b.bolt = tx.bolt.Bucket(name)
	case Badger:
		b.badgerPrefix = name
	case Remote:
		b.remote, err = tx.remote.Bucket(name)
	}
	return b, err
}

func (tx *Tx) cleanup() {
	switch tx.db.opts.provider {
	case Bolt:
		// nothing to cleanup
	case Badger:
		for _, it := range tx.badgerIterators {
			it.Close()
		}
	case Remote:
		// nothing to cleanup
	}
}

type CursorOpts struct {
	provider DbProvider

	remote remote.CursorOpts
	badger badger.IteratorOptions
}

func (opts CursorOpts) PrefetchSize(v uint) CursorOpts {
	switch opts.provider {
	case Bolt:
		// nothing to do
	case Badger:
		opts.badger.PrefetchSize = int(v)
	case Remote:
		opts.remote.PrefetchSize(uint64(v))
	}
	return opts
}

func (opts CursorOpts) PrefetchValues(v bool) CursorOpts {
	switch opts.provider {
	case Bolt:
		// nothing to do
	case Badger:
		opts.badger.PrefetchValues = v
	case Remote:
		opts.remote.PrefetchValues(v)
	}
	return opts
}

func (b *Bucket) CursorOpts() CursorOpts {
	c := CursorOpts{}
	switch b.tx.db.opts.provider {
	case Bolt:
		// nothing to do
	case Badger:
		opts := badger.DefaultIteratorOptions
		opts.Prefix = b.badgerPrefix[:b.nameLen]
		c.badger = opts
	case Remote:
		c.remote = remote.DefaultCursorOpts
	}

	return c
}

func (b *Bucket) Get(key []byte) (val []byte, err error) {
	switch b.tx.db.opts.provider {
	case Bolt:
		val, _ = b.bolt.Get(key)
	case Badger:
		var item *badger.Item
		b.badgerPrefix = append(b.badgerPrefix[:b.nameLen], key...)
		item, err = b.tx.badger.Get(b.badgerPrefix)
		if item != nil {
			val, err = item.ValueCopy(nil) // can improve this by using pool
		}
	case Remote:
		val, err = b.remote.Get(key)
	}
	return val, err
}

func (b *Bucket) Put(key []byte, value []byte) error {
	switch b.tx.db.opts.provider {
	case Bolt:
		return b.bolt.Put(key, value)
	case Badger:
		b.badgerPrefix = append(b.badgerPrefix[:b.nameLen], key...)
		return b.tx.badger.Set(b.badgerPrefix, value)
	case Remote:
		panic("not supported")
	}
	return nil
}

func (b *Bucket) Delete(key []byte) error {
	switch b.tx.db.opts.provider {
	case Bolt:
		return b.bolt.Delete(key)
	case Badger:
		b.badgerPrefix = append(b.badgerPrefix[:b.nameLen], key...)
		return b.tx.badger.Delete(b.badgerPrefix)
	case Remote:
		panic("not supported")
	}
	return nil
}

func (b *Bucket) Cursor(opts CursorOpts) (c *Cursor, err error) {
	c = &Cursor{bucket: b, opts: opts}
	switch c.bucket.tx.db.opts.provider {
	case Bolt:
		c.bolt = b.bolt.Cursor()
	case Badger:
		opts.badger.Prefix = b.badgerPrefix[:b.nameLen] // set bucket
		c.badger = b.tx.badger.NewIterator(opts.badger)
		// add to auto-cleanup on end of transactions
		if b.tx.badgerIterators == nil {
			b.tx.badgerIterators = make([]*badger.Iterator, 0, 1)
		}
		b.tx.badgerIterators = append(b.tx.badgerIterators, c.badger)

	case Remote:
		c.remote, err = b.remote.Cursor(opts.remote)
	}
	return c, err
}

func (c *Cursor) First() ([]byte, []byte, error) {
	var err error
	switch c.bucket.tx.db.opts.provider {
	case Bolt:
		c.k, c.v = c.bolt.First()
	case Badger:
		c.badger.Rewind()
		if !c.badger.Valid() {
			c.k = nil
			break
		}
		item := c.badger.Item()
		c.k = item.Key()
		if c.opts.badger.PrefetchValues {
			c.v, err = item.ValueCopy(c.v)
		}
	case Remote:
		c.k, c.v, err = c.remote.First()
	}
	return c.k, c.v, err
}

func (c *Cursor) Seek(seek []byte) ([]byte, []byte, error) {
	var err error
	switch c.bucket.tx.db.opts.provider {
	case Bolt:
		c.k, c.v = c.bolt.Seek(seek)
	case Badger:
		c.bucket.badgerPrefix = append(c.bucket.badgerPrefix[:c.bucket.nameLen], seek...)
		c.badger.Seek(c.bucket.badgerPrefix)
		if !c.badger.Valid() {
			c.k = nil
			break
		}
		item := c.badger.Item()
		c.k = item.Key()
		if c.opts.badger.PrefetchValues {
			c.v, err = item.ValueCopy(c.v)
		}
	case Remote:
		c.k, c.v, err = c.remote.Seek(seek)
	}
	return c.k, c.v, err
}

func (c *Cursor) Next() ([]byte, []byte, error) {
	var err error
	switch c.bucket.tx.db.opts.provider {
	case Bolt:
		c.k, c.v = c.bolt.Next()
	case Badger:
		c.badger.Next()
		if !c.badger.Valid() {
			c.k = nil
			break
		}
		item := c.badger.Item()
		c.k = item.Key()
		if c.opts.badger.PrefetchValues {
			c.v, err = item.ValueCopy(c.v)
		}
	case Remote:
		return c.remote.Next()
	}
	return c.k, c.v, err
}

func (c *Cursor) FirstKey() (k []byte, vSize uint64, err error) {
	switch c.bucket.tx.db.opts.provider {
	case Bolt:
		var v []byte
		k, v = c.bolt.First()
		vSize = uint64(len(v))
	case Badger:
		c.badger.Rewind()
		if !c.badger.Valid() {
			c.k = nil
			break
		}
		item := c.badger.Item()
		k = item.Key()
		vSize = uint64(item.ValueSize())
	case Remote:
		var vIsEmpty bool
		k, vIsEmpty, err = c.remote.FirstKey()
		if !vIsEmpty {
			vSize = 1
		}
	}
	return k, vSize, err
}

func (c *Cursor) SeekKey(seek []byte) ([]byte, uint64, error) {
	var vSize uint64
	var err error
	switch c.bucket.tx.db.opts.provider {
	case Bolt:
		var v []byte
		c.k, v = c.bolt.Seek(seek)
		vSize = uint64(len(v))
	case Badger:
		c.bucket.badgerPrefix = append(c.bucket.badgerPrefix[:c.bucket.nameLen], seek...)
		c.badger.Seek(c.bucket.badgerPrefix)
		if !c.badger.Valid() {
			c.k = nil
			break
		}
		item := c.badger.Item()
		c.k = item.Key()
		vSize = uint64(item.ValueSize())
	case Remote:
		var vIsEmpty bool
		c.k, vIsEmpty, err = c.remote.SeekKey(seek)
		if !vIsEmpty {
			vSize = 1
		}
	}
	return c.k, vSize, err
}

func (c *Cursor) NextKey() ([]byte, uint64, error) {
	var vSize uint64
	var err error

	switch c.bucket.tx.db.opts.provider {
	case Bolt:
		var v []byte
		c.k, v = c.bolt.Next()
		vSize = uint64(len(v))
	case Badger:
		c.badger.Next()
		if !c.badger.Valid() {
			c.k = nil
			break
		}
		item := c.badger.Item()
		c.k = item.Key()
		vSize = uint64(item.ValueSize())
	case Remote:
		var vIsEmpty bool
		c.k, vIsEmpty, err = c.remote.NextKey()
		if !vIsEmpty {
			vSize = 1
		}
	}
	return c.k, vSize, err
}