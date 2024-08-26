package repository

import (
	"sync"
	"time"

	"golang.org/x/exp/maps"
)

type rwmap[K comparable, V any] struct {
	items   map[K]item[V]
	mx      sync.RWMutex
	closeCh chan struct{}
}

type item[V any] struct {
	data    V
	expires int64
}

// NewRWMap creates a simple thread-safe key-value storage.
func NewRWMap[K comparable, V any](cleaningInterval time.Duration) *rwmap[K, V] {
	rwmap := &rwmap[K, V]{
		items:   make(map[K]item[V]),
		closeCh: make(chan struct{}),
	}

	go func() {
		ticker := time.NewTicker(cleaningInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				now := time.Now().UnixNano()

				rwmap.mx.Lock()
				for key, value := range rwmap.items {
					if value.expires > 0 && now > value.expires {
						delete(rwmap.items, key)
					}
				}
				rwmap.mx.Unlock()

			case <-rwmap.closeCh:
				return
			}
		}
	}()

	return rwmap
}

// Get returns value by key.
func (rwmap *rwmap[K, V]) Get(key K) (V, bool) {
	rwmap.mx.RLock()
	defer rwmap.mx.RUnlock()

	value, exists := rwmap.items[key]
	if !exists {
		return value.data, false
	}

	if value.expires > 0 && time.Now().UnixNano() > value.expires {
		delete(rwmap.items, key)
		return value.data, false
	}

	return value.data, true
}

// Set sets value by key.
func (rwmap *rwmap[K, V]) Set(key K, value V, duration time.Duration) {
	var expires int64

	if duration > 0 {
		expires = time.Now().Add(duration).UnixNano()
	}

	rwmap.mx.Lock()
	defer rwmap.mx.Unlock()

	rwmap.items[key] = item[V]{
		data:    value,
		expires: expires,
	}
}

// Delete deletes value by key.
func (rwmap *rwmap[K, V]) Delete(key K) {
	rwmap.mx.Lock()
	delete(rwmap.items, key)
	rwmap.mx.Unlock()
}

// Close closes storage: cleans internal map and stop cleaning work.
func (rwmap *rwmap[K, V]) Close() {
	rwmap.closeCh <- struct{}{}

	rwmap.mx.Lock()
	defer rwmap.mx.Unlock()

	maps.Clear(rwmap.items)
}
