package page

import (
	"sync"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/entitlements"
)

type PageStore struct {
	handlers map[string]PageHandler
	log      logr.Logger
	mu       sync.RWMutex
	onUpdate func()
}

func NewPageStore(host string, onUpdate func(), log logr.Logger) *PageStore {
	return &PageStore{
		handlers: map[string]PageHandler{},
		onUpdate: onUpdate,
		log:      log,
	}
}

func (s *PageStore) Count() int {
	s.log.V(3).Info("count")
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.handlers)
}

func (s *PageStore) Delete(name string) {
	s.log.V(3).Info("delete", "name", name)
	s.mu.Lock()
	if _, ok := s.handlers[name]; !ok {
		s.mu.Unlock()
		return
	}
	delete(s.handlers, name)
	s.mu.Unlock()
	if s.onUpdate != nil {
		s.onUpdate()
	}
}

func (s *PageStore) Get(name string) (PageHandler, bool) {
	s.log.V(3).Info("get", "name", name)
	s.mu.RLock()
	defer s.mu.RUnlock()
	page, ok := s.handlers[name]
	return page, ok
}

func (s *PageStore) List() []PageHandler {
	s.log.V(3).Info("list")
	s.mu.RLock()
	defer s.mu.RUnlock()
	pages := make([]PageHandler, 0, len(s.handlers))
	for _, page := range s.handlers {
		pages = append(pages, page)
	}
	return pages
}

func (s *PageStore) Set(handler PageHandler) {
	s.log.V(3).Info("set", "name", handler.Name)
	s.mu.Lock()
	s.handlers[handler.Name] = handler
	s.mu.Unlock()
	if s.onUpdate != nil {
		s.onUpdate()
	}
}

func (s *PageStore) UpdateParsedRequirements(name string, parsed entitlements.ParsedRequirements) {
	s.log.V(3).Info("update parsed requirements", "name", name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if handler, ok := s.handlers[name]; ok {
		handler.ParsedRequirements = &parsed
		s.handlers[name] = handler
	}
}
