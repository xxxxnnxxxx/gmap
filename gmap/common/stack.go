package common

import (
	"sync"
)

type (
	Stack struct {
		top    *node
		length int
		mu     *sync.Mutex
	}
	node struct {
		value interface{}
		prev  *node
	}
)

// Create a new stack
func NewStack() *Stack {
	return &Stack{
		top:    nil,
		length: 0,
		mu:     new(sync.Mutex),
	}
}

// Return the number pof items in the stack
func (p *Stack) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.length
}

// View the top item on the stack
func (p *Stack) Peek() interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.length == 0 {
		return nil
	}
	return p.top.value
}

// Pop the top item of the stack and return it
func (p *Stack) Pop() interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.length == 0 {
		return nil
	}

	n := p.top
	p.top = n.prev
	p.length--
	return n.value
}

// Push a value onto the top of the stack
func (p *Stack) Push(value interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()

	n := &node{value, p.top}
	p.top = n
	p.length++
}

func (p *Stack) NodesValue() []interface{} {
	result := make([]interface{}, 0)
	cursor := p.top
	for {
		if cursor == nil {
			break
		}
		result = append(result, cursor.value)
		cursor = cursor.prev
	}

	return result
}
