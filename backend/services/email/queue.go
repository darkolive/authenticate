package email

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Reference method expressions to avoid unused-method lints while async queue is disabled.
var (
	_ = (*AsyncEmailQueue).worker
	_ = (*AsyncEmailQueue).retryProcessor
)

// EmailQueueItem represents an email job in the queue
type EmailQueueItem struct {
	ID          string
	Request     EmailRequest
	Attempts    int
	MaxAttempts int
	CreatedAt   time.Time
	NextRetry   time.Time
	OnSuccess   func(*EmailResponse)
	OnError     func(error)
}

// AsyncEmailQueue manages background email sending
type AsyncEmailQueue struct {
	queue       chan *EmailQueueItem
	workers     int
	provider    EmailProvider
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	running     bool
	mutex       sync.RWMutex
	retryQueue  []*EmailQueueItem
	retryTicker *time.Ticker
}

// NewAsyncEmailQueue creates a new async email queue
func NewAsyncEmailQueue(provider EmailProvider, workers int, queueSize int) *AsyncEmailQueue {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &AsyncEmailQueue{
		queue:       make(chan *EmailQueueItem, queueSize),
		workers:     workers,
		provider:    provider,
		ctx:         ctx,
		cancel:      cancel,
		retryQueue:  make([]*EmailQueueItem, 0),
		retryTicker: time.NewTicker(30 * time.Second), // Check for retries every 30 seconds
	}
}

// Start starts the async email queue processing (DISABLED - WASM incompatible)
func (q *AsyncEmailQueue) Start() {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	if q.running {
		return
	}
	
	// DISABLED: Async queue not compatible with WASM
	// All operations fall back to sync mode
	q.running = false
}

// Stop gracefully shuts down the queue
func (q *AsyncEmailQueue) Stop() {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	if !q.running {
		return
	}
	
	q.running = false
	q.cancel()
	close(q.queue)
	q.retryTicker.Stop()
	q.wg.Wait()
}

// QueueEmail adds an email to the async queue
func (q *AsyncEmailQueue) QueueEmail(req EmailRequest, onSuccess func(*EmailResponse), onError func(error)) error {
	q.mutex.RLock()
	defer q.mutex.RUnlock()
	
	if !q.running {
		return fmt.Errorf("email queue is not running")
	}
	
	item := &EmailQueueItem{
		ID:          generateEmailID(),
		Request:     req,
		Attempts:    0,
		MaxAttempts: 3,
		CreatedAt:   time.Now(),
		NextRetry:   time.Now(),
		OnSuccess:   onSuccess,
		OnError:     onError,
	}
	
	select {
	case q.queue <- item:
		return nil
	case <-q.ctx.Done():
		return fmt.Errorf("email queue is shutting down")
	default:
		return fmt.Errorf("email queue is full")
	}
}

// worker processes emails from the queue
//nolint:deadcode // keep for future async queue enablement
//lint:ignore U1000 kept for future async queue enablement
func (q *AsyncEmailQueue) worker(workerID int) {
	defer q.wg.Done()
	
	for {
		select {
		case item, ok := <-q.queue:
			if !ok {
				return // Queue is closed
			}
			q.processEmailItem(item, workerID)
			
		case <-q.ctx.Done():
			return
		}
	}
}

// processEmailItem attempts to send an email
func (q *AsyncEmailQueue) processEmailItem(item *EmailQueueItem, _ int) {
	item.Attempts++
	
	// Send the email
	response, err := q.provider.SendEmail(item.Request)
	
	if err == nil && response != nil && response.Success {
		// Success - call success callback if provided
		if item.OnSuccess != nil {
			item.OnSuccess(response)
		}
		return
	}
	
	// Failed - check if we should retry
	if item.Attempts < item.MaxAttempts {
		// Add to retry queue with exponential backoff
		backoff := time.Duration(item.Attempts*item.Attempts) * time.Minute
		item.NextRetry = time.Now().Add(backoff)
		
		q.mutex.Lock()
		q.retryQueue = append(q.retryQueue, item)
		q.mutex.Unlock()
		return
	}
	
	// Max attempts reached - call error callback
	if item.OnError != nil {
		if err != nil {
			item.OnError(err)
		} else if response != nil {
			item.OnError(fmt.Errorf("email sending failed: %s", response.Error))
		} else {
			item.OnError(fmt.Errorf("email sending failed: unknown error"))
		}
	}
}

// retryProcessor handles retrying failed emails
//nolint:deadcode // keep for future async queue enablement
//lint:ignore U1000 kept for future async queue enablement
func (q *AsyncEmailQueue) retryProcessor() {
	defer q.wg.Done()
	
	for {
		select {
		case <-q.retryTicker.C:
			q.processRetries()
			
		case <-q.ctx.Done():
			return
		}
	}
}

// processRetries checks for emails ready to retry
func (q *AsyncEmailQueue) processRetries() {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	now := time.Now()
	readyToRetry := make([]*EmailQueueItem, 0)
	remaining := make([]*EmailQueueItem, 0)
	
	for _, item := range q.retryQueue {
		if now.After(item.NextRetry) {
			readyToRetry = append(readyToRetry, item)
		} else {
			remaining = append(remaining, item)
		}
	}
	
	q.retryQueue = remaining
	
	// Re-queue items ready for retry
	for _, item := range readyToRetry {
		select {
		case q.queue <- item:
			// Successfully re-queued
		default:
			// Queue is full, keep in retry queue
			q.retryQueue = append(q.retryQueue, item)
		}
	}
}

// generateEmailID creates a unique ID for an email job
func generateEmailID() string {
	return fmt.Sprintf("email_%d", time.Now().UnixNano())
}

// GetQueueStatus returns current queue status
func (q *AsyncEmailQueue) GetQueueStatus() map[string]interface{} {
	q.mutex.RLock()
	defer q.mutex.RUnlock()
	
	return map[string]interface{}{
		"running":      q.running,
		"queue_length": len(q.queue),
		"retry_count":  len(q.retryQueue),
		"workers":      q.workers,
	}
}
