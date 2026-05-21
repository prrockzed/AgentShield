package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	runLimiters sync.Map
	pruneOnce   sync.Once
)

func startPruner() {
	go func() {
		for range time.Tick(5 * time.Minute) {
			runLimiters.Range(func(k, v any) bool {
				if e, ok := v.(*limiterEntry); ok && time.Since(e.lastSeen) > 5*time.Minute {
					runLimiters.Delete(k)
				}
				return true
			})
		}
	}()
}

func RateLimitRuns() gin.HandlerFunc {
	pruneOnce.Do(startPruner)
	return func(c *gin.Context) {
		key := c.GetString("user_id")
		if key == "" {
			c.Next()
			return
		}

		actual, _ := runLimiters.LoadOrStore(key, &limiterEntry{
			limiter:  rate.NewLimiter(rate.Every(time.Minute/60), 10),
			lastSeen: time.Now(),
		})
		e := actual.(*limiterEntry)
		e.lastSeen = time.Now()

		if !e.limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests,
				gin.H{"error": "rate limit exceeded: 60 requests per minute"})
			return
		}
		c.Next()
	}
}
