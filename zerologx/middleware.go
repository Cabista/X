package zerologx

import (
	"strconv"
	"time"

	"github.com/labstack/echo"
	"github.com/rs/zerolog/log"
)

//Process logs info about each request using zerolog
func Process(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request()
		res := c.Response()
		start := time.Now()
		info := log.Info()
		if err := next(c); err != nil {
			info.Err(err)
			c.Error(err)
		}
		stop := time.Now()
		dif := stop.Sub(start)

		info.Time("time", start)
		info.Str("remote_addr", c.RealIP())
		info.Str("host", c.Request().Host)
		info.Str("uri", c.Path())
		info.Str("method", c.Request().Method)
		if c.Request().Response != nil {
			info.Int("status", c.Request().Response.StatusCode)
		}

		info.Int64("latency", dif.Nanoseconds())
		info.Str("latency_human", strconv.FormatInt(dif.Microseconds(), 10)+"µs")
		length := req.Header.Get(echo.HeaderContentLength)
		if length == "" {
			length = "0"
		}
		siz, err := strconv.ParseInt(req.Header.Get(echo.HeaderContentLength), 10, 64)
		if err != nil {
			info.Err(err)
		}
		info.Int64("bytes_in", siz)
		info.Int64("bytes_out", res.Size)
		info.Send()
		//Int("bytes_in", len(c.Request))
		return nil
	}
}
