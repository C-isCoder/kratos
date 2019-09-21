package blademaster

import (
	"github.com/bilibili/kratos/pkg/ecode"
	"github.com/bilibili/kratos/pkg/net/metadata"
	"os"
	"time"
)

// User is used to mark path as access required.
// If `User-Agent` is exist in request form, it will using web access policy.
// Otherwise to web access policy.
// Mobile user-agent format "{platform};{device};{os_version};{app_version}"
// eg "User-Agent":"iOS;iPhone;12.6.1;1.0.0"
var (
	//_session       = "SESSION"
	_authorization = "Authorization"
	_secret        = "JWT_SECRET"
	_bearer        = "Bearer "

	// os env no jwt_secret
	_osEnvError = ecode.Error(ecode.ServerErr, "环境变量缺少JWT_SECRET值")
	// _noTokenError 未传 token
	_noTokenError = ecode.Error(ecode.AccessDenied, "令牌未携带")
	// _failTokenError Token格式错误
	_failTokenError = ecode.Error(ecode.Unauthorized, "令牌格式错误")
	// _expiredTokenError token 过期
	_expiredTokenError = ecode.Error(ecode.Unauthorized, "令牌过期了，请重新登录")
	// _changeTokenError token 被窜改
	_changeTokenError = ecode.Error(ecode.AccessDenied, "令牌坏掉了")
	// 过期间隔 1176 hour 一个周
	_exp = time.Duration(1176 * (60 /*s*/ * 60 /*m*/))
	// test 1 min
	// _exp = time.Duration(1 * 60)
)
var _filter = []string{
	"/ping",
	"/register",
	"/metrics",
	"/metadata",
	"/debug/pprof/profile",
}

func NoAuth(filter []string) {
	if len(filter) == 0 {
		return
	}
	_filter = append(filter, _filter...)
}
func Auth() HandlerFunc {
	return func(c *Context) {
		req := c.Request
		noAuth := false
		for _, v := range _filter {
			if v == req.URL.Path {
				noAuth = true
			}
		}
		if noAuth {
			c.Next()
			return
		}
		key := req.Header.Get(_authorization)
		if key == "" {
			c.JSON(nil, _noTokenError)
			c.Abort()
			return
		}
		secret := os.Getenv(_secret)
		if secret == "" {
			c.JSON(nil, _osEnvError)
			c.Abort()
			return
		}
		// NOTE: 请求登录鉴权服务接口，拿到对应的用户id
		p, err := VerifyToken(secret, key)
		if err != nil {
			c.JSON(nil, err)
			c.Abort()
			return
		}

		c.Set(metadata.Mid, p.MID)
		c.Set(metadata.Pid, p.PID)
		c.Set(metadata.Role, p.Role)
		c.Set(metadata.IsAdmin, p.IsAdmin)
		if md, ok := metadata.FromContext(c); ok {
			md[metadata.Mid] = p.MID
			md[metadata.Pid] = p.PID
			md[metadata.Role] = p.Role
			md[metadata.IsAdmin] = p.IsAdmin
		}
		c.Next()
	}
}
