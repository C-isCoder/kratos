package auth

import (
	"github.com/bilibili/kratos/pkg/ecode"
	bm "github.com/bilibili/kratos/pkg/net/http/blademaster"
	"github.com/bilibili/kratos/pkg/net/metadata"
	"os"
	"strings"
	"time"
)

// Config is the identify config model.
type Config struct {
	// csrf switch.
	DisableCSRF bool
	Filters     []string
}

// Auth is the authorization middleware
type Auth struct {
	conf *Config
}

// authFunc will return mid and error by given context
type authFunc func(*bm.Context) (*payload, error)

var _defaultConf = &Config{
	DisableCSRF: false,
	Filters:     make([]string, 0),
}

// newAuth is used to create an authorization middleware
func newAuth(conf *Config) *Auth {
	if conf == nil {
		conf = _defaultConf
	}
	auth := &Auth{
		conf: conf,
	}
	return auth
}

// User is used to mark path as access required.
// If `User-Agent` is exist in request form, it will using web access policy.
// Otherwise to web access policy.
// Mobile user-agent format "{system};{device};{os_version};{app_version};
// eg "User-Agent":"iOS;iPhone;12.6.1;1.0.0"
var (
	//_web           = "Mozilla"
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
	// 过期间隔 2 hour
	_exp = time.Duration(2 * (60 /*s*/ * 60 /*m*/))
	// test 1 min
	// _exp = time.Duration(1 * 60)
)

func New(conf *Config) bm.HandlerFunc {
	return func(ctx *bm.Context) {
		req := ctx.Request
		ok := false
		if conf != nil {
			for _, f := range conf.Filters {
				if strings.Contains(req.RequestURI, f) {
					ok = true
				}
			}
		}
		if ok {
			ctx.Next()
			return
		}
		ah := newAuth(conf)
		ah.User(ctx)
	}
}
func (a *Auth) User(ctx *bm.Context) {
	//req := ctx.Request
	//if strings.HasPrefix(req.UserAgent(), _web) {
	//	a.UserWeb(ctx)
	//	return
	//}
	a.UserMobile(ctx)
}

// UserWeb is used to mark path as web access required.
//func (a *Auth) UserWeb(ctx *bm.Context) {
//	a.midAuth(ctx, a.authCookie)
//}

// UserMobile is used to mark path as mobile access required.
func (a *Auth) UserMobile(ctx *bm.Context) {
	a.midAuth(ctx, a.authToken)
}

// Guest is used to mark path as guest policy.
// If `access_token` is exist in request form, it will using mobile access policy.
// Otherwise to web access policy.
//func (a *Auth) Guest(ctx *bm.Context) {
//	req := ctx.Request
//	if req.UserAgent() == "" {
//		a.GuestMobile(ctx)
//		return
//	}
//	a.GuestWeb(ctx)
//}

// GuestWeb is used to mark path as web guest policy.
//func (a *Auth) GuestWeb(ctx *bm.Context) {
//	a.guestAuth(ctx, a.authCookie)
//}

// GuestMobile is used to mark path as mobile guest policy.
//func (a *Auth) GuestMobile(ctx *bm.Context) {
//	a.guestAuth(ctx, a.authToken)
//}

// authToken is used to authorize request by token
func (a *Auth) authToken(ctx *bm.Context) (*payload, error) {
	req := ctx.Request
	key := req.Header.Get(_authorization)
	if key == "" {
		return nil, _noTokenError
	}
	secret := os.Getenv(_secret)
	if secret == "" {
		return nil, _osEnvError
	}
	// NOTE: 请求登录鉴权服务接口，拿到对应的用户id
	p, err := VerifyToken(secret, key)
	if err != nil {
		return p, err
	}
	return p, nil
}

// authCookie is used to authorize request by cookie
//func (a *Auth) authCookie(ctx *bm.Context) (int64, error) {
//	req := ctx.Request
//	session, _ := req.Cookie(_session)
//	if session == nil {
//		return 0, ecode.Unauthorized
//	}
//	secret := os.Getenv(_secret)
//	if secret == "" {
//		return 0, ecode.Error(-508, "JWT_SECRET not existence on OS env.")
//	}
//	// NOTE: 请求登录鉴权服务接口，拿到对应的用户id
//	mid, err := VerifyToken(secret, session)
//	if err != nil {
//		return 0, err
//	}
//	// check csrf
//	clientCsrf := req.FormValue("csrf")
//	if a.conf != nil && !a.conf.DisableCSRF && req.Method == http.MethodPost {
//		// NOTE: 如果开启了CSRF认证，请从CSRF服务获取该用户关联的csrf
//		var csrf string // TODO: get csrf from some code
//		if clientCsrf != csrf {
//			return 0, ecode.Unauthorized
//		}
//	}
//
//	return mid, nil
//}

func (a *Auth) midAuth(ctx *bm.Context, auth authFunc) {
	p, err := auth(ctx)
	if err != nil {
		ctx.JSON(nil, err)
		ctx.Abort()
		return
	}
	setMetadata(ctx, p)
	ctx.Next()
}

//func (a *Auth) guestAuth(ctx *bm.Context, auth authFunc) {
//	mid, err := auth(ctx)
//	// no error happened and mid is valid
//	if err == nil && mid > 0 {
//		setMetadata(ctx, mid)
//		return
//	}
//
//	ec := ecode.Cause(err)
//	if ecode.Equal(ec, ecode.Unauthorized) {
//		ctx.JSON(nil, ec)
//		ctx.Abort()
//		return
//	}
//}

// set mid into context
// NOTE: This method is not thread safe.
func setMetadata(ctx *bm.Context, p *payload) {
	ctx.Set(metadata.Mid, p.MID)
	ctx.Set(metadata.Pid, p.PID)
	ctx.Set(metadata.Role, p.Role)
	ctx.Set(metadata.IsAdmin, p.IsAdmin)
	if md, ok := metadata.FromContext(ctx); ok {
		md[metadata.Mid] = p.MID
		md[metadata.Pid] = p.PID
		md[metadata.Role] = p.Role
		md[metadata.IsAdmin] = p.IsAdmin
		return
	}
}
