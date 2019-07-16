package auth

import (
	"github.com/bilibili/kratos/pkg/ecode"
	bm "github.com/bilibili/kratos/pkg/net/http/blademaster"
	"github.com/bilibili/kratos/pkg/net/metadata"
)

// Config is the identify config model.
type Config struct {
	// csrf switch.
	DisableCSRF bool
	JwtSecret   string
	Filters     []string
}

// Auth is the authorization middleware
type Auth struct {
	conf *Config
}

// authFunc will return mid and error by given context
type authFunc func(*bm.Context) (int64, error)

var _defaultConf = &Config{
	DisableCSRF: false,
	JwtSecret:   "",
	Filters:     []string{},
}

// New is used to create an authorization middleware
func New(conf *Config) *Auth {
	if conf == nil {
		conf = _defaultConf
	}
	auth := &Auth{
		conf: conf,
	}
	return auth
}

// User is used to mark path as access required.
// If `Cookie` is exist in request form, it will using mobile access policy.
// Otherwise to web access policy.
func (a *Auth) User(ctx *bm.Context) {
	req := ctx.Request
	if req.Header.Get(TypeCookie) == "" {
		a.UserWeb(ctx)
		return
	}
	a.UserMobile(ctx)
}

// UserWeb is used to mark path as web access required.
func (a *Auth) UserWeb(ctx *bm.Context) {
	a.midAuth(ctx, a.authCookie)
}

// UserMobile is used to mark path as mobile access required.
func (a *Auth) UserMobile(ctx *bm.Context) {
	a.midAuth(ctx, a.authToken)
}

// Guest is used to mark path as guest policy.
// If `Cookie` is exist in request form, it will using mobile access policy.
// Otherwise to web access policy.
func (a *Auth) Guest(ctx *bm.Context) {
	req := ctx.Request
	if req.Header.Get(TypeCookie) == "" {
		a.GuestWeb(ctx)
		return
	}
	a.GuestMobile(ctx)
}

// GuestWeb is used to mark path as web guest policy.
func (a *Auth) GuestWeb(ctx *bm.Context) {
	a.guestAuth(ctx, a.authCookie)
}

// GuestMobile is used to mark path as mobile guest policy.
func (a *Auth) GuestMobile(ctx *bm.Context) {
	a.guestAuth(ctx, a.authToken)
}

// authToken is used to authorize request by token
func (a *Auth) authToken(ctx *bm.Context) (mid int64, err error) {
	// NOTE: 请求登录鉴权服务接口，拿到对应的用户id
	req := ctx.Request
	token := req.Header.Get(TypeToken)
	mid, err = VerifyToken(a.conf.JwtSecret, token)
	return
}

// authCookie is used to authorize request by cookie
func (a *Auth) authCookie(ctx *bm.Context) (mid int64, err error) {
	// NOTE: 请求登录鉴权服务接口，拿到对应的用户id
	req := ctx.Request
	session, _ := req.Cookie(CookieKey)
	if session == nil {
		err = _failTokenError
		return
	}
	token := session.Value
	mid, err = VerifyToken(a.conf.JwtSecret, token)
	if err != nil {
		return
	}
	// check csrf
	//clientCsrf := req.FormValue("csrf")
	//if a.conf != nil && !a.conf.DisableCSRF && req.Method == "POST" {
	//	// NOTE: 如果开启了CSRF认证，请从CSRF服务获取该用户关联的csrf
	//	var csrf string // TODO: get csrf from some code
	//	if clientCsrf != csrf {
	//		return 0, ecode.Unauthorized
	//	}
	//}
	return
}

func (a *Auth) midAuth(ctx *bm.Context, auth authFunc) {
	mid, err := auth(ctx)
	if err != nil {
		ctx.JSON(nil, err)
		ctx.Abort()
		return
	}
	setMid(ctx, mid)
}

func (a *Auth) guestAuth(ctx *bm.Context, auth authFunc) {
	mid, err := auth(ctx)
	// no error happened and mid is valid
	if err == nil && mid > 0 {
		setMid(ctx, mid)
		return
	}

	ec := ecode.Cause(err)
	if ecode.Equal(ec, ecode.Unauthorized) {
		ctx.JSON(nil, ec)
		ctx.Abort()
		return
	}
}

// set mid into context
// NOTE: This method is not thread safe.
func setMid(ctx *bm.Context, mid int64) {
	ctx.Set(metadata.Mid, mid)
	if md, ok := metadata.FromContext(ctx); ok {
		md[metadata.Mid] = mid
		return
	}
}
