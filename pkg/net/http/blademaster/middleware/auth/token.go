package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/bilibili/kratos/pkg/ecode"
	"github.com/bilibili/kratos/pkg/log"
)

type JWT string

var (
	// _noTokenError 未传 token
	_noTokenError = ecode.Error(ecode.AccessDenied, "令牌未携带")
	// _failTokenError Token格式错误
	_failTokenError = ecode.Error(ecode.Unauthorized, "令牌格式化错误")
	// _expiredTokenError token 过期
	_expiredTokenError = ecode.Error(ecode.Unauthorized, "令牌过期了，请重新登录")
	// _changeTokenError token 被窜改
	_changeTokenError = ecode.Error(ecode.AccessDenied, "令牌坏掉了")
	// 过期间隔 2 hour
	_exp = time.Duration(2 * (60 /*s*/ * 60 /*m*/))
	// test 1 min
	// _exp = time.Duration(1 * 60)
	TypeToken  = "Authorization"
	TypeCookie = "Cookie"
	CookieKey  = "SESSION"
	_br        = "BEARER"
)

/*
iss：JWT token 的签发者
sub：主题
exp：JWT token 过期时间
aud：接收 JWT token 的一方
iat：JWT token 签发时间
nbf：JWT token 生效时间
jti：JWT token ID
*/
type payload struct {
	MID     int64         `json:"mid"`  // 用户ID
	PID     int64         `json:"pid"`  // 父id
	Role    int8          `json:"role"` // 账号角色
	Sub     string        `json:"sub"`
	Aud     string        `json:"aud"`
	Iss     string        `json:"iss"`
	Exp     time.Duration `json:"exp"`
	Nbf     time.Duration `json:"nbf"`
	Name    string        `json:"name"`
	IsAdmin bool          `json:"is_admin"` // 是否管理员
}

/**
token 的类型
token 所使用的加密算法
{
  "typ": "JWT",
  "alg": "HS256"
}
*/
type header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

/*
SIGNATURE
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
*/
func (p payload) NewPayload(mid, pid int64, role int8, isAdmin bool) payload {
	p.MID = mid
	p.PID = pid
	p.IsAdmin = isAdmin
	p.Iss = "iss"
	p.Sub = "sub"
	p.Nbf = now()
	p.Exp = p.Nbf + _exp
	return p
}

func NewToken(secret string, payload payload) JWT {
	head := newHeader()
	//log.Info("secret=%s", hc.JwtSecret)
	head64, payload64, secret265 := hs265(secret, head, payload.string())
	jwt := head64 + "." + payload64 + "." + secret265
	return JWT(jwt)
}

func hs265(secret string, head string, payload string) (hd64 string, pay64 string, sect string) {
	hm := hmac.New(sha256.New, []byte(secret))
	hd64 = base64.URLEncoding.EncodeToString([]byte(head))
	pay64 = base64.URLEncoding.EncodeToString([]byte(payload))
	hm.Write([]byte(hd64 + "." + pay64))
	sect = hex.EncodeToString(hm.Sum(nil))
	return
}

func (jwt JWT) String() string {
	return string(jwt)
}

func VerifyToken(secret, token string) (mid int64, err error) {
	jwt := JWT(token)
	if jwt == "null" || jwt == "" {
		err = _failTokenError
		return
	}
	h, p, sec256 := jwt.parse()
	if now() > p.Exp {
		err = _expiredTokenError
		return
	}
	_, _, sec := hs265(secret, h.string(), p.string())
	if sec256 != sec {
		err = _changeTokenError
		return
	}
	mid = p.MID
	return
}

func (jwt JWT) IsAdmin() bool {
	_, payload, _ := jwt.parse()
	return payload.IsAdmin
}

func (jwt JWT) GetMid() int64 {
	_, payload, _ := jwt.parse()
	return payload.MID
}

func (jwt JWT) GetPid() int64 {
	_, payload, _ := jwt.parse()
	return payload.PID
}

func (jwt JWT) GetName() string {
	_, payload, _ := jwt.parse()
	return payload.Name
}

func newHeader() string {
	header := header{Typ: "JWT", Alg: "HS256"}
	bytes, err := json.Marshal(header)
	if err != nil {
		log.Error("JWT token.header() error(%v)", err)
	}
	return string(bytes)
}

func now() time.Duration {
	return time.Duration(time.Now().Unix())
}

func (jwt JWT) parse() (header, payload, string) {
	sps := strings.Split(jwt.String(), ".")
	var h header
	var p payload
	var secret265 string
	hb, err := base64.URLEncoding.DecodeString(sps[0])
	err = json.Unmarshal(hb, &h)
	pb, err := base64.URLEncoding.DecodeString(sps[1])
	err = json.Unmarshal(pb, &p)
	secret265 = sps[2]
	if err != nil {
		log.Error("JWT token.parse() error(%v)", err)
	}
	return h, p, secret265
}

func (h header) string() string {
	bytes, err := json.Marshal(h)
	if err != nil {
		log.Error("JWT Header.string() error(%v)", err)
	}
	return string(bytes)
}

func (p payload) string() string {
	bytes, err := json.Marshal(p)
	if err != nil {
		log.Error("JWT p.string() error(%v)", err)
	}
	return string(bytes)
}
