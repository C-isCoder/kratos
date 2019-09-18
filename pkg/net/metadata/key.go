package metadata

// metadata common key
const (
	// Network
	RemoteIP   = "remote_ip"
	RemotePort = "remote_port"
	ServerAddr = "server_addr"
	ClientAddr = "client_addr"

	// Router
	Cluster = "cluster"
	Color   = "color"

	// Trace
	Trace  = "trace"
	Caller = "caller"

	// Timeout
	Timeout = "timeout"

	// Dispatch
	CPUUsage = "cpu_usage"
	Errors   = "errors"
	Requests = "requests"

	// Mirror
	Mirror = "mirror"

	// Device 客户端信息
	Device = "device"

	// Criticality 重要性
	Criticality = "criticality"

	// Token 用户信息 Mid 外网账户用户id
	Mid     = "mid"     // NOTE: ！！！业务可重新修改key名！！！
	Pid     = "pid"     // 用户的父id业务场景：子账号
	IsAdmin = "isAdmin" // 是否是管理员
	Role    = "role"    // 用户身份
	Auth    = "auth"    // 是否校验
)

var outgoingKey = map[string]struct{}{
	Color:       struct{}{},
	RemoteIP:    struct{}{},
	RemotePort:  struct{}{},
	Mirror:      struct{}{},
	Criticality: struct{}{},
}

var incomingKey = map[string]struct{}{
	Caller: struct{}{},
}

// IsOutgoingKey represent this key should propagate by rpc.
func IsOutgoingKey(key string) bool {
	_, ok := outgoingKey[key]
	return ok
}

// IsIncomingKey represent this key should extract from rpc metadata.
func IsIncomingKey(key string) (ok bool) {
	_, ok = outgoingKey[key]
	if ok {
		return
	}
	_, ok = incomingKey[key]
	return
}
