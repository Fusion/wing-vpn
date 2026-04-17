package config

type Config struct {
	Interface     string `json:"interface"`
	PrivateKey    string `json:"private_key"`
	MyPublicKey   string `json:"my_public_key"`
	MyEndpoint    string `json:"my_endpoint"`
	Address       string `json:"address"` // e.g. "10.7.0.1/32"
	ListenPort    int    `json:"listen_port"`
	MTU           int    `json:"mtu"`
	DisableRoutes bool   `json:"disable_routes"`
	Peers         []Peer `json:"peers"`
}

type Peer struct {
	Name       string   `json:"name"`
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint"`    // "host:port"
	AllowedIPs []string `json:"allowed_ips"` // only /32 in this minimal version
	Keepalive  int      `json:"keepalive"`   // seconds
}

type State struct {
	ConfigInterface string   `json:"config_interface"`
	OSInterface     string   `json:"os_interface"`
	DisableRoutes   bool     `json:"disable_routes"`
	AllowedIPs      []string `json:"allowed_ips"`
	PID             int      `json:"pid"`
	CreatedAt       string   `json:"created_at"`
}
