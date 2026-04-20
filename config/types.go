package config

type Config struct {
	Interface         string           `json:"interface"`
	PrivateKey        string           `json:"private_key"`
	MyPublicKey       string           `json:"my_public_key"`
	ControlPrivateKey string           `json:"control_private_key"`
	ControlPublicKey  string           `json:"control_public_key"`
	MyEndpoint        string           `json:"my_endpoint"`
	Address           string           `json:"address"` // e.g. "10.7.0.1/32"
	ListenPort        int              `json:"listen_port"`
	MTU               int              `json:"mtu"`
	DisableRoutes     bool             `json:"disable_routes"`
	Daemon            DaemonConfig     `json:"daemon"`
	Rendezvous        RendezvousConfig `json:"rendezvous"`
	Peers             []Peer           `json:"peers"`
}

type Peer struct {
	Name             string   `json:"name"`
	PublicKey        string   `json:"public_key"`
	ControlPublicKey string   `json:"control_public_key,omitempty"`
	Endpoint         string   `json:"endpoint"`          // "host:port"
	DynamicEndpoint  bool     `json:"dynamic_endpoint"`  // allow rendezvous-published endpoint updates
	AllowedIPs       []string `json:"allowed_ips"`       // only /32 in this minimal version
	Keepalive        int      `json:"keepalive"`         // seconds
}

type State struct {
	ConfigInterface string   `json:"config_interface"`
	OSInterface     string   `json:"os_interface"`
	DisableRoutes   bool     `json:"disable_routes"`
	AllowedIPs      []string `json:"allowed_ips"`
	PID             int      `json:"pid"`
	CreatedAt       string   `json:"created_at"`
}

type DaemonConfig struct {
	STUNServers      []string `json:"stun_servers"`
	PublishInterval  int      `json:"publish_interval"`
	FetchInterval    int      `json:"fetch_interval"`
	RetryInitial     int      `json:"retry_initial"`
	RetryMax         int      `json:"retry_max"`
	RecordTTL        int      `json:"record_ttl"`
	AutoKeepalive    bool     `json:"auto_keepalive"`
	ProbePort        int      `json:"probe_port"`
}

type RendezvousConfig struct {
	URL    string   `json:"url"`
	URLs   []string `json:"urls"`
	Listen string   `json:"listen"`
}
