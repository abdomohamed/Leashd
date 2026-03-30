package config

// Config is the parsed representation of a project's rules.yaml.
type Config struct {
	Version       string        `yaml:"version"`
	Project       Project       `yaml:"project"`
	Defaults      Defaults      `yaml:"defaults"`
	Rules         []Rule        `yaml:"rules"`
	Notifications Notifications `yaml:"notifications"`
}

type Project struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

type Defaults struct {
	// Action is the verdict for connections not matched by any rule: "allow", "warn", or "block".
	Action string `yaml:"action"`
	Log    bool   `yaml:"log"`
}

type Rule struct {
	ID      string   `yaml:"id"`
	Comment string   `yaml:"comment"`
	Domains []string `yaml:"domains"` // may include wildcards like *.example.com
	CIDRs   []string `yaml:"cidrs"`   // CIDR notation e.g. 10.0.0.0/8
	IPs     []string `yaml:"ips"`     // exact IPs
	Ports   []uint16 `yaml:"ports"`   // empty = all ports
	Action  string   `yaml:"action"`  // "allow", "warn", or "block"
}

type Notifications struct {
	Terminal bool     `yaml:"terminal"`
	JSONLog  string   `yaml:"json_log"`
	Webhook  *Webhook `yaml:"webhook,omitempty"`
}

type Webhook struct {
	URL string   `yaml:"url"`
	On  []string `yaml:"on"` // e.g. ["block", "warn"]
}
