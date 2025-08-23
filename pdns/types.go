package pdns

// Server represents a PowerDNS server instance.
type Server struct {
	ID         string `json:"id"`
	URL        string `json:"url"`
	DaemonType string `json:"daemon_type,omitempty"`
	Version    string `json:"version,omitempty"`
}

// Zone represents a DNS zone managed by PowerDNS.
type Zone struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type,omitempty"`
	Kind    string   `json:"kind"`
	Serial  int      `json:"serial,omitempty"`
	Masters []string `json:"masters,omitempty"`
	RRsets  []RRSet  `json:"rrsets,omitempty"`
}

// RRSet represents a set of resource records with the same name and type.
type RRSet struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	TTL        int      `json:"ttl"`
	Changetype string   `json:"changetype,omitempty"`
	Records    []Record `json:"records"`
}

// Record represents a single DNS record within an RRSet.
type Record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}
