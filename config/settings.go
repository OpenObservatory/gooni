package config

var websiteCategories = []string{
	"ALDR",
	"ANON",
	"COMM",
	"COMT",
	"CTRL",
	"CULTR",
	"DATE",
	"ECON",
	"ENV",
	"FILE",
	"GAME",
	"GMB",
	"GOVT",
	"GRP",
	"HACK",
	"HATE",
	"HOST",
	"HUMR",
	"IGO",
	"LGBT",
	"MILX",
	"MMED",
	"NEWS",
	"POLR",
	"PORN",
	"PROV",
	"PUBH",
	"REL",
	"SRCH",
	"XED",
}

// NettestConfig represents the configuration for a particular nettest
type NettestConfig struct {
	Name    string
	Options string
}

// Websites test group
type Websites struct {
	EnabledCategories []string `json:"enabled_categories"`
	Limit             int      `json:"limit"`
}

// NettestConfigs returns a list configured enabled tests for the group
func (s *Websites) NettestConfigs() []NettestConfig {
	var nts []NettestConfig
	nts = append(nts, NettestConfig{"web_connectivity", "options"})
	return nts
}

// InstantMessaging nettest group
type InstantMessaging struct {
	EnabledTests []string `json:"enabled_tests"`
}

func (s *InstantMessaging) isEnabled(nt string) bool {
	for _, v := range s.EnabledTests {
		if v == nt {
			return true
		}
	}
	return false
}

// NettestConfigs returns a list configured enabled tests for the group
func (s *InstantMessaging) NettestConfigs() []NettestConfig {
	var nts []NettestConfig
	if s.isEnabled("facebook_messenger") {
		nts = append(nts, NettestConfig{"facebook_messenger", "options"})
	}
	if s.isEnabled("telegram") {
		nts = append(nts, NettestConfig{"telegram", "options"})
	}
	if s.isEnabled("whatsapp") {
		nts = append(nts, NettestConfig{"whatsapp", "options"})
	}
	return nts
}

// Performance nettest group
type Performance struct {
	NDTServer      string `json:"ndt_server"`
	NDTServerPort  string `json:"ndt_server_port"`
	DashServer     string `json:"dash_server"`
	DashServerPort string `json:"dash_server_port"`
}

// Middlebox nettest group
type Middlebox struct {
	EnabledTests []string `json:"enabled_tests"`
}

// NettestGroups related settings
type NettestGroups struct {
	Websites         Websites         `json:"websites"`
	InstantMessaging InstantMessaging `json:"instant_messaging"`
	Performance      Performance      `json:"performance"`
	Middlebox        Middlebox        `json:"middlebox"`
}

// Notifications settings
type Notifications struct {
	Enabled                bool `json:"enabled"`
	NotifyOnTestCompletion bool `json:"notify_on_test_completion"`
	NotifyOnNews           bool `json:"notify_on_news"`
}

// Sharing settings
type Sharing struct {
	IncludeIP      bool `json:"include_ip"`
	IncludeASN     bool `json:"include_asn"`
	IncludeCountry bool `json:"include_country"`
	IncludeGPS     bool `json:"include_gps"`
	UploadResults  bool `json:"upload_results"`
}

// Advanced settings
type Advanced struct {
	UseDomainFronting bool   `json:"use_domain_fronting"`
	SendCrashReports  bool   `json:"send_crash_reports"`
	CollectorURL      string `json:"collector_url"`
	BouncerURL        string `json:"bouncer_url"`
}

// AutomatedTesting settings
type AutomatedTesting struct {
	Enabled          bool     `json:"enabled"`
	EnabledTests     []string `json:"enabled_tests"`
	MonthlyAllowance string   `json:"monthly_allowance"`
}
