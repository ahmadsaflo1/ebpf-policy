package config

type Settings struct {
	Env    string `default:"prod" env:"ENV"`
	AppDir string
	TmpDir string `default:"/tmp" env:"TMP_DIR"`

	Server struct {
		Host        string   `default:"" env:"HOST"`
		Port        int      `default:"4040" env:"PORT"`
		AltPort     int      `default:"8080" env:"ALT_PORT"`
		WebDir      string   `default:"web/public" env:"WEB_DIR"`
		CertFile    string   `default:"" env:"CERT_FILE"`
		CertDir     string   `default:"" env:"CERT_DIR"`
		LetsEncrypt bool     `default:"" env:"LETS_ENCRYPT"`
		Contact     string   `default:"" env:"CONTACT"`
		Domains     []string `default:"" env:"DOMAINS"`
	}

	Nats struct {
		Url string `default:"nats://127.0.0.1:4222" env:"NATS_URL"`
	}

	Postgres struct {
		Host     string `default:"localhost"       env:"POSTGRES_HOST"`
		Port     int    `default:"5432"            env:"POSTGRES_PORT"`
		User     string `default:"ebpf_user"       env:"POSTGRES_USER"`
		Password string `default:""                env:"POSTGRES_PASSWORD"`
		DB       string `default:"policy_metrics"  env:"POSTGRES_DB"`
	}

	Agent struct {
		Interface string `default:"" env:"INTERFACE"`
		AgentID   string `default:"agent-001" env:"AGENT_ID"`
		ServerURL string `default:"http://localhost:8080" env:"SERVER_URL"`
	}
}
