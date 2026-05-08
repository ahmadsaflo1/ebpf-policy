package config

type Settings struct {
	Env    string `default:"prod" env:"ENV"`
	AppDir string
	TmpDir string `default:"/tmp" env:"TMP_DIR"`

	Server struct {
		Host        string   `toml:"host"         default:"" env:"HOST"`
		Port        int      `toml:"port"         default:"4040" env:"PORT"`
		AltPort     int      `toml:"alt_port"     default:"8080" env:"ALT_PORT"`
		WebDir      string   `toml:"web_dir"      default:"web/public" env:"WEB_DIR"`
		CertFile    string   `toml:"cert_file"    default:"" env:"CERT_FILE"`
		CertDir     string   `toml:"cert_dir"     default:"" env:"CERT_DIR"`
		LetsEncrypt bool     `toml:"lets_encrypt" default:"" env:"LETS_ENCRYPT"`
		Contact     string   `toml:"contact"      default:"" env:"CONTACT"`
		Domains     []string `toml:"domains"      default:"" env:"DOMAINS"`
	}

	Nats struct {
		Url string `toml:"url" default:"nats://127.0.0.1:4222" env:"NATS_URL"`
	}

	Postgres struct {
		Host     string `toml:"host"     default:"localhost"       env:"POSTGRES_HOST"`
		Port     int    `toml:"port"     default:"5432"            env:"POSTGRES_PORT"`
		User     string `toml:"user"     default:"ebpf_user"       env:"POSTGRES_USER"`
		Password string `toml:"password" default:""                env:"POSTGRES_PASSWORD"`
		DB       string `toml:"db"       default:"policy_metrics"  env:"POSTGRES_DB"`
	}

	Agent struct {
		Interface string `toml:"interface"  default:"" env:"INTERFACE"`
		AgentID   string `toml:"agent_id"   default:"agent-001" env:"AGENT_ID"`
		ServerURL string `toml:"server_url" default:"http://localhost:8080" env:"SERVER_URL"`
	}
}
