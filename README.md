# ebpf-policy

> Distribuerat system för hastighetsbegränsning och IP-blockering med nätverksfiltrering på kärnnivå och centraliserad policyhantering i realtid.

**eBPF/XDP** filtrerar paket direkt i nätverksdrivrutinen — långt innan de når applikationslagret — medan policybeslut distribueras i realtid via **NATS** till samtliga kör-agenter.

---

## Innehållsförteckning

- [Arkitektur](#arkitektur)
- [Dataflöde](#dataflöde)
- [Krav](#krav)
- [Installation](#installation)
- [Köra systemet](#köra-systemet)
- [REST API](#rest-api)
- [Databasschema](#databasschema)
- [Teknologier](#teknologier)

---

## Arkitektur

```
┌──────────────────────────────┐
│         Policy Server        │   Kontrollplan
│   REST API :8080             │
│   SQLite-databas             │
│   Policy-publicering         │
│   Metrikinsamling            │
└──────────────┬───────────────┘
               │
           NATS pub/sub
               │
       ┌───────┴────────┐
       │                │
┌──────▼──────┐  ┌──────▼──────┐
│   Agent 1   │  │   Agent N   │   Kantpunkter (edge nodes)
│   (eBPF)    │  │   (eBPF)    │
└─────────────┘  └─────────────┘
```

### Komponenter

| Komponent | Beskrivning |
|-----------|-------------|
| **Server** | Hanterar policyer via REST API, persisterar regler i SQLite och distribuerar ändringar via NATS |
| **Agent** | Körs på varje nod, laddar eBPF-programmet till kärnan och blockerar IP-adresser som överskrider definierade tröskelvärden |
| **eBPF/XDP** | C-program på kärnnivå som filtrerar paket direkt på nätverksgränssnittsnivå med minimal latens |
| **NATS** | Meddelandebroker som distribuerar policyändringar och aggregerar metrics från samtliga agenter |

### Meddelandekanaler (NATS)

| Ämne | Riktning | Syfte |
|------|----------|-------|
| `policy.update` | Server → Agenter | Ny eller uppdaterad policyregel |
| `policy.delete` | Server → Agenter | Borttagen policyregel |
| `metrics.report` | Agenter → Server | Trafikstatistik per IP, rapporteras var 10:e sekund |

---

## Dataflöde

**Paketfiltrering (per agent):**

```
Inkommande nätverkspaket
  → XDP-program (eBPF, kärnan)
  → Kontrollera block_list
  → Träff:  XDP_DROP  — paketet kasseras omedelbart
  → Miss:   räknaren ökas, XDP_PASS
```

**Policyuppdatering (end-to-end):**

```
PUT /api/rules/:id
  → REST-hanterare validerar och tar emot begäran
  → Regel persisteras i SQLite
  → Ändring publiceras på NATS "policy.update"
  → Agenter tar emot meddelandet och uppdaterar regelcachen
  → Nästa paketkontroll tillämpar den nya regeln
```

---

## Krav

| Beroende | Version |
|----------|---------|
| Ubuntu / Debian Linux | Kernel ≥ 5.9 |
| Go | 1.21+ |
| clang / llvm | Senaste stabila |
| libbpf-dev | Via apt |
| Linux-headers | Matchande aktiv kärna |
| NATS-server | Tillhandahålls separat |

---

## Installation

### 1. Systemberoenden

```bash
sudo apt update && sudo apt install -y \
    clang llvm libbpf-dev \
    linux-headers-$(uname -r) \
    make git gcc
```

### 2. bpf2go

```bash
go install github.com/cilium/ebpf/cmd/bpf2go@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

> Lägg till `export PATH=$PATH:$(go env GOPATH)/bin` i `~/.bashrc` eller `~/.profile` för att göra inställningen permanent.

### 3. Kompilera eBPF-programmet

```bash
cd ebpf && make && cd ..
```

Kompilerar `policy.c` till eBPF-bytekod (`policy.o`) med clang.

### 4. Generera Go-bindningar

```bash
cd internal/agent/ebpf
bpf2go -go-package ebpf Policy ../../../ebpf/policy.c
cd ../../..
```

Genererade filer:

| Fil | Beskrivning |
|-----|-------------|
| `policy_bpfel.go` | Go-bindningar för little-endian (t.ex. x86-64) |
| `policy_bpfeb.go` | Go-bindningar för big-endian |
| `policy_bpfel.o` | Kompilerad eBPF-bytekod för little-endian |
| `policy_bpfeb.o` | Kompilerad eBPF-bytekod för big-endian |

### 5. Bygg binärerna

```bash
go build -o server ./cmd/server/
go build -o agent ./cmd/agent/
```

---

## Köra systemet

### Server

```bash
./server
```

Servern lyssnar på port `:8080` och ansluter till NATS på `nats://localhost:4222` som standard.

| Miljövariabel | Standardvärde | Beskrivning |
|---------------|---------------|-------------|
| `NATS_URL` | `nats://localhost:4222` | Adress till NATS-broker |

### Agent

Agenten kräver root-behörighet för att ladda eBPF-program till kärnan.

```bash
sudo INTERFACE=<gränssnitt> \
     AGENT_ID=<agent-namn> \
     SERVER_URL=http://<server-ip>:8080 \
     NATS_URL=nats://<server-ip>:4222 \
     ./agent
```

| Miljövariabel | Standardvärde | Beskrivning |
|---------------|---------------|-------------|
| `INTERFACE` | `eth0` | Nätverksgränssnitt att övervaka (t.ex. `ens5`, `eth0`) |
| `AGENT_ID` | `agent-001` | Unikt identifierare för denna agent-instans |
| `SERVER_URL` | `http://localhost:8080` | URL till policyservern |
| `NATS_URL` | `nats://localhost:4222` | Adress till NATS-broker |

---

## REST API

Bas-URL: `http://<server>:8080`

| Metod | Endpoint | Beskrivning |
|-------|----------|-------------|
| `GET` | `/health` | Hälsostatus för servern |
| `GET` | `/api/rules` | Lista samtliga policyregler |
| `POST` | `/api/rules` | Skapa ny policyregel |
| `GET` | `/api/rules/:id` | Hämta en specifik regel |
| `PUT` | `/api/rules/:id` | Uppdatera en befintlig regel |
| `DELETE` | `/api/rules/:id` | Ta bort en regel |

### Exempel: Skapa en regel

```bash
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Blockera >500 förfrågningar/s",
    "threshold": 500,
    "action": "block",
    "duration": 60
  }'
```

**Schemafält:**

| Fält | Typ | Beskrivning |
|------|-----|-------------|
| `name` | `string` | Beskrivande namn på regeln |
| `threshold` | `int` | Tröskelvärde i förfrågningar per sekund |
| `action` | `string` | `"block"` eller `"rate_limit"` |
| `duration` | `int` | Blockeringstid i sekunder |

---

## Databasschema

SQLite-databasen (`policy.db`) skapas automatiskt i arbetskatalogen vid uppstart.

**`policy_rules`** — Policyregler:

```sql
id          INTEGER PRIMARY KEY
name        TEXT
threshold   INTEGER
action      TEXT
duration    INTEGER
created_at  DATETIME
```

**`client_stats`** — Trafikstatistik från agenter:

```sql
id           INTEGER PRIMARY KEY
agent_id     TEXT
ip           TEXT
req_per_sec  REAL
blocked      INTEGER
passed       INTEGER
recorded_at  DATETIME
```

---

## Teknologier

| Teknologi | Användning |
|-----------|------------|
| [cilium/ebpf](https://github.com/cilium/ebpf) | Laddar och hanterar eBPF-program från Go |
| [NATS](https://nats.io) | Distribuerad pub/sub-meddelandehantering |
| [Gin](https://github.com/gin-gonic/gin) | HTTP-ramverk för REST API |
| [SQLite](https://sqlite.org) | Lokal relationsdatabas för regler och statistik |
| eBPF/XDP | Nätverksfiltrering på kärnnivå med minimal overhead |
