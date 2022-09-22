package parser

import (
	"bufio"
	stdlog "log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/eopenio/slowlog-parser/log"
)

// Regular expressions to match important lines in slow log.
var (
	timeRe    = regexp.MustCompile(`Time: (\S+\s{1,2}\S+)`)
	timeNewRe = regexp.MustCompile(`Time:\s+(\d{4}-\d{2}-\d{2}\S+)`)
	userRe    = regexp.MustCompile(`User@Host: ([^\[]+|\[[^[]+\]).*?@ (\S*) \[(.*)\]`)
	schema    = regexp.MustCompile(`Schema: +(.*?) +Last_errno:`)
	headerRe  = regexp.MustCompile(`^#\s+[A-Z]`)
	metricsRe = regexp.MustCompile(`(\w+): (\S+|\z)`)
	adminRe   = regexp.MustCompile(`command: (.+)`)
	setRe     = regexp.MustCompile(`^SET (?:last_insert_id|insert_id|timestamp)`)
	//setTs     = regexp.MustCompile(`^SET timestamp=\d{10}`)
	setTs = regexp.MustCompile(`^SET timestamp=(\d)+`)
	useRe = regexp.MustCompile(`^(?i)use `)
)

// A SlowLogParser parses a MySQL slow log. It implements the LogParser interface.
type SlowLogParser struct {
	text string
	opt  log.Options
	// --
	inHeader    bool
	inQuery     bool
	headerLines uint
	queryLines  uint64
	event       *log.Event
}

// NewSlowLogParser returns a new SlowLogParser that reads from the open file.
func NewSlowLogParser(opt log.Options) *SlowLogParser {
	if opt.DefaultLocation == nil {
		// Old MySQL format assumes time is taken from SYSTEM.
		opt.DefaultLocation = time.Local
	}
	p := &SlowLogParser{
		opt: opt,
		// --
		inHeader:    false,
		inQuery:     false,
		headerLines: 0,
		queryLines:  0,
		event:       log.NewEvent(),
	}
	return p
}

// logf logs with configured logger.
func (p *SlowLogParser) logf(format string, v ...interface{}) {
	if !p.opt.Debug {
		return
	}
	if p.opt.Debugf != nil {
		p.opt.Debugf(format, v...)
		return
	}
	stdlog.Printf(format, v...)
}

func (p *SlowLogParser) Parser(text string) (*log.Event, error) {

	for _, v := range strings.Split(text, "\n") {
		r := bufio.NewReader(strings.NewReader(v))

		line, _ := r.ReadString('\n')

		lineLen := uint64(len(line))

		if lineLen >= 20 && ((line[0] == '/' && line[lineLen-6:lineLen] == "with:\n") ||
			(line[0:5] == "Time ") ||
			(line[0:4] == "Tcp ") ||
			(line[0:4] == "TCP ")) {
			p.logf("meta")
		}
		// PMM-1834: Filter out empty comments and MariaDB explain:
		if line == "#\n" || strings.HasPrefix(line, "# explain:") {
			p.logf("# explain")
		}

		// Remove \n.
		//line = line[0 : lineLen-1]
		// No Need Remove \n
		line = line[0:lineLen]

		if p.inHeader {
			p.parseHeader(line)
		} else if p.inQuery {
			p.parseQuery(line)
		} else if headerRe.MatchString(line) {
			p.inHeader = true
			p.inQuery = false
			p.parseHeader(line)
		}
	}

	return p.event, nil
}

// --------------------------------------------------------------------------

func (p *SlowLogParser) parseHeader(line string) {
	p.logf("header")

	if !headerRe.MatchString(line) {
		p.inHeader = false
		p.inQuery = true
		p.parseQuery(line)
		return
	}

	p.headerLines++

	if strings.HasPrefix(line, "# Time") {
		p.logf("time")
		m := timeRe.FindStringSubmatch(line)
		if len(m) == 2 {
			//p.event.Ts, _ = time.ParseInLocation("060102 15:04:05", m[1], p.opt.DefaultLocation)
			p.logf("time: %v", m[0])
		} else {
			m = timeNewRe.FindStringSubmatch(line)
			p.logf("time: %v", m)
			if len(m) == 2 {
				p.logf("time: %v", m)
				//p.event.Ts, _ = time.ParseInLocation(time.RFC3339Nano, m[1], p.opt.DefaultLocation)
			} else {
				return
			}
		}
		if userRe.MatchString(line) {
			p.logf("user (bad format)")
			m := userRe.FindStringSubmatch(line)
			p.event.User = m[1]
			p.event.Host = m[2]
		}
	} else if strings.HasPrefix(line, "# User") {
		p.logf("user")
		m := userRe.FindStringSubmatch(line)
		if len(m) < 3 {
			return
		}
		p.event.User = m[1]
		p.event.Host = m[3]
	} else if strings.HasPrefix(line, "# admin") {
		p.parseAdmin(line)
	} else {
		p.logf("metrics")
		submatch := schema.FindStringSubmatch(line)
		if len(submatch) == 2 {
			p.event.Db = submatch[1]
		}

		m := metricsRe.FindAllStringSubmatch(line, -1)
		for _, smv := range m {
			// [String, Metric, Value], e.g. ["Query_time: 2", "Query_time", "2"]
			if strings.HasSuffix(smv[1], "_time") || strings.HasSuffix(smv[1], "_wait") {
				// microsecond value
				val, _ := strconv.ParseFloat(smv[2], 64)
				p.event.TimeMetrics[smv[1]] = val
			} else if smv[2] == "Yes" || smv[2] == "No" {
				// boolean value
				if smv[2] == "Yes" {
					p.event.BoolMetrics[smv[1]] = true
				} else {
					p.event.BoolMetrics[smv[1]] = false
				}
			} else if smv[1] == "Schema" {
				p.event.Db = smv[2]
			} else if smv[1] == "Log_slow_rate_type" {
				p.event.RateType = smv[2]
			} else if smv[1] == "Log_slow_rate_limit" {
				val, _ := strconv.ParseUint(smv[2], 10, 64)
				p.event.RateLimit = uint(val)
			} else {
				// integer value
				val, _ := strconv.ParseUint(smv[2], 10, 64)
				p.event.NumberMetrics[smv[1]] = val
			}
		}
	}
}

func (p *SlowLogParser) parseQuery(line string) {
	p.logf("query")

	if strings.HasPrefix(line, "# admin") {
		p.parseAdmin(line)
		return
	} else if headerRe.MatchString(line) {
		p.logf("next event")
		p.inHeader = true
		p.inQuery = false
		// todo
		p.parseEvent(true, false)
		p.parseHeader(line)
		return
	}

	isUse := useRe.FindString(line)
	if p.queryLines == 0 && isUse != "" {
		p.logf("use db")
		db := strings.TrimPrefix(line, isUse)
		db = strings.TrimRight(db, ";")
		db = strings.Trim(db, "`")
		p.event.Db = db
		p.event.Query = line
	} else if setTs.MatchString(line) {
		m := setTs.FindString(line)
		tsStr := strings.Split(m, "=")
		p.logf("len = %v", len(tsStr))
		if len(tsStr) != 2 {
			p.event.Ts = time.Now().Format("2006-01-02 15:04:15")
		}
		p.logf("tsStr = %s", tsStr[1])
		ts, _ := strconv.ParseInt(tsStr[1], 10, 64)
		p.event.Ts = time.Unix(ts, 0).Format("2006-01-02 15:04:05")
	} else {
		p.logf("query")
		if p.queryLines > 0 {
			p.event.Query += "\n" + line
		} else {
			p.event.Query = line
		}
		p.queryLines++
	}
}

func (p *SlowLogParser) parseAdmin(line string) {
	p.logf("admin")
	p.event.Admin = true
	m := adminRe.FindStringSubmatch(line)
	p.event.Query = m[1]
	p.event.Query = strings.TrimSuffix(p.event.Query, ";") // makes FilterAdminCommand work

	// admin commands should be the last line of the event.
	if filtered := p.opt.FilterAdminCommand[p.event.Query]; !filtered {
		p.logf("not filtered")
		// todo
		p.parseEvent(false, false)
	} else {
		p.inHeader = false
		p.inQuery = false
	}
}

func (p *SlowLogParser) parseEvent(inHeader bool, inQuery bool) error {

	// Make a new event and reset our metadata.
	defer func() {
		p.event = log.NewEvent()
		p.headerLines = 0
		p.queryLines = 0
		p.inHeader = inHeader
		p.inQuery = inQuery
	}()

	// Clean up the event.
	p.event.Db = strings.TrimSuffix(p.event.Db, ";\n")
	p.event.Query = strings.TrimSuffix(p.event.Query, ";")

	return nil
}
