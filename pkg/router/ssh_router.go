package router

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/usma0118/asus-bcm-crowsec-bouncer/pkg/crowdsec"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type SSHRouter struct {
	addr            string
	user            string
	chain           string
	signer          ssh.Signer
	hostKeyCallback ssh.HostKeyCallback
	log             *zap.Logger
}

func NewSSHRouterFromEnv(log *zap.Logger) (*SSHRouter, error) {
	host := os.Getenv("ROUTER_HOST")
	if host == "" {
		return nil, fmt.Errorf("ROUTER_HOST not set")
	}
	port := os.Getenv("ROUTER_PORT")
	if port == "" {
		port = "22"
	}
	addr := host + ":" + port

	userName := os.Getenv("ROUTER_USER")
	if userName == "" {
		userName = "admin"
	}

	keyPath := os.Getenv("ROUTER_SSH_KEY_PATH")
	if keyPath == "" {
		keyPath = "/config/.ssh/id_rsa"
	}

	signer, err := loadPrivateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load ssh key: %w", err)
	}

	var hk ssh.HostKeyCallback
	if os.Getenv("ROUTER_ALLOW_INSECURE_HOSTKEY") == "true" {
		log.Warn("HOSTKEY PINNING DISABLED (ROUTER_ALLOW_INSECURE_HOSTKEY=true) – NOT RECOMMENDED")
		hk = ssh.InsecureIgnoreHostKey()
	} else {
		khPath := os.Getenv("ROUTER_KNOWN_HOSTS_FILE")
		if khPath == "" {
			// fallback to ~/.ssh/known_hosts if present
			if u, err := user.Current(); err == nil {
				khPath = filepath.Join(u.HomeDir, ".ssh", "known_hosts")
			}
		}
		if khPath == "" {
			return nil, fmt.Errorf("ROUTER_KNOWN_HOSTS_FILE not set and no ~/.ssh/known_hosts; can't pin host key")
		}
		hk, err = knownhosts.New(khPath)
		if err != nil {
			return nil, fmt.Errorf("load known_hosts: %w", err)
		}
	}

	chain := os.Getenv("CHAIN_NAME")
	if chain == "" {
		chain = "CROWDSEC"
	}

	return &SSHRouter{
		addr:            addr,
		user:            userName,
		chain:           chain,
		signer:          signer,
		hostKeyCallback: hk,
		log:             log,
	}, nil
}

func loadPrivateKey(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

func (r *SSHRouter) Sync(ctx context.Context, decisions []crowdsec.Decision) error {
	cfg := &ssh.ClientConfig{
		User:            r.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(r.signer)},
		HostKeyCallback: r.hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	conn, err := ssh.Dial("tcp", r.addr, cfg)
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer conn.Close()

	// list existing IPs
	existing, err := r.listIPs(conn)
	if err != nil {
		return fmt.Errorf("list IPs: %w", err)
	}

	desiredSet := make(map[string]crowdsec.Decision, len(decisions))
	for _, d := range decisions {
		desiredSet[d.IP] = d
	}

	existingSet := make(map[string]struct{}, len(existing))
	for _, ip := range existing {
		existingSet[ip] = struct{}{}
	}

	var toAdd []string
	for ip := range desiredSet {
		if _, ok := existingSet[ip]; !ok {
			toAdd = append(toAdd, ip)
		}
	}

	var toDel []string
	for ip := range existingSet {
		if _, ok := desiredSet[ip]; !ok {
			toDel = append(toDel, ip)
		}
	}

	r.log.Info("router diff",
		zap.Int("add", len(toAdd)),
		zap.Int("del", len(toDel)),
	)

	script := r.buildScript(toAdd, toDel)

	if err := r.runScript(conn, script); err != nil {
		return fmt.Errorf("apply diff: %w", err)
	}

	return nil
}

func (r *SSHRouter) listIPs(conn *ssh.Client) ([]string, error) {
	cmd := fmt.Sprintf("iptables -S %q -n 2>/dev/null || true", r.chain)
	out, err := r.runCommand(conn, cmd)
	if err != nil {
		return nil, err
	}

	var ips []string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Example: -A CROWDSEC -s 1.2.3.4/32 -j DROP
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "-s" && i+1 < len(fields) {
				ip := strings.TrimSuffix(fields[i+1], "/32")
				if ip != "" {
					ips = append(ips, ip)
				}
				break
			}
		}
	}
	return ips, nil
}

func (r *SSHRouter) buildScript(toAdd, toDel []string) string {
	var buf bytes.Buffer
	buf.WriteString("set -e\n")
	buf.WriteString(fmt.Sprintf("CHAIN=%q\n", r.chain))
	buf.WriteString(`iptables -N "$CHAIN" 2>/dev/null || true
iptables -S INPUT | grep -F -- "-j $CHAIN" >/dev/null || iptables -I INPUT -j "$CHAIN"
`)

	for _, ip := range toAdd {
		buf.WriteString(fmt.Sprintf(
			"iptables -C \"$CHAIN\" -s '%s' -j DROP 2>/dev/null || iptables -I \"$CHAIN\" -s '%s' -j DROP\n",
			ip, ip,
		))
	}
	for _, ip := range toDel {
		buf.WriteString(fmt.Sprintf(
			"while iptables -D \"$CHAIN\" -s '%s' -j DROP 2>/dev/null; do :; done\n",
			ip,
		))
	}
	return buf.String()
}

func (r *SSHRouter) runScript(conn *ssh.Client, script string) error {
	sess, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	sess.Stdin = strings.NewReader(script)
	if err := sess.Run("sh -s"); err != nil {
		return err
	}
	return nil
}

func (r *SSHRouter) runCommand(conn *ssh.Client, cmd string) (string, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	var out bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &out

	if err := sess.Run(cmd); err != nil {
		return "", fmt.Errorf("cmd error: %w, output: %s", err, out.String())
	}
	return out.String(), nil
}
