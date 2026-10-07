package adopt

import (
	"encoding/json"
	"strings"
)

type dockerC struct {
	ID, Name, Image, Restart string
	Pid                      int
	Env                      map[string]string
	Mounts                   map[string]string // назначение → источник на хосте
	Ports                    map[string]int    // "443/tcp" → порт хоста
	Labels                   map[string]string
}

// dockerPS — запущенные контейнеры с нужными подробностями (docker inspect).
func dockerPS() []dockerC {
	ids, err := run("docker", "ps", "-q", "--no-trunc")
	if err != nil || strings.TrimSpace(ids) == "" {
		return nil
	}
	out, err := run("docker", append([]string{"inspect"}, strings.Fields(ids)...)...)
	if err != nil {
		return nil
	}
	return parseDockerInspect(out)
}

func parseDockerInspect(out string) []dockerC {
	var raw []struct {
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		State struct {
			Pid int `json:"Pid"`
		} `json:"State"`
		Config struct {
			Image  string            `json:"Image"`
			Env    []string          `json:"Env"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		HostConfig struct {
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
			PortBindings map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"PortBindings"`
		} `json:"HostConfig"`
		Mounts []struct {
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
		} `json:"Mounts"`
	}
	if json.Unmarshal([]byte(out), &raw) != nil {
		return nil
	}
	var res []dockerC
	for _, r := range raw {
		c := dockerC{ID: r.ID, Name: strings.TrimPrefix(r.Name, "/"), Image: r.Config.Image, Pid: r.State.Pid,
			Restart: r.HostConfig.RestartPolicy.Name, Env: map[string]string{}, Mounts: map[string]string{}, Ports: map[string]int{}, Labels: r.Config.Labels}
		for _, kv := range r.Config.Env {
			if k, v, ok := strings.Cut(kv, "="); ok {
				c.Env[k] = v
			}
		}
		for _, m := range r.Mounts {
			c.Mounts[m.Destination] = m.Source
		}
		for k, b := range r.HostConfig.PortBindings {
			if len(b) > 0 {
				c.Ports[k] = anyInt(b[0].HostPort)
			}
		}
		res = append(res, c)
	}
	return res
}
