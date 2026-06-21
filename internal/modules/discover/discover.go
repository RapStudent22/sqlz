package discover

import (
	"fmt"

	"sqlz/internal/discovery"
	"sqlz/internal/models"
)

type Options struct {
	LDAPServer string
	Port       int

	Domain   string
	Username string
	Password string
	BaseDN   string

	Dedup bool
}

func Run(opts Options) ([]models.SQLInstance, error) {

	cfg := discovery.LDAPConfig{
		Server:   opts.LDAPServer,
		Port:     opts.Port,
		Domain:   opts.Domain,
		Username: opts.Username,
		Password: opts.Password,
		BaseDN:   opts.BaseDN,
	}

	instances, err := discovery.DiscoverSQLInstances(cfg)
	if err != nil {
		return nil, err
	}

	if !opts.Dedup {
		return instances, nil
	}

	seen := make(map[string]bool)
	var result []models.SQLInstance

	for _, inst := range instances {

		key := inst.Hostname
		if inst.Port > 0 {
			key = fmt.Sprintf("%s:%d", inst.Hostname, inst.Port)
		}

		if !seen[key] {
			seen[key] = true
			result = append(result, inst)
		}
	}

	return result, nil
}
