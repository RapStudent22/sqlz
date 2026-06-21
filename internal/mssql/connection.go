package mssql

import (
	"context"
	"time"

	"github.com/RapStudent22/sqlz/internal/models"
)

func (c *Client) TestConnection(
	instance models.SQLInstance,
) models.ConnectionResult {

	result := models.ConnectionResult{
		Instance: instance,
	}

	start := time.Now()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		c.config.ConnectionTimeout,
	)
	defer cancel()

	err := c.db.PingContext(ctx)

	result.ResponseTime = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Reachable = true
	result.Authenticated = true

	return result
}

func (c *Client) TestConnectionWithVersion(
	instance models.SQLInstance,
) models.ConnectionResult {

	result := c.TestConnection(instance)

	if !result.Authenticated {
		return result
	}

	var version string

	err := c.db.QueryRow(
		`SELECT @@VERSION`,
	).Scan(&version)

	if err != nil {
		return result
	}

	result.Version = version

	return result
}

func (c *Client) IsReachable() bool {

	ctx, cancel := context.WithTimeout(
		context.Background(),
		3*time.Second,
	)

	defer cancel()

	err := c.db.PingContext(ctx)

	return err == nil
}
