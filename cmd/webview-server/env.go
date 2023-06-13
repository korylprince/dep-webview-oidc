package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func EnvString(key, def string) string {
	if env, ok := os.LookupEnv(key); ok {
		return env
	}
	return def
}

func EnvBool(key string, def bool) bool {
	switch env := os.Getenv(key); strings.ToLower(env) {
	case "true", "yes", "1":
		return true
	case "false", "no", "0":
		return false
	}
	return def
}

func EnvInt(key string, def int) int {
	env := os.Getenv(key)
	if i, err := strconv.Atoi(env); err == nil {
		return i
	}
	return def
}

func EnvDuration(key string, def time.Duration) time.Duration {
	env := os.Getenv(key)
	if d, err := time.ParseDuration(env); err == nil {
		return d
	}
	return def
}

func toList(str string) []string {
	var list []string
	for _, s := range strings.Split(str, ",") {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			list = append(list, trimmed)
		}
	}
	return list
}
