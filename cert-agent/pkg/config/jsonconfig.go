package jsonconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
)

func writeEnvConfig(p string, cfg map[string]interface{}, fd *os.File) {
	if p != "" {
		p = p + "_"
	}
	for k, v := range cfg {
		key := strings.ToUpper(p + k)
		switch reflect.TypeOf(v).Kind() {
		case reflect.Map:
			writeEnvConfig(p+k, v.(map[string]interface{}), fd)
		case reflect.Slice:
			value := ""
			for _, v := range v.([]interface{}) {
				if value == "" {
					value += fmt.Sprintf("%v", v)
				} else {
					value += fmt.Sprintf(",%v", v)
				}
			}
			line := fmt.Sprintf("%s=%v\n", key, value)
			fd.WriteString(line)
		default:
			line := fmt.Sprintf("%s=%v\n", key, v)
			fd.WriteString(line)
		}
	}

}

func Json2env(prefix string, b []byte, cfg string) error {
	fd, err := os.Create(cfg)
	defer fd.Close()

	var c map[string]interface{}
	err = json.Unmarshal(b, &c)
	writeEnvConfig(prefix, c, fd)
	return err
}
