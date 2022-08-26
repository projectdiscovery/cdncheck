package testutils

import (
	"fmt"
	"os/exec"
	"strings"
)

func RunCdncheckBinaryAndGetResults(target string, cdncheckBinary string, debug bool, args []string) ([]string, error) {
	cmd := exec.Command("bash", "-c")
	cmdLine := fmt.Sprintf(`echo %s | %s `, target, cdncheckBinary)
	cmdLine += strings.Join(args, " ")

	cmd.Args = append(cmd.Args, cmdLine)
	data, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	parts := []string{}
	items := strings.Split(string(data), "\n")
	for _, i := range items {
		if i != "" {
			parts = append(parts, i)
		}
	}
	return parts, nil
}
