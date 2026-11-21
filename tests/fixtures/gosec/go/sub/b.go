package other

import "os/exec"

func Run(c string) error {
	return exec.Command("sh", "-c", c).Run()
}
