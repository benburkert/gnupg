package gpgtest

import (
	"bufio"
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// GPG2 wraps the gpg2 command line tool and gpg-agent daemon.
type GPG2 struct {
	HomeDir string

	agent *exec.Cmd
}

// NewGPG2 returns a GPG2 with a temp homedir running a gpg-agent subprocesses.
func NewGPG2() (*GPG2, error) {
	if !checkVersion() {
		return nil, errors.New("GnuPG 2.1 or greater not installed")
	}

	homedir, err := ioutil.TempDir("", "go-gnupg")
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(homedir, 0700); err != nil {
		return nil, err
	}

	agentArgs := []string{
		"--homedir", homedir,
		"--daemon",
		"cat", // run "cat" to sleep forever in the foreground
	}

	gpg2 := &GPG2{
		HomeDir: homedir,
		agent:   exec.Command("gpg-agent", agentArgs...),
	}

	return gpg2, gpg2.agent.Start()
}

// Close kills the gpg-agent subprocess.
func (g *GPG2) Close() error {
	return g.agent.Process.Kill()
}

// Run executes a gpg2 command.
func (g *GPG2) Run(args ...string) (stdout, stderr *bytes.Buffer, err error) {
	stdout, stderr = new(bytes.Buffer), new(bytes.Buffer)
	args = append([]string{"--homedir", g.HomeDir}, args...)

	cmd := exec.Command("gpg2", args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	return stdout, stderr, cmd.Run()
}

// checkVersion returns true if GnuPG 2.1 is present.
func checkVersion() bool {
	gpg2Path, err := exec.LookPath("gpg2")
	if err != nil {
		return false
	}

	cmd := exec.Command(gpg2Path, "--version")
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	err = cmd.Run()
	if err != nil {
		return false
	}

	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false
		}

		// Skip any informational messages, such as
		//   gpg: keyserver option ...
		if strings.HasPrefix(scanner.Text(), "gpg:") {
			continue
		}

		major, minor, _, ok := gnupgVersion(scanner.Text())
		if !ok {
			return false
		}

		// An argument could be made to check for a major >= 2, but
		// the EdDSA interface is in flux right now, and isn't
		// guaranteed for future versions.
		//
		// A similar argument could be made here. If the situation changes,
		// the test *should* fail, and the current logic reëvaluated.
		return major == 2 && minor == 1
	}

	return false
}

var gnupgVersionRE = regexp.MustCompile(`^gpg \(GnuPG\) (\d+)\.(\d+)\.(\d+).*$`)

// gnupgVersion extracts the major, minor, and patch from a GnuPG version string.
func gnupgVersion(v string) (major, minor, patch int, ok bool) {
	matches := gnupgVersionRE.FindAllStringSubmatch(v, -1)
	if len(matches) != 1 {
		return -1, -1, -1, false
	}

	major, err := strconv.Atoi(matches[0][1])
	if err != nil {
		return -1, -1, -1, false
	}

	minor, err = strconv.Atoi(matches[0][2])
	if err != nil {
		return -1, -1, -1, false
	}

	patch, err = strconv.Atoi(matches[0][3])
	if err != nil {
		return -1, -1, -1, false
	}

	return major, minor, patch, true
}
