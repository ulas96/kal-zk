// Command zktestmutate applies the release mutation matrix to isolated source checkouts and
// requires the named security test—not merely package compilation—to fail for every mutant.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const mutationCount = 55

var testName = regexp.MustCompile(`^Test[A-Za-z0-9_]+$`)

type patch struct {
	File   string `json:"file"`
	Before string `json:"before"`
	After  string `json:"after"`
}

type mutation struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Repo        string  `json:"repo"`
	Test        string  `json:"test"`
	Tags        string  `json:"tags,omitempty"`
	Patches     []patch `json:"patches"`
}

type manifest struct {
	Version   int        `json:"version"`
	Mutations []mutation `json:"mutations"`
}

type result struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Test        string `json:"test"`
	Status      string `json:"status"`
	DurationMS  int64  `json:"duration_ms"`
	Error       string `json:"error,omitempty"`
}

type testEvent struct {
	Action string `json:"Action"`
	Test   string `json:"Test"`
}

func main() {
	var manifestPath, kalRepo, onlyID string
	var validateOnly bool
	var timeout time.Duration
	flag.StringVar(&manifestPath, "manifest", "tests/zk_mutations.json", "mutation manifest")
	flag.StringVar(&kalRepo, "kal-repo", "", "path to the kal source repository (default: sibling kal)")
	flag.StringVar(&onlyID, "id", "", "execute one mutation id or a comma-separated subset (the complete manifest is still validated)")
	flag.BoolVar(&validateOnly, "validate-only", false, "validate the manifest and current source anchors without executing mutants")
	flag.DurationVar(&timeout, "timeout", 15*time.Minute, "timeout for each named test")
	flag.Parse()

	root, err := repositoryRoot()
	if err != nil {
		fatal(err)
	}
	m, err := readManifest(root, manifestPath)
	if err != nil {
		fatal(err)
	}
	if kalRepo == "" {
		kalRepo = filepath.Join(filepath.Dir(root), "kal")
	} else if !filepath.IsAbs(kalRepo) {
		kalRepo = filepath.Join(root, kalRepo)
	}
	repos := map[string]string{"kal-zk": root, "kal": filepath.Clean(kalRepo)}
	if err := validateManifest(m, repos); err != nil {
		fatal(err)
	}
	if validateOnly {
		fmt.Printf("validated %d exact mutation anchors\n", len(m.Mutations))
		return
	}
	results := make([]result, 0, len(m.Mutations))
	survivors := 0
	selected := map[string]bool{}
	for _, id := range strings.Split(onlyID, ",") {
		if id = strings.TrimSpace(id); id != "" {
			selected[id] = true
		}
	}
	for _, mutant := range m.Mutations {
		if len(selected) != 0 && !selected[mutant.ID] {
			continue
		}
		started := time.Now()
		r := result{ID: mutant.ID, Description: mutant.Description, Test: mutant.Test}
		err := runMutation(repos, mutant, timeout)
		r.DurationMS = time.Since(started).Milliseconds()
		if err != nil {
			r.Status, r.Error = "survived", err.Error()
			survivors++
		} else {
			r.Status = "killed"
		}
		results = append(results, r)
		encoded, _ := json.Marshal(r)
		fmt.Println(string(encoded))
	}
	if len(selected) != 0 && len(results) != len(selected) {
		fatal(fmt.Errorf("one or more mutation ids in %q were not found", onlyID))
	}
	summary := struct {
		Mutations int `json:"mutations"`
		Killed    int `json:"killed"`
		Survived  int `json:"survived"`
	}{len(results), len(results) - survivors, survivors}
	encoded, _ := json.Marshal(summary)
	fmt.Println(string(encoded))
	if survivors != 0 {
		os.Exit(1)
	}
}

func repositoryRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found")
		}
		dir = parent
	}
}

func readManifest(repository, name string) (manifest, error) {
	root, err := os.OpenRoot(repository)
	if err != nil {
		return manifest{}, err
	}
	defer root.Close()
	f, err := root.Open(name)
	if err != nil {
		return manifest{}, err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var out manifest
	if err := decoder.Decode(&out); err != nil {
		return manifest{}, fmt.Errorf("decode %s: %w", name, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return manifest{}, fmt.Errorf("decode %s: trailing JSON", name)
	}
	return out, nil
}

func validateManifest(m manifest, repos map[string]string) error {
	if m.Version != 1 {
		return fmt.Errorf("manifest version %d, want 1", m.Version)
	}
	if len(m.Mutations) != mutationCount {
		return fmt.Errorf("manifest has %d mutations, want %d", len(m.Mutations), mutationCount)
	}
	repoRoots := make(map[string]*os.Root, len(repos))
	for name, path := range repos {
		root, err := os.OpenRoot(path)
		if err != nil {
			return fmt.Errorf("open %s repository: %w", name, err)
		}
		repoRoots[name] = root
		defer root.Close()
	}
	for i, mutant := range m.Mutations {
		wantID := fmt.Sprintf("M%d", i+1)
		if mutant.ID != wantID {
			return fmt.Errorf("mutation %d id %q, want %q", i, mutant.ID, wantID)
		}
		repoRoot, ok := repoRoots[mutant.Repo]
		if !ok {
			return fmt.Errorf("%s: unknown repository %q", mutant.ID, mutant.Repo)
		}
		if mutant.Description == "" || !testName.MatchString(mutant.Test) || len(mutant.Patches) == 0 {
			return fmt.Errorf("%s: description, exact top-level test and patches are required", mutant.ID)
		}
		for j, p := range mutant.Patches {
			if !filepath.IsLocal(p.File) || p.Before == "" || p.Before == p.After {
				return fmt.Errorf("%s patch %d: invalid exact replacement", mutant.ID, j)
			}
			raw, err := repoRoot.ReadFile(p.File)
			if err != nil {
				return fmt.Errorf("%s patch %d: %w", mutant.ID, j, err)
			}
			if count := bytes.Count(raw, []byte(p.Before)); count != 1 {
				return fmt.Errorf("%s patch %d: before text occurs %d times in %s, want exactly once",
					mutant.ID, j, count, p.File)
			}
		}
	}
	return nil
}

func runMutation(repos map[string]string, mutant mutation, timeout time.Duration) error {
	temp, err := os.MkdirTemp("", "kal-zk-mutant-"+strings.ToLower(mutant.ID)+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	temp, err = filepath.EvalSymlinks(temp)
	if err != nil {
		return err
	}
	clones := make(map[string]string, len(repos))
	for _, name := range []string{"kal-zk", "kal"} {
		clones[name] = filepath.Join(temp, name)
		if err := copyTree(repos[name], clones[name]); err != nil {
			return fmt.Errorf("snapshot %s: %w", name, err)
		}
	}
	cloneRoots := make(map[string]*os.Root, len(clones))
	for name, path := range clones {
		root, err := os.OpenRoot(path)
		if err != nil {
			return err
		}
		cloneRoots[name] = root
		defer root.Close()
	}
	workspace := filepath.Join(temp, "go.work")
	goVersion := strings.TrimPrefix(runtime.Version(), "go")
	work := fmt.Sprintf("go %s\n\nuse %s\n\nreplace github.com/ulas96/kal => %s\n",
		goVersion, clones["kal-zk"], clones["kal"])
	if err := os.WriteFile(workspace, []byte(work), 0o600); err != nil {
		return err
	}
	passed, failed, output, err := runNamedTest(clones["kal-zk"], workspace, mutant, timeout)
	if err != nil {
		return fmt.Errorf("unmutated baseline command failed: %w: %s", err, tail(output))
	}
	if !passed || failed {
		return fmt.Errorf("unmutated baseline did not pass by name: %s", tail(output))
	}
	for _, p := range mutant.Patches {
		cloneRoot := cloneRoots[mutant.Repo]
		raw, err := cloneRoot.ReadFile(p.File)
		if err != nil {
			return err
		}
		if count := bytes.Count(raw, []byte(p.Before)); count != 1 {
			return fmt.Errorf("before text occurs %d times after snapshot in %s", count, p.File)
		}
		mutated := bytes.Replace(raw, []byte(p.Before), []byte(p.After), 1)
		if err := cloneRoot.WriteFile(p.File, mutated, 0o600); err != nil {
			return err
		}
	}
	_, failed, output, err = runNamedTest(clones["kal-zk"], workspace, mutant, timeout)
	if err == nil {
		return fmt.Errorf("named test passed")
	}
	if !failed {
		return fmt.Errorf("test command failed without a named-test failure (compile/setup failures do not kill mutants): %s", tail(output))
	}
	return nil
}

func runNamedTest(root, workspace string, mutant mutation, timeout time.Duration) (passed, failed bool, output []byte, runErr error) {
	args := []string{"test"}
	if mutant.Tags != "" {
		args = append(args, "-tags", mutant.Tags)
	}
	args = append(args, "-json", "-count=1", "-run", "^"+mutant.Test+"$", "./tests")
	env := append(os.Environ(), "GOWORK="+workspace)
	output, runErr = goCommand(root, timeout, env, args...)
	// Parse line by line and skip anything that is not a JSON object. `go test -json` interleaves
	// plain text into the same stream — "go: downloading <module>" on a cold module cache is the
	// one that matters. A streaming decoder stops at the first such byte, parses zero events, and
	// reports the unmutated baseline as not having passed, which the runner scores as a survivor:
	// a green suite fails the whole matrix on the first mutant and only ever on a cold cache, so it
	// reproduces in CI and never on a developer machine.
	for _, line := range bytes.Split(output, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var event testEvent
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		if event.Action == "pass" && event.Test == mutant.Test {
			passed = true
		}
		if event.Action == "fail" && event.Test == mutant.Test {
			failed = true
		}
	}
	return passed, failed, output, runErr
}

// copyTree creates a fresh source snapshot instead of cloning HEAD. That lets contributors kill
// mutants before committing while release-check independently requires a clean committed tree.
// Repository metadata and local build outputs are intentionally absent from the mutant.
func copyTree(source, destination string) error {
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return err
	}
	sourceRoot, err := os.OpenRoot(source)
	if err != nil {
		return err
	}
	defer sourceRoot.Close()
	destinationRoot, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer destinationRoot.Close()
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".cache", "vendor":
				return filepath.SkipDir
			}
			return destinationRoot.MkdirAll(relative, 0o700)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink is not allowed in mutation input: %s", relative)
		}
		if entry.Name() == "coverage.out" || entry.Name() == ".env" {
			return nil
		}
		info, err := sourceRoot.Stat(relative)
		if err != nil {
			return err
		}
		input, err := sourceRoot.Open(relative)
		if err != nil {
			return err
		}
		output, err := destinationRoot.OpenFile(relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			_ = input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		inputCloseErr := input.Close()
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if inputCloseErr != nil {
			return inputCloseErr
		}
		return closeErr
	})
}

func goCommand(dir string, timeout time.Duration, env []string, args ...string) ([]byte, error) {
	// The executable is fixed, and exec.Command passes each generated test flag directly without
	// shell interpretation. Manifest test names are additionally constrained by testName.
	cmd := exec.Command("go", args...) // #nosec G204 -- no variable executable or shell exists here.
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	errCh := make(chan error, 1)
	go func() { errCh <- cmd.Run() }()
	select {
	case err := <-errCh:
		return output.Bytes(), err
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-errCh
		return output.Bytes(), fmt.Errorf("timed out after %s", timeout)
	}
}

func tail(raw []byte) string {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) > 12 {
		lines = lines[len(lines)-12:]
	}
	return strings.Join(lines, "\n")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "zktestmutate:", err)
	os.Exit(2)
}
