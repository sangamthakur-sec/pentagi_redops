// Package skills reads a folder of skills (each a directory with a SKILL.md) and turns a
// skill's numbered Workflow section into ordered steps. It replaces the LLM subtask
// generator: a task that names a skill is planned from the skill's own steps, verbatim.
package skills

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const primaryFileName = "SKILL.md"

// Skill is one skill found under the library root.
type Skill struct {
	Name        string
	Description string
	// RelDir is the skill directory relative to the library root, slash-separated.
	RelDir string
	// Content is the raw SKILL.md.
	Content []byte
}

// RelPrimary is the SKILL.md path relative to the library root.
func (s Skill) RelPrimary() string {
	return s.RelDir + "/" + primaryFileName
}

// Step is one item of a skill's numbered Workflow list.
type Step struct {
	Number int
	Title  string
	// Text is the item exactly as written, continuation lines included.
	Text      string
	StartLine int
	EndLine   int
}

// Library holds the skills of one root folder, keyed by frontmatter name.
type Library struct {
	byName map[string]Skill
}

// ErrNoWorkflow means the skill has no numbered list under a "Workflow" heading.
var ErrNoWorkflow = errors.New("skill has no numbered workflow")

// Load reads every SKILL.md under root. Directories inside another skill (vendored
// copies, sub-skills kept as reference material) are only used when their frontmatter
// name is not already taken by a shallower skill.
func Load(root string) (*Library, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("skills root %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("skills root %q is not a directory", root)
	}

	var paths []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if !d.IsDir() && d.Name() == primaryFileName {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk skills root: %w", err)
	}

	// Shallow first, so a top-level skill wins a name collision with a copy nested inside another skill.
	sort.Slice(paths, func(i, j int) bool {
		di, dj := strings.Count(paths[i], string(filepath.Separator)), strings.Count(paths[j], string(filepath.Separator))
		if di != dj {
			return di < dj
		}
		return paths[i] < paths[j]
	})

	lib := &Library{byName: make(map[string]Skill)}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		name, description := frontmatter(content)
		if name == "" {
			continue
		}
		if _, taken := lib.byName[name]; taken {
			continue
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		lib.byName[name] = Skill{
			Name:        name,
			Description: description,
			RelDir:      filepath.ToSlash(rel),
			Content:     content,
		}
	}

	return lib, nil
}

// Len is the number of skills loaded.
func (l *Library) Len() int {
	return len(l.byName)
}

// Get returns the skill with the given frontmatter name.
func (l *Library) Get(name string) (Skill, bool) {
	s, ok := l.byName[name]
	return s, ok
}

var (
	invocation     = regexp.MustCompile(`^\s*/([A-Za-z0-9][A-Za-z0-9._-]*)(?:\s+|$)`)
	frontmatterEnd = regexp.MustCompile(`(?m)^---\s*$`)
)

// Match recognises a message that starts with /<skill-name>. It returns the skill and
// the rest of the message. An unknown name does not match.
func (l *Library) Match(message string) (Skill, string, bool) {
	m := invocation.FindStringSubmatchIndex(message)
	if m == nil {
		return Skill{}, "", false
	}
	s, ok := l.byName[message[m[2]:m[3]]]
	if !ok {
		return Skill{}, "", false
	}
	return s, strings.TrimSpace(message[m[1]:]), true
}

func frontmatter(content []byte) (name, description string) {
	if !bytes.HasPrefix(content, []byte("---\n")) && !bytes.HasPrefix(content, []byte("---\r\n")) {
		return "", ""
	}
	rest := content[bytes.IndexByte(content, '\n')+1:]
	end := frontmatterEnd.FindIndex(rest)
	if end == nil {
		return "", ""
	}
	var meta struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal(rest[:end[0]], &meta); err != nil {
		return "", ""
	}
	return strings.TrimSpace(meta.Name), strings.TrimSpace(meta.Description)
}

var (
	headingLine  = regexp.MustCompile(`^(#{1,6})\s+(.*?)\s*#*\s*$`)
	numberedItem = regexp.MustCompile(`^(\d+)[.)]\s+(.*)$`)
	boldLead     = regexp.MustCompile(`^\*\*(.+?)\*\*`)
	fence        = regexp.MustCompile("^\\s*(```|~~~)")
)

// Workflow returns the top-level numbered items of the first section whose heading
// contains "workflow". An item runs until the next top-level item, a heading, or an
// unindented line after a blank line.
func Workflow(content []byte) ([]Step, error) {
	var (
		lines     []string
		sc        = bufio.NewScanner(bytes.NewReader(content))
		inSection bool
		level     int
		inFence   bool
		steps     []Step
		cur       *Step
		sawBlank  bool
	)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	closeStep := func() {
		if cur == nil {
			return
		}
		body := lines[cur.StartLine-1 : cur.EndLine]
		cur.Text = strings.TrimRight(strings.Join(body, "\n"), " \n")
		steps = append(steps, *cur)
		cur = nil
	}

	for i, line := range lines {
		lineNo := i + 1
		if fence.MatchString(line) {
			inFence = !inFence
		}
		if !inFence {
			if h := headingLine.FindStringSubmatch(line); h != nil {
				if inSection && len(h[1]) <= level {
					break
				}
				if !inSection && strings.Contains(strings.ToLower(h[2]), "workflow") {
					inSection, level = true, len(h[1])
				}
				continue
			}
		}
		if !inSection {
			continue
		}
		if !inFence {
			if m := numberedItem.FindStringSubmatch(line); m != nil {
				closeStep()
				var n int
				fmt.Sscanf(m[1], "%d", &n)
				cur = &Step{Number: n, Title: stepTitle(m[2]), StartLine: lineNo, EndLine: lineNo}
				sawBlank = false
				continue
			}
		}
		if cur == nil {
			continue
		}
		if strings.TrimSpace(line) == "" {
			sawBlank = true
			continue
		}
		if sawBlank && !inFence && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			closeStep()
			continue
		}
		cur.EndLine = lineNo
		sawBlank = false
	}
	closeStep()

	if len(steps) == 0 {
		return nil, ErrNoWorkflow
	}
	return steps, nil
}

func stepTitle(first string) string {
	if m := boldLead.FindStringSubmatch(first); m != nil {
		return strings.TrimRight(strings.TrimSpace(m[1]), ".:")
	}
	title := first
	for _, sep := range []string{" — ", " - ", ". "} {
		if i := strings.Index(title, sep); i > 0 {
			title = title[:i]
			break
		}
	}
	const maxTitle = 120
	if len(title) > maxTitle {
		title = title[:maxTitle]
	}
	return strings.TrimSpace(title)
}
