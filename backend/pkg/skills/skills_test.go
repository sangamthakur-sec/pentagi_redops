package skills

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureRoot = "testdata/lib"

func loadFixture(t *testing.T) *Library {
	t.Helper()
	lib, err := Load(fixtureRoot)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return lib
}

func TestSkills_Load_ShallowSkillWinsNameCollision(t *testing.T) {
	lib := loadFixture(t)

	if lib.Len() != 2 {
		t.Fatalf("Len = %d, want 2", lib.Len())
	}
	s, ok := lib.Get("web-sqli")
	if !ok {
		t.Fatal("web-sqli not loaded")
	}
	if s.RelDir != "web-sqli" {
		t.Errorf("RelDir = %q, want the top-level folder, not the vendored copy", s.RelDir)
	}
	if s.RelPrimary() != "web-sqli/SKILL.md" {
		t.Errorf("RelPrimary = %q", s.RelPrimary())
	}
	if s.Description != "SQL injection — detected, exploited to impact, proven with a control case." {
		t.Errorf("Description = %q", s.Description)
	}
}

func TestSkills_Load_RejectsMissingRoot(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("Load on a missing root returned no error")
	}
}

func TestSkills_Load_SkipsSkillWithoutFrontmatterName(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "nameless")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# no frontmatter\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lib, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if lib.Len() != 0 {
		t.Fatalf("Len = %d, want 0", lib.Len())
	}
}

func TestSkills_Match_RecognisesInvocation(t *testing.T) {
	lib := loadFixture(t)

	cases := []struct {
		name     string
		message  string
		wantOK   bool
		wantRest string
	}{
		{"skill with request", "/web-sqli https://lab.example scope: lab.example", true, "https://lab.example scope: lab.example"},
		{"leading whitespace", "  /web-sqli target", true, "target"},
		{"skill alone", "/web-sqli", true, ""},
		{"unknown skill", "/nope https://lab.example", false, ""},
		{"no slash", "web-sqli https://lab.example", false, ""},
		{"prefix of a name", "/web-sql https://lab.example", false, ""},
		{"name glued to text", "/web-sqlitarget", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, rest, ok := lib.Match(tc.message)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if s.Name != "web-sqli" || rest != tc.wantRest {
				t.Errorf("got (%q, %q), want (web-sqli, %q)", s.Name, rest, tc.wantRest)
			}
		})
	}
}

func TestSkills_Workflow_ExtractsNumberedSteps(t *testing.T) {
	s, _ := loadFixture(t).Get("web-sqli")

	steps, err := Workflow(s.Content)
	if err != nil {
		t.Fatalf("Workflow: %v", err)
	}

	want := []struct {
		number     int
		title      string
		start, end int
		textHas    string
		textHasNot string
	}{
		{1, "Identify injection points", 18, 19, "   headers, cookies, path segments.", ""},
		{2, "Detect the class", 20, 24, "1. this numbered line is inside a code block", ""},
		{3, "Load the matching reference — mandatory gate before any exploit payload", 25, 26, "destructive-to-others operations (DROP, mass-delete, DoS) stay out of bounds", "Every applicable class"},
		{4, "Report to standard", 30, 30, "4. Report to standard.", "Text under a deeper heading"},
	}
	if len(steps) != len(want) {
		t.Fatalf("got %d steps, want %d: %+v", len(steps), len(want), steps)
	}
	for i, w := range want {
		got := steps[i]
		if got.Number != w.number || got.Title != w.title || got.StartLine != w.start || got.EndLine != w.end {
			t.Errorf("step %d = {%d %q %d-%d}, want {%d %q %d-%d}", i, got.Number, got.Title, got.StartLine, got.EndLine, w.number, w.title, w.start, w.end)
		}
		if !strings.Contains(got.Text, w.textHas) {
			t.Errorf("step %d text lacks %q:\n%s", i, w.textHas, got.Text)
		}
		if w.textHasNot != "" && strings.Contains(got.Text, w.textHasNot) {
			t.Errorf("step %d text contains %q:\n%s", i, w.textHasNot, got.Text)
		}
	}
}

func TestSkills_Workflow_TextIsVerbatim(t *testing.T) {
	s, _ := loadFixture(t).Get("web-sqli")
	steps, err := Workflow(s.Content)
	if err != nil {
		t.Fatalf("Workflow: %v", err)
	}
	lines := strings.Split(string(s.Content), "\n")
	for _, st := range steps {
		want := strings.Join(lines[st.StartLine-1:st.EndLine], "\n")
		if st.Text != want {
			t.Errorf("step %d text differs from source lines %d-%d", st.Number, st.StartLine, st.EndLine)
		}
	}
}

func TestSkills_Workflow_NoWorkflowSection(t *testing.T) {
	s, _ := loadFixture(t).Get("no-flow")
	if _, err := Workflow(s.Content); !errors.Is(err, ErrNoWorkflow) {
		t.Fatalf("err = %v, want ErrNoWorkflow", err)
	}
}
