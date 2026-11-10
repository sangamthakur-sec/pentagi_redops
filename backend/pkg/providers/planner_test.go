package providers

import (
	"strings"
	"testing"

	"pentagi/pkg/database"
	"pentagi/pkg/skills"
	"pentagi/pkg/tools"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadPlannerSkills(t *testing.T) *skills.Library {
	t.Helper()
	lib, err := skills.Load("../skills/testdata/lib")
	require.NoError(t, err)
	return lib
}

func TestPlanner_PlanTask_PlainMessageIsOneSubtask(t *testing.T) {
	plan, matched := planTask(database.Task{ID: 7, Input: "scan 10.0.0.5 for open ports"}, loadPlannerSkills(t))

	assert.False(t, matched)
	require.NotNil(t, plan, "an empty, non-nil plan is how the controller is told to run the message as one subtask")
	assert.Empty(t, plan)
}

func TestPlanner_PlanTask_UnknownSkillIsOneSubtask(t *testing.T) {
	plan, matched := planTask(database.Task{ID: 7, Input: "/no-such-skill https://lab.example"}, loadPlannerSkills(t))

	assert.False(t, matched)
	require.NotNil(t, plan)
	assert.Empty(t, plan)
}

func TestPlanner_PlanTask_OneSubtaskPerWorkflowStep(t *testing.T) {
	plan, matched := planTask(database.Task{ID: 12, Input: "/web-sqli https://lab.example scope: lab.example"}, loadPlannerSkills(t))

	require.True(t, matched)
	require.Len(t, plan, 4)
	assert.Equal(t, []string{
		"Step 1 — Identify injection points",
		"Step 2 — Detect the class",
		"Step 3 — Load the matching reference — mandatory gate before any exploit payload",
		"Step 4 — Report to standard",
	}, []string{plan[0].Title, plan[1].Title, plan[2].Title, plan[3].Title})

	third := plan[2].Description
	ref, ok := skillStepRef(third)
	require.True(t, ok, "the first line must mark the subtask as a skill step")
	assert.Equal(t, "[skill-step] web-sqli#3/4 web-sqli/SKILL.md:25-26", ref)
	assert.Contains(t, third, "USER REQUEST: https://lab.example scope: lab.example")
	assert.Contains(t, third, "OUTPUT_DIR: /work/engagements/task-12")
	assert.Contains(t, third, "destructive-to-others operations (DROP, mass-delete, DoS) stay out of bounds",
		"the step text must be carried verbatim")
	assert.Contains(t, third, "/work/skills/web-sqli/SKILL.md")
	assert.NotContains(t, third, "Every applicable class", "text after the step must not leak into it")
}

func TestPlanner_PlanTask_SkillWithoutWorkflowIsOneSubtask(t *testing.T) {
	plan, matched := planTask(database.Task{ID: 3, Input: "/no-flow https://chat.lab.example"}, loadPlannerSkills(t))

	require.True(t, matched)
	require.Len(t, plan, 1)
	assert.Equal(t, "Apply skill no-flow", plan[0].Title)
	_, isStep := skillStepRef(plan[0].Description)
	assert.False(t, isStep, "a whole-skill subtask is not a protected step")
	assert.Contains(t, plan[0].Description, "/work/skills/no-flow/SKILL.md")
	assert.Contains(t, plan[0].Description, "USER REQUEST: https://chat.lab.example")
}

func TestPlanner_PlanTask_MissingRequestAsksForTarget(t *testing.T) {
	plan, matched := planTask(database.Task{ID: 3, Input: "/web-sqli"}, loadPlannerSkills(t))

	require.True(t, matched)
	assert.Contains(t, plan[0].Description, "ask for the target and scope before touching any system")
}

func TestPlanner_GroupSteps_KeepsOrderWithinLimit(t *testing.T) {
	steps := make([]skills.Step, 20)
	for i := range steps {
		steps[i] = skills.Step{Number: i + 1, Title: "s"}
	}

	groups := groupSteps(steps, 15)

	require.Len(t, groups, 15)
	next := 1
	for _, g := range groups {
		require.NotEmpty(t, g)
		for _, st := range g {
			assert.Equal(t, next, st.Number, "steps must stay in source order with none dropped")
			next++
		}
	}
	assert.Equal(t, 21, next)

	assert.Len(t, groupSteps(steps[:7], 15), 7, "at or under the limit every step is its own subtask")
}

func TestPlanner_StepGroupDescription_RangeMarker(t *testing.T) {
	lib := loadPlannerSkills(t)
	s, _ := lib.Get("web-sqli")
	steps, err := skills.Workflow(s.Content)
	require.NoError(t, err)

	desc := stepGroupDescription(1, s, "x", steps[1:3], len(steps))

	ref, ok := skillStepRef(desc)
	require.True(t, ok)
	assert.True(t, strings.HasPrefix(ref, "[skill-step] web-sqli#2-3/4 "), ref)
}

func plannedWithSkillSteps() []database.Subtask {
	return []database.Subtask{
		{ID: 10, Title: "Step 2", Description: "[skill-step] web-sqli#2/4 web-sqli/SKILL.md:20-24\n\nstep two"},
		{ID: 11, Title: "extra check", Description: "added by the refiner earlier"},
		{ID: 12, Title: "Step 3", Description: "[skill-step] web-sqli#3/4 web-sqli/SKILL.md:25-26\n\nstep three"},
	}
}

func id(v int64) *int64 { return &v }

func TestPlanner_ProtectSkillSteps_DropsRemoveAndReorderOfSkillSteps(t *testing.T) {
	patch := tools.SubtaskPatch{Operations: tools.SubtaskOperations{
		{Op: tools.SubtaskOpRemove, ID: id(10)},
		{Op: tools.SubtaskOpReorder, ID: id(12), AfterID: id(0)},
		{Op: tools.SubtaskOpRemove, ID: id(11)},
		{Op: tools.SubtaskOpAdd, AfterID: id(10), Title: "new", Description: "new step"},
	}}

	out, dropped := protectSkillSteps(plannedWithSkillSteps(), patch)

	require.Len(t, dropped, 2)
	assert.Equal(t, int64(10), *dropped[0].ID)
	assert.Equal(t, int64(12), *dropped[1].ID)
	require.Len(t, out.Operations, 2, "operations on ordinary subtasks and adds pass through")
	assert.Equal(t, tools.SubtaskOpRemove, out.Operations[0].Op)
	assert.Equal(t, int64(11), *out.Operations[0].ID)
	assert.Equal(t, tools.SubtaskOpAdd, out.Operations[1].Op)
}

func TestPlanner_ProtectSkillSteps_ModifyKeepsMarkerLine(t *testing.T) {
	patch := tools.SubtaskPatch{Operations: tools.SubtaskOperations{
		{Op: tools.SubtaskOpModify, ID: id(12), Description: "reworded: route to error-based first"},
		{Op: tools.SubtaskOpModify, ID: id(10), Title: "renamed only"},
	}}

	out, dropped := protectSkillSteps(plannedWithSkillSteps(), patch)

	assert.Empty(t, dropped)
	require.Len(t, out.Operations, 2)
	ref, ok := skillStepRef(out.Operations[0].Description)
	require.True(t, ok)
	assert.Equal(t, "[skill-step] web-sqli#3/4 web-sqli/SKILL.md:25-26", ref)
	assert.Contains(t, out.Operations[0].Description, "reworded: route to error-based first")
	assert.Empty(t, out.Operations[1].Description, "a title-only modify must not gain a description")
}

func TestPlanner_ProtectSkillSteps_PlansWithoutSkillStepsAreUntouched(t *testing.T) {
	planned := []database.Subtask{{ID: 1, Description: "plain"}}
	patch := tools.SubtaskPatch{Operations: tools.SubtaskOperations{{Op: tools.SubtaskOpRemove, ID: id(1)}}}

	out, dropped := protectSkillSteps(planned, patch)

	assert.Empty(t, dropped)
	assert.Equal(t, patch, out)
}

func TestPlanner_SkillStepsIntact(t *testing.T) {
	planned := plannedWithSkillSteps()
	step := func(id int64, d string) tools.SubtaskInfoPatch {
		return tools.SubtaskInfoPatch{ID: id, SubtaskInfo: tools.SubtaskInfo{Description: d}}
	}
	s10, s12 := planned[0].Description, planned[2].Description

	cases := []struct {
		name    string
		refined []tools.SubtaskInfoPatch
		want    bool
	}{
		{"unchanged order with an addition", []tools.SubtaskInfoPatch{step(0, "new"), step(10, s10), step(12, s12)}, true},
		{"step removed", []tools.SubtaskInfoPatch{step(12, s12)}, false},
		{"steps swapped", []tools.SubtaskInfoPatch{step(12, s12), step(10, s10)}, false},
		{"marker stripped", []tools.SubtaskInfoPatch{step(10, "no marker"), step(12, s12)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, skillStepsIntact(planned, tc.refined))
		})
	}
}
