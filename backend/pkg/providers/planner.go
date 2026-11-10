package providers

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"pentagi/pkg/database"
	"pentagi/pkg/docker"
	obs "pentagi/pkg/observability"
	"pentagi/pkg/skills"
	"pentagi/pkg/tools"

	"github.com/sirupsen/logrus"
)

// skillStepMarker opens the first line of every subtask planned from a skill step. The
// refiner may reword such a subtask but never remove or reorder it, and the marker line is
// how code recognises one (see protectSkillSteps).
const skillStepMarker = "[skill-step]"

var skillStepLine = regexp.MustCompile(`^\[skill-step\] (\S+)#(\d+)(?:-(\d+))?/(\d+) `)

// GenerateSubtasks plans a task without a model. A message that starts with /<skill-name>
// becomes one subtask per step of that skill's Workflow; any other message becomes a single
// subtask, which the controller builds from an empty plan.
func (fp *flowProvider) GenerateSubtasks(ctx context.Context, taskID int64) ([]tools.SubtaskInfo, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "providers.flowProvider.GenerateSubtasks")
	defer span.End()

	logger := logrus.WithContext(ctx).WithField("task_id", taskID)

	task, err := fp.db.GetTask(ctx, taskID)
	if err != nil {
		return nil, fmt.Errorf("failed to get task %d: %w", taskID, err)
	}

	invokesSkill := strings.HasPrefix(strings.TrimSpace(task.Input), "/")
	if fp.cfg == nil || fp.cfg.SkillsDir == "" {
		if invokesSkill {
			logger.Warn("message looks like a skill invocation but SKILLS_DIR is not set; running it as one subtask")
		}
		return []tools.SubtaskInfo{}, nil
	}

	lib, err := skills.Load(fp.cfg.SkillsDir)
	if err != nil {
		if invokesSkill {
			return nil, fmt.Errorf("failed to load skills for task %d: %w", taskID, err)
		}
		logger.WithError(err).Warn("failed to load skills; running the message as one subtask")
		return []tools.SubtaskInfo{}, nil
	}

	plan, matched := planTask(task, lib)
	if !matched && invokesSkill {
		logger.WithField("input", task.Input[:min(len(task.Input), 200)]).Warn("no skill matches the invocation; running it as one subtask")
	}

	return plan, nil
}

// planTask is the whole planning decision, kept free of I/O so it can be tested directly.
func planTask(task database.Task, lib *skills.Library) ([]tools.SubtaskInfo, bool) {
	skill, request, ok := lib.Match(task.Input)
	if !ok {
		return []tools.SubtaskInfo{}, false
	}

	steps, err := skills.Workflow(skill.Content)
	if errors.Is(err, skills.ErrNoWorkflow) || err != nil {
		return []tools.SubtaskInfo{{
			Title:       "Apply skill " + skill.Name,
			Description: wholeSkillDescription(task.ID, skill, request),
		}}, true
	}

	groups := groupSteps(steps, TasksNumberLimit)
	plan := make([]tools.SubtaskInfo, 0, len(groups))
	for _, g := range groups {
		plan = append(plan, tools.SubtaskInfo{
			Title:       stepGroupTitle(g),
			Description: stepGroupDescription(task.ID, skill, request, g, len(steps)),
		})
	}

	return plan, true
}

// groupSteps keeps one step per subtask unless the skill has more steps than a task may
// have subtasks; then neighbouring steps are combined, never reordered.
func groupSteps(steps []skills.Step, limit int) [][]skills.Step {
	if limit <= 0 || len(steps) <= limit {
		groups := make([][]skills.Step, len(steps))
		for i := range steps {
			groups[i] = steps[i : i+1]
		}
		return groups
	}

	groups := make([][]skills.Step, 0, limit)
	for i := 0; i < limit; i++ {
		lo, hi := i*len(steps)/limit, (i+1)*len(steps)/limit
		groups = append(groups, steps[lo:hi])
	}
	return groups
}

func stepGroupTitle(g []skills.Step) string {
	if len(g) == 1 {
		return fmt.Sprintf("Step %d — %s", g[0].Number, g[0].Title)
	}
	return fmt.Sprintf("Steps %d–%d — %s … %s", g[0].Number, g[len(g)-1].Number, g[0].Title, g[len(g)-1].Title)
}

func containerSkillPath(skill skills.Skill) string {
	return path.Join(docker.WorkFolderPathInContainer, tools.SkillsDirName, skill.RelPrimary())
}

func engagementHeader(taskID int64, request string) string {
	if request == "" {
		request = "(none given — ask for the target and scope before touching any system)"
	}
	return fmt.Sprintf(`ENGAGEMENT HEADER — you are the coordinator; skip any "Standalone orchestration" section of the skill.
TARGET and SCOPE: exactly as stated in the user request below. Never act outside them.
OUTPUT_DIR: %s/engagements/task-%d
USER REQUEST: %s`, docker.WorkFolderPathInContainer, taskID, request)
}

func stepGroupDescription(taskID int64, skill skills.Skill, request string, g []skills.Step, total int) string {
	first, last := g[0], g[len(g)-1]

	var b strings.Builder
	b.WriteString(skillStepMarker + " " + skill.Name + "#" + strconv.Itoa(first.Number))
	if len(g) > 1 {
		b.WriteString("-" + strconv.Itoa(last.Number))
	}
	fmt.Fprintf(&b, "/%d %s:%d-%d\n\n", total, skill.RelPrimary(), first.StartLine, last.EndLine)
	b.WriteString(engagementHeader(taskID, request))
	b.WriteString("\n\n")
	for _, st := range g {
		fmt.Fprintf(&b, "SKILL STEP %d of %d (verbatim, %s lines %d-%d):\n%s\n\n", st.Number, total, skill.RelPrimary(), st.StartLine, st.EndLine, st.Text)
	}
	fmt.Fprintf(&b, "The full skill is at %s. Read it and every file this step names before acting. "+
		"Its Rules and Anti-Patterns apply to this step. Never execute files under scripts/.", containerSkillPath(skill))

	return b.String()
}

func wholeSkillDescription(taskID int64, skill skills.Skill, request string) string {
	return engagementHeader(taskID, request) + "\n\n" + fmt.Sprintf(
		"SKILL: %s — %s\nThis skill has no numbered Workflow, so it runs as one subtask. Read %s first and follow its "+
			"method, routing tables and tier rules as written. Its Rules and Anti-Patterns apply throughout. "+
			"Never execute files under scripts/.", skill.Name, skill.Description, containerSkillPath(skill))
}

// skillStepRef reports whether a subtask description was planned from a skill step.
func skillStepRef(description string) (string, bool) {
	first, _, _ := strings.Cut(description, "\n")
	if !skillStepLine.MatchString(first) {
		return "", false
	}
	return first, true
}

// protectSkillSteps drops refiner operations that would remove or reorder a subtask planned
// from a skill step, and keeps the marker line on any rewording of one. The refiner may still
// add subtasks anywhere and reword titles and descriptions. Dropped operations are returned
// for logging.
func protectSkillSteps(planned []database.Subtask, patch tools.SubtaskPatch) (tools.SubtaskPatch, []tools.SubtaskOperation) {
	markers := make(map[int64]string)
	for _, st := range planned {
		if ref, ok := skillStepRef(st.Description); ok {
			markers[st.ID] = ref
		}
	}
	if len(markers) == 0 {
		return patch, nil
	}

	kept := make(tools.SubtaskOperations, 0, len(patch.Operations))
	var dropped []tools.SubtaskOperation
	for _, op := range patch.Operations {
		var marker string
		protected := false
		if op.ID != nil {
			marker, protected = markers[*op.ID]
		}
		switch {
		case protected && (op.Op == tools.SubtaskOpRemove || op.Op == tools.SubtaskOpReorder):
			dropped = append(dropped, op)
			continue
		case protected && op.Op == tools.SubtaskOpModify && op.Description != "":
			if ref, ok := skillStepRef(op.Description); !ok || ref != marker {
				op.Description = marker + "\n\n" + op.Description
			}
		}
		kept = append(kept, op)
	}
	patch.Operations = kept

	return patch, dropped
}

// skillStepsIntact reports whether every planned skill-step subtask is still present in the
// refined list, in its original relative order.
func skillStepsIntact(planned []database.Subtask, refined []tools.SubtaskInfoPatch) bool {
	var want []int64
	for _, st := range planned {
		if _, ok := skillStepRef(st.Description); ok {
			want = append(want, st.ID)
		}
	}
	if len(want) == 0 {
		return true
	}
	var got []int64
	for _, st := range refined {
		if st.ID == 0 {
			continue
		}
		if _, ok := skillStepRef(st.Description); ok {
			got = append(got, st.ID)
		}
	}
	return slices.Equal(want, got)
}
