//go:build local
// +build local

package service

import (
    "context"
    "fmt"
    "path/filepath"
    "strings"
    "testing"
)

type fakeRunner struct{ cmds [][]string; fail bool }

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) error {
    rec := append([]string{name}, args...)
    f.cmds = append(f.cmds, rec)
    if f.fail { return fmt.Errorf("fail") }
    return nil
}

func Test_CheckoutRepo_CloneBranch(t *testing.T) {
    svc := newTestService(t)
    svc.saveToken("default", "acc", "", "TOK")
    fr := &fakeRunner{}
    svc.SetCmdRunner(fr)

    dest := filepath.Join(svc.storageDir, "tmp_checkout")
    out, err := svc.CheckoutRepo(context.Background(), &CheckoutRepoInput{
        GitTarget: GitTarget{Account: Account{Alias: "acc"}, Repo: RepoRef{Owner: "viant", Name: "mcp-toolbox"}},
        Branch:  "main",
        DestDir: dest,
        Depth:   1,
    }, nil)
    if err != nil { t.Fatalf("unexpected error: %v", err) }
    if !out.WasCloned { t.Fatalf("expected WasCloned=true") }
    if out.Path != dest { t.Fatalf("unexpected path: %s", out.Path) }
    if out.CheckedOut != "main" { t.Fatalf("unexpected checked out: %s", out.CheckedOut) }

    if len(fr.cmds) != 1 { t.Fatalf("expected 1 command, got %d", len(fr.cmds)) }
    got := strings.Join(fr.cmds[0], " ")
    if !strings.Contains(got, "git clone") || !strings.Contains(got, "--depth 1") || !strings.Contains(got, "-b main") {
        t.Fatalf("unexpected clone args: %s", got)
    }
    if !strings.Contains(got, "https://x-access-token:TOK@github.com/viant/mcp-toolbox.git") {
        t.Fatalf("unexpected clone URL: %s", got)
    }
    if !strings.HasSuffix(got, " "+dest) {
        t.Fatalf("expected dest at end: %s", got)
    }
}

func Test_CheckoutRepo_Commit(t *testing.T) {
    svc := newTestService(t)
    svc.saveToken("default", "acc", "github.com", "TOK2")
    fr := &fakeRunner{}
    svc.SetCmdRunner(fr)

    // No dest provided; it should choose a path in storageDir with owner_repo pattern
    out, err := svc.CheckoutRepo(context.Background(), &CheckoutRepoInput{
        GitTarget: GitTarget{Account: Account{Alias: "acc"}, Repo: RepoRef{Owner: "viant", Name: "tool"}},
        Commit:  "abc1234",
        Depth:   0,
    }, nil)
    if err != nil { t.Fatalf("unexpected error: %v", err) }
    if !out.WasCloned { t.Fatalf("expected clone to happen") }
    if !strings.Contains(out.Path, filepath.Join(svc.storageDir, "gh_viant_tool")) {
        t.Fatalf("unexpected auto path: %s", out.Path)
    }
    if out.CheckedOut != "abc1234" {
        t.Fatalf("unexpected checked out: %s", out.CheckedOut)
    }

    if len(fr.cmds) != 2 { t.Fatalf("expected 2 commands, got %d", len(fr.cmds)) }
    clone := strings.Join(fr.cmds[0], " ")
    if !strings.Contains(clone, "git clone") || strings.Contains(clone, "--depth") {
        t.Fatalf("unexpected clone flags for depth 0: %s", clone)
    }
    if !strings.Contains(clone, "https://x-access-token:TOK2@github.com/viant/tool.git") {
        t.Fatalf("unexpected clone URL: %s", clone)
    }
    checkout := strings.Join(fr.cmds[1], " ")
    if !strings.Contains(checkout, "git -C "+out.Path+" checkout abc1234") {
        t.Fatalf("unexpected checkout cmd: %s", checkout)
    }
}
