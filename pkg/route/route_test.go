package route

import (
	"runtime"
	"testing"
)

func TestBuildArgsUnixDefaults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix flag mapping")
	}
	got := BuildArgs(Options{MaxHops: 30, Probes: 3, WaitSec: 2}, "google.com")
	want := []string{"-m", "30", "-q", "3", "-w", "2", "google.com"}
	if !sliceEq(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestBuildArgsUnixNoResolve(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix flag mapping")
	}
	got := BuildArgs(Options{MaxHops: 10, NoResolve: true}, "1.1.1.1")
	// -n must be present; max-hops also present; probes/wait omitted (zero values).
	if got[0] != "-n" {
		t.Errorf("got[0] = %q, want -n", got[0])
	}
	if got[len(got)-1] != "1.1.1.1" {
		t.Errorf("last arg = %q, want 1.1.1.1", got[len(got)-1])
	}
}

func TestBuildArgsWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows flag mapping")
	}
	got := BuildArgs(Options{MaxHops: 30, WaitSec: 2, NoResolve: true}, "google.com")
	want := []string{"-d", "-h", "30", "-w", "2000", "google.com"} // wait in ms on windows
	if !sliceEq(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestInstallHintNonEmpty(t *testing.T) {
	if InstallHint() == "" {
		t.Error("InstallHint returned empty")
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
