//go:build linux

package zapret2

import (
    "strings"
    "testing"
)

func TestPlannerSocketPathUsesAbsoluteByteBound(t *testing.T) {
    prev:=PlannerSocket()
    t.Cleanup(func(){_ = SetPlannerSocket(prev)})
    for _,path:=range []string{"/","/"+strings.Repeat("a",98),"/"+strings.Repeat("é",49)} {
        if !ValidPlannerSocketPath(path) || SetPlannerSocket(path)!=nil || PlannerSocket()!=path {
            t.Fatal("valid path rejected")
        }
    }
    for _,path:=range []string{"relative","/a\x00b","/"+strings.Repeat("a",99),"/"+strings.Repeat("é",50)} {
        before:=PlannerSocket()
        if ValidPlannerSocketPath(path) || SetPlannerSocket(path)==nil || PlannerSocket()!=before {
            t.Fatal("invalid path selected")
        }
    }
    if ValidPlannerSocketPath("") || SetPlannerSocket("")!=nil || PlannerSocket()!="" {
        t.Fatal("in-process selection changed")
    }
}
