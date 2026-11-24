//go:build linux || windows

package bridge

import (
    "net"
    "testing"
    "github.com/miekg/dns"
)

func TestLocalControlRequiresMatchingPublicA(t *testing.T) {
    q:=new(dns.Msg)
    q.SetQuestion(localControlHost,dns.TypeA)
    r:=new(dns.Msg)
    r.SetReply(q)
    a:=&dns.A{Hdr:dns.RR_Header{Name:localControlHost,Rrtype:dns.TypeA,Class:dns.ClassINET},A:net.ParseIP("8.8.8.8")}
    r.Answer=[]dns.RR{a}
    if got:=localControlA(r,q.Id);got==nil {t.Fatal("public matching A rejected")}
    if localControlA(r,q.Id+1)!=nil {t.Fatal("wrong id accepted")}
    a.A=net.ParseIP("192.168.1.2")
    if localControlA(r,q.Id)!=nil {t.Fatal("private A accepted")}
    a.A=net.ParseIP("8.8.8.8")
    a.Hdr.Name="example.org."
    if localControlA(r,q.Id)!=nil {t.Fatal("unrelated A accepted")}
}
