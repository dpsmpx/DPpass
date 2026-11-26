// D-120: проверка TUN под ROOT в отдельном сетевом namespace Android.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func links() string {
	b, err := exec.Command("ip", "-o", "link", "show").Output()
	check(err)
	return string(b)
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "receive" {
		receive(3)
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(links()), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || strings.Contains(","+strings.Trim(fields[2], "<>")+",", ",UP,") {
			panic("expected isolated namespace")
		}
		switch fields[1] {
		case "lo:", "ip_vti0@NONE:", "ip6_vti0@NONE:", "sit0@NONE:", "ip6tnl0@NONE:":
		default:
			panic("unexpected interface")
		}
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	check(err)
	var req [40]byte
	copy(req[:], "dpgateway")
	binary.LittleEndian.PutUint16(req[16:], 0x1001)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		panic(errno)
	}
	if !strings.Contains(links(), " dpgateway:") {
		panic("missing TUN")
	}
	if len(os.Args) == 3 && os.Args[1] == "send" {
		sendToLocalReceiver(fd, os.Args[2])
		check(syscall.Close(fd))
		return
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	check(err)
	check(syscall.Sendmsg(pair[0], []byte{'T'}, syscall.UnixRights(fd), nil, 0))
	check(syscall.Close(fd))
	check(syscall.Close(pair[0]))
	socket := os.NewFile(uintptr(pair[1]), "receiver")
	exe, err := os.Executable()
	check(err)
	child := exec.Command(exe, "receive")
	// Проверяем смену UID, но не переход в SELinux-домен приложения.
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 2000, Gid: 2000}}
	child.ExtraFiles = []*os.File{socket}
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	check(child.Run())
	check(socket.Close())
	if strings.Contains(links(), " dpgateway:") {
		panic("TUN not removed")
	}
	fmt.Println("Android cross-process TUN descriptor lifetime passed")
}

// Filesystem socket: abstract sockets would be scoped to the network namespace.
func sendToLocalReceiver(fd int, path string) {
	if !strings.HasPrefix(path, "/data/user/0/com.dpsmpx.dppass/") {
		panic("expected private test socket")
	}
	conn, err := net.DialTimeout("unix", path, 3*time.Second)
	check(err)
	defer conn.Close()
	check(conn.SetWriteDeadline(time.Now().Add(3 * time.Second)))
	n, oob, err := conn.(*net.UnixConn).WriteMsgUnix([]byte{'T'}, syscall.UnixRights(fd), nil)
	check(err)
	if n != 1 || oob != syscall.CmsgSpace(4) {
		panic("incomplete descriptor transfer")
	}
}

func receive(fd int) {
	var payload [1]byte
	ancillary := make([]byte, syscall.CmsgSpace(4))
	n, an, flags, _, err := syscall.Recvmsg(fd, payload[:], ancillary, syscall.MSG_CMSG_CLOEXEC)
	check(err)
	msgs, err := syscall.ParseSocketControlMessage(ancillary[:an])
	check(err)
	if n != 1 || payload[0] != 'T' || flags&syscall.MSG_CTRUNC != 0 || len(msgs) != 1 {
		panic("invalid descriptor message")
	}
	rights, err := syscall.ParseUnixRights(&msgs[0])
	check(err)
	if len(rights) != 1 || !strings.Contains(links(), " dpgateway:") {
		panic("received TUN missing")
	}
	// TUNGETIFF проверяет привязку принятого fd, а не только номер устройства.
	var req [40]byte
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(rights[0]), 0x800454d2, uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		panic(errno)
	}
	if strings.TrimRight(string(req[:16]), "\x00") != "dpgateway" || binary.LittleEndian.Uint16(req[16:])&0x1001 != 0x1001 {
		panic("unexpected TUN binding")
	}
	info, infoErr := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", rights[0]))
	if infoErr == nil && strings.Contains(string(info), "iff:\tdpgateway\n") {
		fmt.Println("TUN interface also visible in fdinfo")
	} else {
		fmt.Println("TUN interface not reported by fdinfo; ioctl required")
	}
	check(syscall.Close(rights[0]))
	if strings.Contains(links(), " dpgateway:") {
		panic("TUN not removed")
	}
	fmt.Fprintln(os.Stdout, "Android TUN descriptor lifetime passed")
}
