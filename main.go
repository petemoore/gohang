package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

const (
	LOGON32_PROVIDER_DEFAULT  = 0
	LOGON32_LOGON_INTERACTIVE = 2
	PI_NOUI                   = 1
)

var (
	advapi32       = syscall.NewLazyDLL("advapi32.dll")
	procLogonUserW = advapi32.NewProc("LogonUserW")

	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle = kernel32.NewProc("CloseHandle")

	userenv               = syscall.NewLazyDLL("userenv.dll")
	procDeleteProfileW    = userenv.NewProc("DeleteProfileW")
	procLoadUserProfileW  = userenv.NewProc("LoadUserProfileW")
	procUnloadUserProfile = userenv.NewProc("UnloadUserProfile")
	procCreateProfile     = userenv.NewProc("CreateProfile")
)

type ProfileInfo struct {
	Size        uint32
	Flags       uint32
	Username    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     syscall.Handle
}

func main() {
	sigInterrupt := make(chan os.Signal, 1)
	signal.Notify(sigInterrupt, os.Interrupt)

	created := make(chan string)
	created2 := make(chan string)
	password := "_$rg274SGFh54D&$%"
	var wg sync.WaitGroup
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			username := <-created
			log.Printf("Receive: %v", username)
			log.Printf("Deleting user profile %v...", username)
			DeleteProfile(username)
		}
	}(&wg)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			username := <-created2
			log.Printf("Logging into user profile %v...", username)
			LoginAndLogoutUser(username, password)
		}
	}(&wg)

	for i := 4; i < 100; i++ {
		username := fmt.Sprintf("testuser%v", i)
		CreateUser(username, password)
	}

	go func(wg *sync.WaitGroup) {
		defer wg.Done()

		for {
			for i := 4; i < 100; i++ {
				username := fmt.Sprintf("testuser%v", i)
				log.Printf("Creating user %v...", username)
				CreateProfile(username)
				log.Printf("Send: %v", username)
				created <- username
				created2 <- username
			}
		}
	}(&wg)

	go func() {
		for {
			runtime.GC()
		}
	}()

	log.Printf("Waiting")
	wg.Add(3)
	wg.Wait()
	log.Printf("Done")
}

func CreateProfile(username string) {
	u, err := user.Lookup(username)
	if err != nil {
	}
	_userSID, err := syscall.UTF16PtrFromString(u.Uid)
	if err != nil {
	}
	_username, err := syscall.UTF16PtrFromString(username)
	var ret = "123456789"
	r1, _, e1 := procCreateProfile.Call(
		uintptr(unsafe.Pointer(_userSID)),
		uintptr(unsafe.Pointer(_username)),
		uintptr(unsafe.Pointer(&ret)),
		uintptr(9),
	)

	if int(r1) != 0 {
		os.NewSyscallError("CreateProfile", e1)
		return
	}
}
func CreateUser(username, password string) {
	cmd := exec.Command(
		"net",
		"user",
		username,
		password,
		"/add",
		"/y",
	)
	out, err := cmd.CombinedOutput()
	log.Printf("%s\n", out)
	if err != nil {
	}
}

func DeleteUser(username string) {
	cmd := exec.Command("net", "user", username, "/del", "/y")
	out, err := cmd.CombinedOutput()
	log.Printf("%s\n", out)
	if err != nil {
		log.Printf("%s\n", err)
	}
}

func LogonUser(username *uint16, domain *uint16, password *uint16, logonType uint32, logonProvider uint32) (token syscall.Token) {
	r1, _, _ := procLogonUserW.Call(
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(logonType),
		uintptr(logonProvider),
		uintptr(unsafe.Pointer(&token)))
	if int(r1) == 0 {
	}
	return
}

func LoadUserProfile(token syscall.Token, pinfo *ProfileInfo) error {
	r1, _, e1 := procLoadUserProfileW.Call(
		uintptr(token),
		uintptr(unsafe.Pointer(pinfo)))
	if int(r1) == 0 {
		return os.NewSyscallError("LoadUserProfile", e1)
	}
	return nil
}

// https://docs.microsoft.com/en-us/windows/desktop/api/userenv/nf-userenv-unloaduserprofile
func UnloadUserProfile(token syscall.Token, profile syscall.Handle) error {
	if r1, _, e1 := procUnloadUserProfile.Call(
		uintptr(token),
		uintptr(profile)); int(r1) == 0 {
		return os.NewSyscallError("UnloadUserProfile", e1)
	}
	return nil
}

func LoginAndLogoutUser(username, password string) {
	_username, err := syscall.UTF16PtrFromString(username)
	if err != nil {
	}
	_dot, err := syscall.UTF16PtrFromString(".")
	if err != nil {
	}
	_password, err := syscall.UTF16PtrFromString(password)
	if err != nil {
	}
	userHandle := LogonUser(
		_username,
		_dot,
		_password,
		LOGON32_LOGON_INTERACTIVE,
		LOGON32_PROVIDER_DEFAULT,
	)
	var pinfo ProfileInfo
	pinfo = ProfileInfo{
		Size:     uint32(unsafe.Sizeof(pinfo)),
		Flags:    PI_NOUI,
		Username: _username,
	}
	LoadUserProfile(userHandle, &pinfo)
	UnloadUserProfile(userHandle, pinfo.Profile)
	CloseHandle(syscall.Handle(userHandle))
}

func DeleteProfile(username string) {
	u, err := user.Lookup(username)
	if err != nil {
		panic(err)
		return
	}
	_userSID, err := syscall.UTF16PtrFromString(u.Uid)
	if err != nil {
		panic(err)
		return
	}
	DeleteProfileW(_userSID, nil, nil)
}

// https://docs.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-deleteprofilew
// USERENVAPI BOOL DeleteProfileW(
//   LPCWSTR lpSidString,
//   LPCWSTR lpProfilePath,
//   LPCWSTR lpComputerName
// );
func DeleteProfileW(
	lpSidString *uint16,
	lpProfilePath *uint16,
	lpComputerName *uint16,
) {
	r1, _, e1 := procDeleteProfileW.Call(
		uintptr(unsafe.Pointer(lpSidString)),
		uintptr(unsafe.Pointer(lpProfilePath)),
		uintptr(unsafe.Pointer(lpComputerName)),
	)
	if r1 == 0 {
		log.Printf("%s", os.NewSyscallError("DeleteProfileW", e1))
	}
}

func CloseHandle(handle syscall.Handle) {
	// syscall.CloseHandle(handle)
	r1, _, e1 := procCloseHandle.Call(
		uintptr(handle),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
		} else {
		}
	}
}

func SetupGoRoutines() {
}
