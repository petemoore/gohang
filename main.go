package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"syscall"
	"unsafe"
)

const (
	LOGON32_PROVIDER_DEFAULT  = 0
	LOGON32_LOGON_INTERACTIVE = 2
	PI_NOUI                   = 1
)

var (
	advapi32       = NewLazyDLL("advapi32.dll")
	procLogonUserW = advapi32.NewProc("LogonUserW")

	kernel32        = NewLazyDLL("kernel32.dll")
	procCloseHandle = kernel32.NewProc("CloseHandle")

	userenv               = NewLazyDLL("userenv.dll")
	procDeleteProfileW    = userenv.NewProc("DeleteProfileW")
	procLoadUserProfileW  = userenv.NewProc("LoadUserProfileW")
	procUnloadUserProfile = userenv.NewProc("UnloadUserProfile")
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
	SetupGoRoutines()
	for i := 0; ; i++ {
		username := fmt.Sprintf("testuser%v", i)
		password := "_$rg274SGFh54D&$%"
		// If user already exists, delete it
		DeleteUser(username)
		log.Printf("Creating user %v...", username)
		CreateProfile(username, password)
		log.Printf("Logging user %v in and out...", username)
		LoginAndLogoutUser(username, password)
		log.Printf("Deleting user profile %v...", username)
		DeleteProfile(username)
		log.Printf("Deleting user account %v...", username)
		out, err := DeleteUser(username)
		log.Printf("%s\n", out)
		if err != nil {
			panic(err)
		}
	}
}

func DeleteUser(username string) (out []byte, err error) {
	cmd := exec.Command(
		"net",
		"user",
		username,
		"/delete",
	)
	return cmd.CombinedOutput()
}

func CreateProfile(username, password string) {
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
		panic(err)
	}
}

func LogonUser(username *uint16, domain *uint16, password *uint16, logonType uint32, logonProvider uint32) (token syscall.Token) {
	r1, _, e1 := procLogonUserW.Call(
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(logonType),
		uintptr(logonProvider),
		uintptr(unsafe.Pointer(&token)))
	if int(r1) == 0 {
		panic(os.NewSyscallError("LogonUser", e1))
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
		panic(err)
	}
	_dot, err := syscall.UTF16PtrFromString(".")
	if err != nil {
		panic(err)
	}
	_password, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		panic(err)
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
	}
	_userSID, err := syscall.UTF16PtrFromString(u.Uid)
	if err != nil {
		panic(err)
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
		panic(os.NewSyscallError("DeleteProfileW", e1))
	}
}

func CloseHandle(handle syscall.Handle) {
	// syscall.CloseHandle(handle)
	r1, _, e1 := procCloseHandle.Call(
		uintptr(handle),
	)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			panic(error(e1))
		} else {
			panic(syscall.EINVAL)
		}
	}
}

func SetupGoRoutines() {
}
