//go:build windows

package color

import (
	"syscall"
	"unsafe"
)

func init() {
	initEnabled()
	if !enabled {
		return
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getStdHandle := kernel32.NewProc("GetStdHandle")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	// STD_OUTPUT_HANDLE = -11
	handle, _, _ := getStdHandle.Call(^uintptr(10))
	if handle == 0 || handle == ^uintptr(0) {
		enabled = false
		return
	}

	var mode uint32
	ret, _, _ := getConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	if ret == 0 {
		// not a real console (e.g. redirected), disable colors
		enabled = false
		return
	}

	const enableVTP = 0x0004 // ENABLE_VIRTUAL_TERMINAL_PROCESSING
	ret, _, _ = setConsoleMode.Call(handle, uintptr(mode|enableVTP))
	if ret == 0 {
		// console doesn't support VTP (very old Windows), disable colors
		enabled = false
	}
}
