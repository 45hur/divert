package divert

import (
	"syscall"
	"unsafe"
)

var (
	winDivertDLL *syscall.LazyDLL

	winDivertOpen                *syscall.LazyProc
	winDivertClose               *syscall.LazyProc
	winDivertRecv                *syscall.LazyProc
	winDivertSend                *syscall.LazyProc
	winDivertRecvEx              *syscall.LazyProc
	winDivertSendEx              *syscall.LazyProc
	winDivertHelperCalcChecksums *syscall.LazyProc
	winDivertHelperEvalFilter    *syscall.LazyProc
	winDivertHelperCheckFilter   *syscall.LazyProc
)

func Initialize() {
	winDivertDLL = syscall.NewLazyDLL("WinDivert.dll")

	winDivertOpen = winDivertDLL.NewProc("WinDivertOpen")
	winDivertClose = winDivertDLL.NewProc("WinDivertClose")
	winDivertRecv = winDivertDLL.NewProc("WinDivertRecv")
	winDivertSend = winDivertDLL.NewProc("WinDivertSend")
	winDivertRecvEx = winDivertDLL.NewProc("WinDivertRecvEx")
	winDivertSendEx = winDivertDLL.NewProc("WinDivertSendEx")
	winDivertHelperCalcChecksums = winDivertDLL.NewProc("WinDivertHelperCalcChecksums")
	winDivertHelperEvalFilter = winDivertDLL.NewProc("WinDivertHelperEvalFilter")
	winDivertHelperCheckFilter = winDivertDLL.NewProc("WinDivertHelperCheckFilter")
}

// https://reqrypt.org/windivert-doc.html#divert_open
func Open(filter *string, layer int, priority int16, flags uint64) (*WinDivert, error) {
	handle, _, err := winDivertOpen.Call(uintptr(unsafe.Pointer(filter)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags))

	if handle == uintptr(syscall.InvalidHandle) {
		return nil, err
	}

	return &WinDivert{
		handle: handle,
	}, nil
}

// https://reqrypt.org/windivert-doc.html#divert_close
func (wd *WinDivert) Close() error {
	_, _, err := winDivertClose.Call(wd.handle)
	return err
}

// https://reqrypt.org/windivert-doc.html#divert_recv
func (wd *WinDivert) Recv() (*Packet, error) {
	packetBuffer := make([]byte, PacketBufferSize)

	var packetLen uint
	var addr WINDIVERT_ADDRESS
	success, _, err := winDivertRecv.Call(wd.handle,
		uintptr(unsafe.Pointer(&packetBuffer[0])),
		uintptr(PacketBufferSize),
		uintptr(unsafe.Pointer(&packetLen)),
		uintptr(unsafe.Pointer(&addr)))

	if success == 0 {
		return nil, err
	}

	packet := &Packet{
		Raw:       packetBuffer[:packetLen],
		Addr:      &addr,
		PacketLen: packetLen,
	}

	return packet, nil
}

func (wd *WinDivert) RecvEx(packet *Packet) (uint, error) {
	packetBuffer := make([]byte, PacketBufferSize)

	var readLen uint
	var addr WINDIVERT_ADDRESS
	var no NativeOverlapped
	success, _, err := winDivertRecvEx.Call(wd.handle,
		uintptr(unsafe.Pointer(&(packetBuffer[0]))),
		uintptr(0), //flags
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&readLen)),
		uintptr(unsafe.Pointer(&packet.Addr)),
		uintptr(unsafe.Pointer(&no)))

	if success == 0 {
		return 0, err
	}

	return readLen, nil
}

// https://reqrypt.org/windivert-doc.html#divert_send
func (wd *WinDivert) Send(packet *Packet) (uint, error) {
	var sendLen uint

	success, _, err := winDivertSend.Call(wd.handle,
		uintptr(unsafe.Pointer(&(packet.Raw[0]))),
		uintptr(packet.PacketLen),
		uintptr(unsafe.Pointer(packet.Addr)),
		uintptr(unsafe.Pointer(&sendLen)))

	if success == 0 {
		return 0, err
	}

	return sendLen, nil
}

func (wd *WinDivert) SendEx(packet *Packet) (uint, error) {
	var sendLen uint

	success, _, err := winDivertSendEx.Call(wd.handle,
		uintptr(unsafe.Pointer(&(packet.Raw[0]))),
		uintptr(packet.PacketLen),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(0), //flags
		uintptr(unsafe.Pointer(&packet.Addr)),
		uintptr(packet.AddrLen),
		uintptr(unsafe.Pointer(&packet.Overlapped)))

	if success == 0 {
		return 0, err
	}

	return sendLen, nil
}

// https://reqrypt.org/windivert-doc.html#divert_helper_calc_checksums
func (wd *WinDivert) HelperCalcChecksum(packet *Packet) {
	winDivertHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packet.Raw[0])),
		uintptr(packet.PacketLen),
		uintptr(unsafe.Pointer(&packet.Addr)),
		uintptr(0))
}

// https://reqrypt.org/windivert-doc.html#divert_helper_check_filter
func HelperCheckFilter(filter *string) (bool, int) {
	var errorPos uint

	success, _, _ := winDivertHelperCheckFilter.Call(
		uintptr(unsafe.Pointer(filter)),
		uintptr(0),
		uintptr(0), // Not implemented yet
		uintptr(unsafe.Pointer(&errorPos)))

	if success == 1 {
		return true, -1
	}
	return false, int(errorPos)
}

// https://reqrypt.org/windivert-doc.html#divert_helper_eval_filter
func HelperEvalFilter(packet *Packet, filter *string) (bool, error) {
	success, _, err := winDivertHelperEvalFilter.Call(
		uintptr(unsafe.Pointer(filter)),
		uintptr(0),
		uintptr(unsafe.Pointer(&packet.Raw[0])),
		uintptr(packet.PacketLen),
		uintptr(unsafe.Pointer(&packet.Addr)))

	if success == 0 {
		return false, err
	}

	return true, nil
}
