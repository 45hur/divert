package divert

const (
	WINDIVERT_LAYER_NETWORK         = iota
	WINDIVERT_LAYER_NETWORK_FORWARD = iota
	WINDIVERT_LAYER_FLOW            = iota
	WINDIVERT_LAYER_SOCKET          = iota
	WINDIVERT_LAYER_REFLECT         = iota
)

type WINDIVERT_LAYER int

type WINDIVERT_DATA_NETWORK struct {
	IfIdx uint32

	SubIfIdx uint32
}

type WINDIVERT_DATA_FLOW struct {
	Endpoint       uint64
	ParentEndpoint uint64
	ProcessId      uint32
	LocalAddr      uint32 //[4];
	RemoteAddr     uint32 //[4];
	LocalPort      uint16
	RemotePort     uint16
	Protocol       uint8
}

type WINDIVERT_DATA_SOCKET struct {
	Endpoint       uint64
	ParentEndpoint uint64
	ProcessId      uint32
	LocalAddr      uint32 //[4];
	RemoteAddr     uint32 //[4];
	LocalPort      uint16
	RemotePort     uint16
	Protocol       uint8
}

type WINDIVERT_DATA_REFLECT struct {
	Timestamp int64
	ProcessId uint32
	Layer     WINDIVERT_LAYER
	Flags     uint64
	Priority  int16
}

type WINDIVERT_ADDRESS struct {
	Timestamp   int64
	Layer       uint64 //:8;
	Event       uint64 //:8;
	Sniffed     uint64 //:1;
	Outbound    uint64 //:1;
	Loopback    uint64 //:1;
	Impostor    uint64 //:1;
	IPv6        uint64 //:1;
	IPChecksum  uint64 //:1;
	TCPChecksum uint64 //:1;
	UDPChecksum uint64 //:1;
	u           struct {
		Network WINDIVERT_DATA_NETWORK
		Flow    WINDIVERT_DATA_FLOW
		Socket  WINDIVERT_DATA_SOCKET
		Reflect WINDIVERT_DATA_REFLECT
	}
}

type WinDivert struct {
	handle uintptr
}

type Packet struct {
	Raw       []byte
	Addr      *WINDIVERT_ADDRESS
	PacketLen uint
}
