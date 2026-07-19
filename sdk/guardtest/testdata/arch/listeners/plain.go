package listeners

import "net"

// Planted violations: a TCP listen and a unix-socket listen, both
// unregistered.
func tcp() (net.Listener, error) { return net.Listen("tcp", ":8080") }

func sock() (net.Listener, error) { return net.Listen("unix", "/run/x.sock") }

func multicast() (*net.UDPConn, error) { return net.ListenMulticastUDP("udp", nil, nil) }
