package socketcore

// ProtectSocket for android
type ProtectSocket interface {
	Protect(filedescriptor int) int
}
