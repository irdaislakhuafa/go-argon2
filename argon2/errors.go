package argon2

type Error struct {
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

func NewErr(s string) error {
	return &Error{Message: s}
}

var (
	ErrHashNotMatch              = NewErr("argon2 hash and plain is not match")
	ErrInvalidHashLength         = NewErr("argon2 hash is invalid length")
	ErrArgon2Version             = NewErr("error get argon version on decode hash")
	ErrIncompatibleArgon2Version = NewErr("incompatible argon2 version")
	ErrArgon2Format              = NewErr("error while get values from memory, iterations, and parallelism")
	ErrDecodeSalt                = NewErr("error while decode salt from values")
	ErrDecodeHash                = NewErr("error while decode hash from values")
)
