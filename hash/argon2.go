package hash

const (
	// default delimiter for argon2 hash format
	defaultDelimiter = "$"

	// standard length of values from argon2 hashed string with default delimiter
	standardLengthValues = 6

	/*
		NOTE: values with '$' as delimiter
			1: hash algorithm name
			2: argon2 (v)ersion
			3: (m)emory, i(t)erations, (p)arallelism used for hash
			4: salt with encoded base64
			5: hash with encoded base64
	*/
	standardHashFormat = "$argon2id$v=%d$m=%d,t=$d,p=%d$%s$%s"
)

func HashArgon2() {

}
