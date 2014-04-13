package crypto

type KeyNotFoundError string

func (e KeyNotFoundError) Error() string {
	return "comm_denoisr: key not found for '" + string(e) + "'"
}
