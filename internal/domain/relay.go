package domain

type RelayClient interface {
	Register(bundle PrekeyBundle) error
	FetchPrekey(username string) (PrekeyBundle, error)
}
