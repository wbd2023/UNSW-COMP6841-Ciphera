package domain

type RelayClient interface {
	Register(bundle PrekeyBundle) error
	// TODO: Send, Recv, FetchPrekeyBundle(username string), etc.
}
