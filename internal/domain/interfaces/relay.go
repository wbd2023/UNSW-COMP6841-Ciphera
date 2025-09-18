package interfaces

import (
	"context"

	domaintypes "ciphera/internal/domain/types"
)

// RelayClient is how we talk to the central relay server, all with context.
type RelayClient interface {
	RegisterPreKeyBundle(ctx context.Context, bundle domaintypes.PreKeyBundle) error
	FetchPreKeyBundle(
		ctx context.Context,
		username domaintypes.Username,
	) (domaintypes.PreKeyBundle, error)

	SendMessage(ctx context.Context, envelope domaintypes.Envelope) error
	FetchMessages(
		ctx context.Context,
		username domaintypes.Username,
		limit int,
	) ([]domaintypes.Envelope, error)
	AckMessages(ctx context.Context, username domaintypes.Username, count int) error
	FetchAccountCanary(ctx context.Context, username domaintypes.Username) (string, error)
}
