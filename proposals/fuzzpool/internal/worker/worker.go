package worker

import (
	"context"

	"fuzzpool/internal/protocol"
)

type Worker struct {
	Client *Client
	Engine Engine
}

// Round leases one campaign, fuzzes it and submits the results in batches
// no larger than the lease allows.
func (w *Worker) Round(ctx context.Context) (protocol.SubmitResponse, error) {
	lease, err := w.Client.Lease(ctx)
	if err != nil {
		return protocol.SubmitResponse{}, err
	}
	inputs, err := w.Engine.Fuzz(ctx, lease)
	if err != nil {
		return protocol.SubmitResponse{}, err
	}
	batch := lease.MaxInputs
	if batch <= 0 {
		batch = 64
	}
	var total protocol.SubmitResponse
	for start := 0; start < len(inputs); start += batch {
		resp, err := w.Client.Submit(ctx, lease.ID, inputs[start:min(start+batch, len(inputs))])
		if err != nil {
			return total, err
		}
		for _, v := range resp.Verdicts {
			v.Index += start
			total.Verdicts = append(total.Verdicts, v)
		}
		total.Paid += resp.Paid
		total.Slashed += resp.Slashed
		total.EscrowRemaining = resp.EscrowRemaining
		total.CampaignOpen = resp.CampaignOpen
		if !resp.CampaignOpen {
			break
		}
	}
	return total, nil
}
