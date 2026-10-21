// Command demo runs a whole campaign in one process over real HTTP: a
// customer funds it, an honest worker earns, and a cheater tries every trick
// that works against hashrate-style pools and is rejected each time.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"

	"fuzzpool/internal/coordinator"
	"fuzzpool/internal/identity"
	"fuzzpool/internal/ledger"
	"fuzzpool/internal/money"
	"fuzzpool/internal/protocol"
	"fuzzpool/internal/target"
	"fuzzpool/internal/worker"
)

const adminToken = "demo-admin-token"

func main() {
	ctx := context.Background()
	led := ledger.New()
	coord := coordinator.New(coordinator.DefaultConfig(), led)
	srv := &coordinator.Server{Coord: coord, Ledger: led, AdminToken: adminToken,
		Targets: map[string]target.Executor{"tinyparse": target.TinyParse{}}}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	fmt.Println("== fuzzpool demo ==")
	fmt.Printf("Цель: tinyparse (встроенный парсер с двумя заложенными багами). Координатор: %s\n\n", ts.URL)

	// 1. Customer.
	admin(ts.URL, "/v1/admin/deposits", map[string]any{"account": "customer:acme", "amount": "100", "memo": "оплата картой"}, nil)
	var camp coordinator.CampaignStats
	admin(ts.URL, "/v1/admin/campaigns", map[string]any{
		"name": "tinyparse", "customer": "customer:acme", "budget": "100",
		"price_per_edge": "0.5", "price_per_crash": "20", "target": "tinyparse",
		"seeds": [][]byte{[]byte("FZ\x01\x00")},
	}, &camp)
	fmt.Println("[1] Заказчик внёс 100.000000 и создал кампанию")
	fmt.Printf("    комиссия платформы (5%%, известна заранее): %s\n", led.Balance(ledger.Platform))
	fmt.Printf("    в эскроу: %s | цена: 0.5 за новое ребро покрытия, 20 за новый уникальный краш\n", camp.EscrowRemaining)
	fmt.Printf("    покрытие сидов заказчика засчитано бесплатно: %d рёбер\n\n", camp.BaselineEdges)

	// 2. Honest worker.
	honest := newWorker(ctx, ts.URL)
	fmt.Printf("[2] Честный воркер %s: залог 5.000000, 3 раунда фаззинга\n", short(honest.Signer.ID()))
	for round := 1; round <= 3; round++ {
		w := &worker.Worker{Client: honest, Engine: &worker.MutationEngine{
			Exec: target.TinyParse{}, Iterations: 600_000, MaxInputs: 256,
			Rand: rand.New(rand.NewPCG(uint64(round), 42)),
		}}
		resp, err := w.Round(ctx)
		if err != nil {
			log.Fatal(err)
		}
		edges, crashes := 0, 0
		for _, v := range resp.Verdicts {
			edges += v.NewEdges
			if v.Status == protocol.StatusNewCrash {
				crashes++
			}
		}
		fmt.Printf("    раунд %d: отправлено входов %d → новых рёбер %d, новых крашей %d, выплачено %s\n",
			round, len(resp.Verdicts), edges, crashes, resp.Paid)
	}
	fmt.Println()

	// 3. Cheater.
	cheater := newWorker(ctx, ts.URL)
	fmt.Printf("[3] Мошенник %s: залог 5.000000, пробует обмануть систему\n", short(cheater.Signer.ID()))
	l, err := cheater.Lease(ctx)
	if err != nil {
		log.Fatal(err)
	}

	raw := fmt.Sprintf(`{"worker_id":%q,"lease_id":%q,"nonce":1,"inputs":[{"data":"QUFBQQ=="}],"hashrate_gh_s":1700}`, cheater.Signer.ID(), l.ID)
	fmt.Printf("    а) заявил «hashrate_gh_s: 1700» (как в пулах с самоотчётом)\n       → %s\n",
		outcome(cheater.Do(ctx, http.MethodPost, "/v1/submissions", []byte(raw), nil)))

	var stolen []protocol.Input
	for _, s := range l.Seeds {
		stolen = append(stolen, protocol.Input{Data: s})
	}
	resp, err := cheater.Submit(ctx, l.ID, stolen)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    б) переотправил чужой корпус (%d входов из своей лизы)\n       → выплачено %s, вердикты: %s\n",
		len(stolen), resp.Paid, verdicts(resp.Verdicts))

	sub := cheater.NewSubmission(l.ID, []protocol.Input{{Data: []byte("FZ\x01\x00")}})
	_, _ = cheater.Send(ctx, sub)
	fmt.Printf("    в) повторил уже принятый подписанный запрос\n       → %s\n", outcome(sendErr(cheater.Send(ctx, sub))))

	forged := protocol.Submission{WorkerID: honest.Signer.ID(), LeaseID: l.ID, Nonce: 1 << 62, Inputs: []protocol.Input{{Data: []byte("x")}}}
	forged.Sig = cheater.Signer.Sign(protocol.DomainSubmit, forged.SigningBytes())
	fmt.Printf("    г) отправил запрос от имени честного воркера, подписав своим ключом\n       → %s\n", outcome(sendErr(cheater.Send(ctx, forged))))

	hl, err := honest.Lease(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    д) попробовал сдать работу по чужой лизе\n       → %s\n",
		outcome(sendErr(cheater.Submit(ctx, hl.ID, []protocol.Input{{Data: []byte("y")}}))))

	resp, err = cheater.Submit(ctx, l.ID, []protocol.Input{{Data: []byte("AAAA"), ClaimCrash: true}})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("    е) заявил краш на безобидном входе\n       → %s, списано из залога %s\n\n", resp.Verdicts[0].Status, resp.Slashed)

	// 4. Results.
	fmt.Println("[4] Итог")
	names := map[ledger.Account]string{
		"customer:acme":                                "заказчик",
		ledger.Platform:                                "платформа (комиссия)",
		ledger.External:                                "внешний мир (−всё, что внесено)",
		coordinator.EscrowAccount(camp.ID):             "эскроу кампании",
		coordinator.WalletAccount(honest.Signer.ID()):  "кошелёк честного",
		coordinator.StakeAccount(honest.Signer.ID()):   "залог честного",
		coordinator.WalletAccount(cheater.Signer.ID()): "кошелёк мошенника",
		coordinator.StakeAccount(cheater.Signer.ID()):  "залог мошенника",
	}
	var rows [][2]string
	for _, b := range led.Balances() {
		rows = append(rows, [2]string{names[b.Account], b.Balance.String()})
	}
	for _, a := range []ledger.Account{"customer:acme", coordinator.WalletAccount(cheater.Signer.ID())} {
		if led.Balance(a) == 0 {
			rows = append(rows, [2]string{names[a], money.Amount(0).String()})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	for _, r := range rows {
		fmt.Printf("    %-34s %16s\n", r[0], r[1])
	}
	if err := led.CheckInvariant(); err != nil {
		fmt.Printf("\n    Инвариант бухгалтерии НАРУШЕН: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n    Инвариант бухгалтерии: OK — сумма всех счетов = 0, журнал из %d записей воспроизводит каждый баланс.\n", len(led.Journal()))
	fmt.Println("    Ни одной монеты не создано: всё, что получили воркеры, оплатил заказчик.")

	st, _ := coord.Campaign(camp.ID)
	fmt.Printf("\n    Покрытие: %d рёбер (из них %d — бесплатный базис заказчика); корпус: %d входов\n", st.Edges, st.BaselineEdges, st.CorpusSize)
	fmt.Println("    Найденные краши (каждый проверен двумя повторными запусками на координаторе):")
	for _, c := range st.Crashes {
		repro, _ := coord.Reproducer(camp.ID, c.Signature)
		fmt.Printf("      %-22s sig=%s  %s  нашёл %s, вход %+q, выплачено %s\n",
			c.Kind, c.Signature, strings.Join(c.Frames, " ← "), short(c.FoundBy), repro, c.Paid)
	}
}

func newWorker(ctx context.Context, url string) *worker.Client {
	s, err := identity.GenerateSigner()
	if err != nil {
		log.Fatal(err)
	}
	c := &worker.Client{BaseURL: url, Signer: s}
	if _, err := c.Register(ctx); err != nil {
		log.Fatal(err)
	}
	admin(url, "/v1/admin/deposits", map[string]any{"account": coordinator.StakeAccount(s.ID()), "amount": "5", "memo": "залог"}, nil)
	return c
}

func admin(url, path string, in, out any) {
	b, _ := json.Marshal(in)
	req, _ := http.NewRequest(http.MethodPost, url+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("%s: HTTP %d", path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			log.Fatal(err)
		}
	}
}

func sendErr(_ protocol.SubmitResponse, err error) error { return err }

func outcome(err error) string {
	var apiErr *worker.APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("отклонено: HTTP %d %s", apiErr.Status, apiErr.Message)
	}
	if err != nil {
		return "ошибка: " + err.Error()
	}
	return "ПРИНЯТО (это была бы дыра)"
}

func verdicts(vs []protocol.Verdict) string {
	counts := map[string]int{}
	for _, v := range vs {
		counts[v.Status]++
	}
	var parts []string
	for k, n := range counts {
		parts = append(parts, fmt.Sprintf("%s×%d", k, n))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func short(id identity.WorkerID) string { return string(id)[:8] + "…" }
