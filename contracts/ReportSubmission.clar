(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-PROOF u101)
(define-constant ERR-INVALID-HASH u102)
(define-constant ERR-INVALID-SUMMARY u103)
(define-constant ERR-INVALID-REPORT-ID u104)
(define-constant ERR-REPORT-ALREADY-EXISTS u105)
(define-constant ERR-REPORT-NOT-FOUND u106)
(define-constant ERR-INVALID-TIMESTAMP u107)
(define-constant ERR-VERIFIER-NOT-SET u108)
(define-constant ERR-BOUNTY-POOL-NOT-SET u109)
(define-constant ERR-INVALID-REWARD-AMOUNT u110)
(define-constant ERR-INSUFFICIENT-BOUNTY u111)
(define-constant ERR-INVALID-STATUS u112)
(define-constant ERR-SYBIL-ATTACK-DETECTED u113)
(define-constant ERR-INVALID-THRESHOLD u114)
(define-constant ERR-INVALID-EXPIRY u115)
(define-constant ERR-EXPIRED-REPORT u116)
(define-constant ERR-INVALID-ANONYMITY-LEVEL u117)
(define-constant ERR-INVALID-EVIDENCE-HASH u118)
(define-constant ERR-INVALID-CATEGORY u119)
(define-constant ERR-INVALID-SEVERITY u120)
(define-constant ERR-MAX-REPORTS-EXCEEDED u121)
(define-constant ERR-INVALID-UPDATE-PARAM u122)
(define-constant ERR-UPDATE-NOT-ALLOWED u123)

(define-data-var next-report-id uint u0)
(define-data-var max-reports uint u10000)
(define-data-var submission-fee uint u100)
(define-data-var verifier-contract (optional principal) none)
(define-data-var bounty-pool-contract (optional principal) none)
(define-data-var min-reward uint u50)
(define-data-var max-reward uint u1000)
(define-data-var report-expiry uint u144)
(define-data-var sybil-threshold uint u5)
(define-data-var anonymity-level uint u2)

(define-map reports
  uint
  {
    proof: (buff 256),
    hash: (buff 32),
    summary: (string-utf8 256),
    timestamp: uint,
    submitter: principal,
    status: bool,
    reward-claimed: bool,
    category: (string-utf8 50),
    severity: uint,
    evidence-hash: (buff 32),
    expiry: uint
  }
)

(define-map reports-by-hash
  (buff 32)
  uint
)

(define-map report-updates
  uint
  {
    update-summary: (string-utf8 256),
    update-timestamp: uint,
    updater: principal
  }
)

(define-map submitter-history
  principal
  { count: uint, last-submission: uint }
)

(define-read-only (get-report (id uint))
  (map-get? reports id)
)

(define-read-only (get-report-updates (id uint))
  (map-get? report-updates id)
)

(define-read-only (is-report-registered (hash (buff 32)))
  (is-some (map-get? reports-by-hash hash))
)

(define-private (validate-proof (proof (buff 256)))
  (if (> (len proof) u0)
      (ok true)
      (err ERR-INVALID-PROOF))
)

(define-private (validate-hash (hash (buff 32)))
  (if (is-eq (len hash) u32)
      (ok true)
      (err ERR-INVALID-HASH))
)

(define-private (validate-summary (summary (string-utf8 256)))
  (if (and (> (len summary) u0) (<= (len summary) u256))
      (ok true)
      (err ERR-INVALID-SUMMARY))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
      (ok true)
      (err ERR-INVALID-TIMESTAMP))
)

(define-private (validate-category (cat (string-utf8 50)))
  (if (or (is-eq cat "bribery") (is-eq cat "corruption") (is-eq cat "fraud"))
      (ok true)
      (err ERR-INVALID-CATEGORY))
)

(define-private (validate-severity (sev uint))
  (if (and (>= sev u1) (<= sev u10))
      (ok true)
      (err ERR-INVALID-SEVERITY))
)

(define-private (validate-evidence-hash (ehash (buff 32)))
  (if (is-eq (len ehash) u32)
      (ok true)
      (err ERR-INVALID-EVIDENCE-HASH))
)

(define-private (validate-expiry (exp uint))
  (if (> exp block-height)
      (ok true)
      (err ERR-INVALID-EXPIRY))
)

(define-private (check-sybil (submitter principal))
  (let ((history (default-to { count: u0, last-submission: u0 } (map-get? submitter-history submitter))))
    (if (>= (get count history) (var-get sybil-threshold))
        (err ERR-SYBIL-ATTACK-DETECTED)
        (ok true))
  )
)

(define-private (update-submitter-history (submitter principal))
  (let ((history (default-to { count: u0, last-submission: u0 } (map-get? submitter-history submitter))))
    (map-set submitter-history submitter
      { count: (+ (get count history) u1), last-submission: block-height })
    (ok true)
  )
)

(define-public (set-verifier-contract (contract-principal principal))
  (begin
    (asserts! (is-none (var-get verifier-contract)) (err ERR-VERIFIER-NOT-SET))
    (var-set verifier-contract (some contract-principal))
    (ok true)
  )
)

(define-public (set-bounty-pool-contract (contract-principal principal))
  (begin
    (asserts! (is-none (var-get bounty-pool-contract)) (err ERR-BOUNTY-POOL-NOT-SET))
    (var-set bounty-pool-contract (some contract-principal))
    (ok true)
  )
)

(define-public (set-min-reward (new-min uint))
  (begin
    (asserts! (> new-min u0) (err ERR-INVALID-REWARD-AMOUNT))
    (var-set min-reward new-min)
    (ok true)
  )
)

(define-public (set-max-reward (new-max uint))
  (begin
    (asserts! (> new-max (var-get min-reward)) (err ERR-INVALID-REWARD-AMOUNT))
    (var-set max-reward new-max)
    (ok true)
  )
)

(define-public (set-report-expiry (new-expiry uint))
  (begin
    (asserts! (> new-expiry u0) (err ERR-INVALID-EXPIRY))
    (var-set report-expiry new-expiry)
    (ok true)
  )
)

(define-public (set-sybil-threshold (new-threshold uint))
  (begin
    (asserts! (> new-threshold u0) (err ERR-INVALID-THRESHOLD))
    (var-set sybil-threshold new-threshold)
    (ok true)
  )
)

(define-public (set-anonymity-level (new-level uint))
  (begin
    (asserts! (and (>= new-level u1) (<= new-level u5)) (err ERR-INVALID-ANONYMITY-LEVEL))
    (var-set anonymity-level new-level)
    (ok true)
  )
)

(define-public (submit-report
  (proof (buff 256))
  (hash (buff 32))
  (summary (string-utf8 256))
  (category (string-utf8 50))
  (severity uint)
  (evidence-hash (buff 32))
)
  (let (
    (next-id (var-get next-report-id))
    (current-max (var-get max-reports))
    (verifier (unwrap! (var-get verifier-contract) (err ERR-VERIFIER-NOT-SET)))
    (bounty-pool (unwrap! (var-get bounty-pool-contract) (err ERR-BOUNTY-POOL-NOT-SET)))
    (expiry (+ block-height (var-get report-expiry)))
  )
    (asserts! (< next-id current-max) (err ERR-MAX-REPORTS-EXCEEDED))
    (try! (validate-proof proof))
    (try! (validate-hash hash))
    (try! (validate-summary summary))
    (try! (validate-category category))
    (try! (validate-severity severity))
    (try! (validate-evidence-hash evidence-hash))
    (try! (check-sybil tx-sender))
    (asserts! (is-none (map-get? reports-by-hash hash)) (err ERR-REPORT-ALREADY-EXISTS))
    (try! (stx-transfer? (var-get submission-fee) tx-sender bounty-pool))
    (let ((verified (as-contract (contract-call? verifier verify-proof proof))))
      (asserts! (is-ok verified) (err ERR-INVALID-PROOF))
    )
    (map-set reports next-id
      {
        proof: proof,
        hash: hash,
        summary: summary,
        timestamp: block-height,
        submitter: tx-sender,
        status: true,
        reward-claimed: false,
        category: category,
        severity: severity,
        evidence-hash: evidence-hash,
        expiry: expiry
      }
    )
    (map-set reports-by-hash hash next-id)
    (try! (update-submitter-history tx-sender))
    (var-set next-report-id (+ next-id u1))
    (print { event: "report-submitted", id: next-id })
    (ok next-id)
  )
)

(define-public (update-report-summary
  (report-id uint)
  (new-summary (string-utf8 256))
)
  (let ((report (map-get? reports report-id)))
    (match report
      r
      (begin
        (asserts! (is-eq (get submitter r) tx-sender) (err ERR-NOT-AUTHORIZED))
        (asserts! (< block-height (get expiry r)) (err ERR-EXPIRED-REPORT))
        (try! (validate-summary new-summary))
        (map-set reports report-id
          (merge r { summary: new-summary, timestamp: block-height })
        )
        (map-set report-updates report-id
          {
            update-summary: new-summary,
            update-timestamp: block-height,
            updater: tx-sender
          }
        )
        (print { event: "report-updated", id: report-id })
        (ok true)
      )
      (err ERR-REPORT-NOT-FOUND)
    )
  )
)

(define-public (claim-reward (report-id uint))
  (let ((report (map-get? reports report-id))
        (bounty-pool (unwrap! (var-get bounty-pool-contract) (err ERR-BOUNTY-POOL-NOT-SET))))
    (match report
      r
      (begin
        (asserts! (is-eq (get submitter r) tx-sender) (err ERR-NOT-AUTHORIZED))
        (asserts! (get status r) (err ERR-INVALID-STATUS))
        (asserts! (not (get reward-claimed r)) (err ERR-INVALID-STATUS))
        (asserts! (< block-height (get expiry r)) (err ERR-EXPIRED-REPORT))
        (let ((reward-amount (+ (var-get min-reward) (* (get severity r) u10))))
          (asserts! (<= reward-amount (var-get max-reward)) (err ERR-INVALID-REWARD-AMOUNT))
          (as-contract (try! (contract-call? bounty-pool transfer-reward tx-sender reward-amount)))
        )
        (map-set reports report-id
          (merge r { reward-claimed: true })
        )
        (print { event: "reward-claimed", id: report-id })
        (ok true)
      )
      (err ERR-REPORT-NOT-FOUND)
    )
  )
)

(define-public (get-report-count)
  (ok (var-get next-report-id))
)

(define-public (check-report-existence (hash (buff 32)))
  (ok (is-report-registered hash))
)