import { describe, it, expect, beforeEach } from "vitest";
import { buffCV, stringUtf8CV, uintCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_INVALID_PROOF = 101;
const ERR_INVALID_HASH = 102;
const ERR_INVALID_SUMMARY = 103;
const ERR_REPORT_ALREADY_EXISTS = 105;
const ERR_REPORT_NOT_FOUND = 106;
const ERR_VERIFIER_NOT_SET = 108;
const ERR_BOUNTY_POOL_NOT_SET = 109;
const ERR_INVALID_REWARD_AMOUNT = 110;
const ERR_INVALID_CATEGORY = 119;
const ERR_INVALID_SEVERITY = 120;
const ERR_INVALID_EVIDENCE_HASH = 118;
const ERR_MAX_REPORTS_EXCEEDED = 121;
const ERR_INVALID_UPDATE_PARAM = 122;
const ERR_SYBIL_ATTACK_DETECTED = 113;
const ERR_EXPIRED_REPORT = 116;

interface Report {
  proof: Uint8Array;
  hash: Uint8Array;
  summary: string;
  timestamp: number;
  submitter: string;
  status: boolean;
  rewardClaimed: boolean;
  category: string;
  severity: number;
  evidenceHash: Uint8Array;
  expiry: number;
}

interface ReportUpdate {
  updateSummary: string;
  updateTimestamp: number;
  updater: string;
}

interface SubmitterHistory {
  count: number;
  lastSubmission: number;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class ReportSubmissionMock {
  state: {
    nextReportId: number;
    maxReports: number;
    submissionFee: number;
    verifierContract: string | null;
    bountyPoolContract: string | null;
    minReward: number;
    maxReward: number;
    reportExpiry: number;
    sybilThreshold: number;
    anonymityLevel: number;
    reports: Map<number, Report>;
    reportUpdates: Map<number, ReportUpdate>;
    reportsByHash: Map<string, number>;
    submitterHistory: Map<string, SubmitterHistory>;
  } = {
    nextReportId: 0,
    maxReports: 10000,
    submissionFee: 100,
    verifierContract: null,
    bountyPoolContract: null,
    minReward: 50,
    maxReward: 1000,
    reportExpiry: 144,
    sybilThreshold: 5,
    anonymityLevel: 2,
    reports: new Map(),
    reportUpdates: new Map(),
    reportsByHash: new Map(),
    submitterHistory: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1SUBMITTER";
  stxTransfers: Array<{ amount: number; from: string; to: string | null }> = [];
  verifiedProofs: Set<string> = new Set();
  bountyTransfers: Array<{ amount: number; to: string }> = [];

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextReportId: 0,
      maxReports: 10000,
      submissionFee: 100,
      verifierContract: null,
      bountyPoolContract: null,
      minReward: 50,
      maxReward: 1000,
      reportExpiry: 144,
      sybilThreshold: 5,
      anonymityLevel: 2,
      reports: new Map(),
      reportUpdates: new Map(),
      reportsByHash: new Map(),
      submitterHistory: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1SUBMITTER";
    this.stxTransfers = [];
    this.verifiedProofs = new Set();
    this.bountyTransfers = [];
  }

  setVerifierContract(contractPrincipal: string): Result<boolean> {
    if (this.state.verifierContract !== null) return { ok: false, value: false };
    this.state.verifierContract = contractPrincipal;
    return { ok: true, value: true };
  }

  setBountyPoolContract(contractPrincipal: string): Result<boolean> {
    if (this.state.bountyPoolContract !== null) return { ok: false, value: false };
    this.state.bountyPoolContract = contractPrincipal;
    return { ok: true, value: true };
  }

  setMinReward(newMin: number): Result<boolean> {
    if (newMin <= 0) return { ok: false, value: false };
    this.state.minReward = newMin;
    return { ok: true, value: true };
  }

  setMaxReward(newMax: number): Result<boolean> {
    if (newMax <= this.state.minReward) return { ok: false, value: false };
    this.state.maxReward = newMax;
    return { ok: true, value: true };
  }

  setReportExpiry(newExpiry: number): Result<boolean> {
    if (newExpiry <= 0) return { ok: false, value: false };
    this.state.reportExpiry = newExpiry;
    return { ok: true, value: true };
  }

  setSybilThreshold(newThreshold: number): Result<boolean> {
    if (newThreshold <= 0) return { ok: false, value: false };
    this.state.sybilThreshold = newThreshold;
    return { ok: true, value: true };
  }

  submitReport(
    proof: Uint8Array,
    hash: Uint8Array,
    summary: string,
    category: string,
    severity: number,
    evidenceHash: Uint8Array
  ): Result<number> {
    if (this.state.nextReportId >= this.state.maxReports) return { ok: false, value: ERR_MAX_REPORTS_EXCEEDED };
    if (proof.length === 0) return { ok: false, value: ERR_INVALID_PROOF };
    if (hash.length !== 32) return { ok: false, value: ERR_INVALID_HASH };
    if (summary.length === 0 || summary.length > 256) return { ok: false, value: ERR_INVALID_SUMMARY };
    if (!["bribery", "corruption", "fraud"].includes(category)) return { ok: false, value: ERR_INVALID_CATEGORY };
    if (severity < 1 || severity > 10) return { ok: false, value: ERR_INVALID_SEVERITY };
    if (evidenceHash.length !== 32) return { ok: false, value: ERR_INVALID_EVIDENCE_HASH };
    const history = this.state.submitterHistory.get(this.caller) || { count: 0, lastSubmission: 0 };
    if (history.count >= this.state.sybilThreshold) return { ok: false, value: ERR_SYBIL_ATTACK_DETECTED };
    const hashKey = hash.toString();
    if (this.state.reportsByHash.has(hashKey)) return { ok: false, value: ERR_REPORT_ALREADY_EXISTS };
    if (!this.state.verifierContract) return { ok: false, value: ERR_VERIFIER_NOT_SET };
    if (!this.state.bountyPoolContract) return { ok: false, value: ERR_BOUNTY_POOL_NOT_SET };
    if (!this.verifiedProofs.has(proof.toString())) return { ok: false, value: ERR_INVALID_PROOF };

    this.stxTransfers.push({ amount: this.state.submissionFee, from: this.caller, to: this.state.bountyPoolContract });

    const id = this.state.nextReportId;
    const expiry = this.blockHeight + this.state.reportExpiry;
    const report: Report = {
      proof,
      hash,
      summary,
      timestamp: this.blockHeight,
      submitter: this.caller,
      status: true,
      rewardClaimed: false,
      category,
      severity,
      evidenceHash,
      expiry,
    };
    this.state.reports.set(id, report);
    this.state.reportsByHash.set(hashKey, id);
    this.state.submitterHistory.set(this.caller, { count: history.count + 1, lastSubmission: this.blockHeight });
    this.state.nextReportId++;
    return { ok: true, value: id };
  }

  getReport(id: number): Report | null {
    return this.state.reports.get(id) || null;
  }

  updateReportSummary(id: number, newSummary: string): Result<boolean> {
    const report = this.state.reports.get(id);
    if (!report) return { ok: false, value: false };
    if (report.submitter !== this.caller) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (this.blockHeight >= report.expiry) return { ok: false, value: ERR_EXPIRED_REPORT };
    if (newSummary.length === 0 || newSummary.length > 256) return { ok: false, value: ERR_INVALID_UPDATE_PARAM };

    const updated: Report = {
      ...report,
      summary: newSummary,
      timestamp: this.blockHeight,
    };
    this.state.reports.set(id, updated);
    this.state.reportUpdates.set(id, {
      updateSummary: newSummary,
      updateTimestamp: this.blockHeight,
      updater: this.caller,
    });
    return { ok: true, value: true };
  }

  claimReward(id: number): Result<boolean> {
    const report = this.state.reports.get(id);
    if (!report) return { ok: false, value: false };
    if (report.submitter !== this.caller) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (!report.status) return { ok: false, value: false };
    if (report.rewardClaimed) return { ok: false, value: false };
    if (this.blockHeight >= report.expiry) return { ok: false, value: ERR_EXPIRED_REPORT };
    if (!this.state.bountyPoolContract) return { ok: false, value: ERR_BOUNTY_POOL_NOT_SET };

    const rewardAmount = this.state.minReward + report.severity * 10;
    if (rewardAmount > this.state.maxReward) return { ok: false, value: ERR_INVALID_REWARD_AMOUNT };

    this.bountyTransfers.push({ amount: rewardAmount, to: this.caller });

    const updated: Report = {
      ...report,
      rewardClaimed: true,
    };
    this.state.reports.set(id, updated);
    return { ok: true, value: true };
  }

  getReportCount(): Result<number> {
    return { ok: true, value: this.state.nextReportId };
  }

  checkReportExistence(hash: Uint8Array): Result<boolean> {
    return { ok: true, value: this.state.reportsByHash.has(hash.toString()) };
  }
}

describe("ReportSubmission", () => {
  let contract: ReportSubmissionMock;

  beforeEach(() => {
    contract = new ReportSubmissionMock();
    contract.reset();
  });

  it("submits a report successfully", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    const result = contract.submitReport(proof, hash, "Bribery incident", "bribery", 5, evidenceHash);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);

    const report = contract.getReport(0);
    expect(report?.summary).toBe("Bribery incident");
    expect(report?.category).toBe("bribery");
    expect(report?.severity).toBe(5);
    expect(contract.stxTransfers).toEqual([{ amount: 100, from: "ST1SUBMITTER", to: "ST3BOUNTY" }]);
  });

  it("rejects duplicate report hashes", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    contract.submitReport(proof, hash, "Bribery incident", "bribery", 5, evidenceHash);
    const result = contract.submitReport(proof, hash, "Another incident", "corruption", 6, evidenceHash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_REPORT_ALREADY_EXISTS);
  });

  it("rejects submission without verifier contract", () => {
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    const result = contract.submitReport(proof, hash, "Bribery incident", "bribery", 5, evidenceHash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_VERIFIER_NOT_SET);
  });

  it("rejects invalid proof", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(0);
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    const result = contract.submitReport(proof, hash, "Bribery incident", "bribery", 5, evidenceHash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_PROOF);
  });

  it("rejects invalid hash", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(31).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    const result = contract.submitReport(proof, hash, "Bribery incident", "bribery", 5, evidenceHash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_HASH);
  });

  it("rejects invalid category", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    const result = contract.submitReport(proof, hash, "Bribery incident", "invalid", 5, evidenceHash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_CATEGORY);
  });

  it("rejects sybil attack", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hashBase = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    for (let i = 0; i < 5; i++) {
      const hash = new Uint8Array(hashBase);
      hash[0] = i;
      contract.submitReport(proof, hash, `Incident ${i}`, "bribery", 5, evidenceHash);
    }
    const hash = new Uint8Array(hashBase);
    hash[0] = 5;
    const result = contract.submitReport(proof, hash, "Incident 5", "bribery", 5, evidenceHash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_SYBIL_ATTACK_DETECTED);
  });

  it("updates report summary successfully", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    contract.submitReport(proof, hash, "Old summary", "bribery", 5, evidenceHash);
    const result = contract.updateReportSummary(0, "New summary");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const report = contract.getReport(0);
    expect(report?.summary).toBe("New summary");
  });

  it("rejects update for non-existent report", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const result = contract.updateReportSummary(99, "New summary");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects update by non-submitter", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    contract.submitReport(proof, hash, "Summary", "bribery", 5, evidenceHash);
    contract.caller = "ST4FAKE";
    const result = contract.updateReportSummary(0, "New summary");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("rejects update for expired report", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    contract.submitReport(proof, hash, "Summary", "bribery", 5, evidenceHash);
    contract.blockHeight += 145;
    const result = contract.updateReportSummary(0, "New summary");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_EXPIRED_REPORT);
  });

  it("claims reward successfully", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    contract.submitReport(proof, hash, "Summary", "bribery", 5, evidenceHash);
    const result = contract.claimReward(0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const report = contract.getReport(0);
    expect(report?.rewardClaimed).toBe(true);
    expect(contract.bountyTransfers).toEqual([{ amount: 100, to: "ST1SUBMITTER" }]);
  });

  it("rejects claim for non-existent report", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const result = contract.claimReward(99);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects claim by non-submitter", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    contract.submitReport(proof, hash, "Summary", "bribery", 5, evidenceHash);
    contract.caller = "ST4FAKE";
    const result = contract.claimReward(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("rejects claim for expired report", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    contract.submitReport(proof, hash, "Summary", "bribery", 5, evidenceHash);
    contract.blockHeight += 145;
    const result = contract.claimReward(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_EXPIRED_REPORT);
  });

  it("rejects claim if already claimed", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    contract.submitReport(proof, hash, "Summary", "bribery", 5, evidenceHash);
    contract.claimReward(0);
    const result = contract.claimReward(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("returns correct report count", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash1 = new Uint8Array(32).fill(2);
    const hash2 = new Uint8Array(32).fill(3);
    const evidenceHash = new Uint8Array(32).fill(4);
    contract.submitReport(proof, hash1, "Summary1", "bribery", 5, evidenceHash);
    contract.submitReport(proof, hash2, "Summary2", "corruption", 6, evidenceHash);
    const result = contract.getReportCount();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });

  it("checks report existence correctly", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash = new Uint8Array(32).fill(2);
    const evidenceHash = new Uint8Array(32).fill(3);
    contract.submitReport(proof, hash, "Summary", "bribery", 5, evidenceHash);
    const result = contract.checkReportExistence(hash);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const fakeHash = new Uint8Array(32).fill(4);
    const result2 = contract.checkReportExistence(fakeHash);
    expect(result2.ok).toBe(true);
    expect(result2.value).toBe(false);
  });

  it("parses report parameters with Clarity types", () => {
    const summary = stringUtf8CV("Test Summary");
    const severity = uintCV(5);
    expect(summary.value).toBe("Test Summary");
    expect(severity.value).toEqual(BigInt(5));
  });

  it("rejects submission with max reports exceeded", () => {
    contract.setVerifierContract("ST2VERIFIER");
    contract.setBountyPoolContract("ST3BOUNTY");
    contract.state.maxReports = 1;
    const proof = new Uint8Array(256).fill(1);
    contract.verifiedProofs.add(proof.toString());
    const hash1 = new Uint8Array(32).fill(2);
    const hash2 = new Uint8Array(32).fill(3);
    const evidenceHash = new Uint8Array(32).fill(4);
    contract.submitReport(proof, hash1, "Summary1", "bribery", 5, evidenceHash);
    const result = contract.submitReport(proof, hash2, "Summary2", "corruption", 6, evidenceHash);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_REPORTS_EXCEEDED);
  });

  it("sets verifier contract successfully", () => {
    const result = contract.setVerifierContract("ST2VERIFIER");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.verifierContract).toBe("ST2VERIFIER");
  });

  it("sets bounty pool contract successfully", () => {
    const result = contract.setBountyPoolContract("ST3BOUNTY");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.bountyPoolContract).toBe("ST3BOUNTY");
  });
});