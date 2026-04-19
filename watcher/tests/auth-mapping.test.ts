import { describe, expect, it } from "vitest";
import { emailAuthFromMilter } from "../src/watcher.js";

describe("emailAuthFromMilter", () => {
	it("maps a happy-path milter auth block to the SDK shape", () => {
		const out = emailAuthFromMilter({
			spf: "pass",
			dkim: "pass",
			dkim_domains: ["example.com"],
			dmarc: "pass",
			dmarc_policy: "reject",
			dmarc_from_domain: "example.com",
		});
		expect(out.spf).toBe("pass");
		expect(out.dmarc).toBe("pass");
		expect(out.dmarcPolicy).toBe("reject");
		expect(out.dmarcFromDomain).toBe("example.com");
		expect(out.dkimSignatures).toHaveLength(1);
		expect(out.dkimSignatures[0].result).toBe("pass");
		expect(out.dkimSignatures[0].aligned).toBe(true);
		expect(out.dmarcDkimAligned).toBe(true);
	});

	it("normalizes DKIM result case — 'Pass' is accepted as 'pass'", () => {
		// Milters in the wild may emit capitalized values. Every other field
		// in this mapper lowercases before validation; DKIM must too or a
		// valid 'Pass' silently becomes 'permerror' and the signature is
		// reported as failed.
		const out = emailAuthFromMilter({
			spf: "pass",
			dkim: "Pass",
			dkim_domains: ["example.com"],
			dmarc: "pass",
			dmarc_policy: "reject",
			dmarc_from_domain: "example.com",
		});
		expect(out.dkimSignatures[0].result).toBe("pass");
	});

	it("normalizes SPF and DMARC case", () => {
		const out = emailAuthFromMilter({
			spf: "Pass",
			dmarc: "Fail",
			dmarc_policy: "Reject",
		});
		expect(out.spf).toBe("pass");
		expect(out.dmarc).toBe("fail");
		expect(out.dmarcPolicy).toBe("reject");
	});

	it("defaults unknown DKIM result to permerror", () => {
		const out = emailAuthFromMilter({
			spf: "pass",
			dkim: "weird-value",
			dkim_domains: ["example.com"],
		});
		expect(out.dkimSignatures[0].result).toBe("permerror");
	});

	it("omits dkimSignatures when the milter didn't provide domains", () => {
		const out = emailAuthFromMilter({ spf: "pass" });
		expect(out.dkimSignatures).toEqual([]);
		expect(out.dmarcDkimAligned).toBe(false);
	});

	it("marks a signature aligned iff domain matches AND DKIM verified", () => {
		const out = emailAuthFromMilter({
			spf: "pass",
			dkim: "pass",
			dkim_domains: ["example.com", "other.com"],
			dmarc_from_domain: "example.com",
		});
		expect(out.dkimSignatures[0].aligned).toBe(true);
		expect(out.dkimSignatures[1].aligned).toBe(false);
		expect(out.dmarcDkimAligned).toBe(true);
	});

	it("never reports alignment when DKIM verification failed, even for a matching domain", () => {
		// DMARC DKIM alignment requires BOTH domain match AND successful
		// verification. A receiver gating security decisions on
		// `dmarcDkimAligned` must not see `true` when DKIM actually failed.
		const out = emailAuthFromMilter({
			spf: "pass",
			dkim: "fail",
			dkim_domains: ["example.com"],
			dmarc_from_domain: "example.com",
		});
		expect(out.dkimSignatures[0].result).toBe("fail");
		expect(out.dkimSignatures[0].aligned).toBe(false);
		expect(out.dmarcDkimAligned).toBe(false);
	});

	it("never reports alignment when DKIM is temperror/permerror", () => {
		for (const result of ["temperror", "permerror"] as const) {
			const out = emailAuthFromMilter({
				spf: "pass",
				dkim: result,
				dkim_domains: ["example.com"],
				dmarc_from_domain: "example.com",
			});
			expect(out.dkimSignatures[0].aligned).toBe(false);
			expect(out.dmarcDkimAligned).toBe(false);
		}
	});

	it("coerces unknown SPF / DMARC values to 'none'", () => {
		const out = emailAuthFromMilter({
			spf: "weird",
			dmarc: "weird",
			dmarc_policy: "weird",
		});
		expect(out.spf).toBe("none");
		expect(out.dmarc).toBe("none");
		expect(out.dmarcPolicy).toBeNull();
	});
});
