import {
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import worker from "../src";

describe("Seeds of Success worker", () => {
	it("responds with the API status JSON (unit style)", async () => {
		const request = new Request("http://example.com");
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, {}, ctx);
		await waitOnExecutionContext(ctx);
		expect(await response.json()).toEqual({
			success: true,
			message: "Seeds of Success API",
		});
	});

	it("responds with the API status JSON (integration style)", async () => {
		const response = await SELF.fetch("http://example.com");
		expect(await response.json()).toEqual({
			success: true,
			message: "Seeds of Success API",
		});
	});

	it("saves volunteer applications with a password hash", async () => {
		let boundValues = [];
		let findExisting = null;
		const request = new Request("http://example.com/api/application", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				full_name: "Test Volunteer",
				email: "volunteer@example.com",
				phone: "555-0100",
				role: "Technology Implementer",
				skills: "Web",
				message: "I can help.",
				password: "password123",
			}),
		});
		const mockEnv = {
			sos_db: {
				prepare() {
					return {
						bind(...values) {
							boundValues = values;
							return {
								run: async () => ({ success: true }),
								first: async () => findExisting,
							};
						},
					};
				},
			},
		};

		const response = await worker.fetch(request, mockEnv);
		expect(await response.json()).toEqual({
			success: true,
			message: "Application submitted successfully",
		});
		expect(boundValues[7]).toMatch(/^[a-f0-9]{64}$/);
		expect(boundValues[7]).not.toBe("password123");
	});

	it("rejects volunteer applications with an invalid email", async () => {
		const request = new Request("http://example.com/api/application", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				full_name: "Test Volunteer",
				email: "not-an-email",
				phone: "555-0100",
				role: "Technology Implementer",
				skills: "Web",
				message: "I can help.",
				password: "password123",
			}),
		});
		const mockEnv = { sos_db: { prepare() { throw new Error("should not be called"); } } };

		const response = await worker.fetch(request, mockEnv);
		const body = await response.json();
		expect(response.status).toBe(400);
		expect(body.success).toBe(false);
		expect(body.error).toBe("Please enter a valid email address.");
	});

	it("still registers the volunteer when the notification email fails", async () => {
		vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(
			new Error("Resend API down")
		);

		let bindValues = [];
		const request = new Request("http://example.com/api/application", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				full_name: "Test Volunteer",
				email: "volunteer@example.com",
				phone: "555-0100",
				role: "Technology Implementer",
				skills: "Web",
				message: "I can help.",
				password: "password123",
			}),
		});
		const mockEnv = {
			sos_db: {
				prepare() {
					return {
						bind(...values) {
							bindValues = values;
							return {
								run: async () => ({ success: true }),
								first: async () => null,
							};
						},
					};
				},
			},
			VOLUNTEER_NOTIFICATION_EMAIL: "team@seedsofsuccessngo.org",
			EMAIL_FROM_ADDRESS: "onboarding@resend.dev",
		};

		const response = await worker.fetch(request, mockEnv);
		expect(await response.json()).toEqual({
			success: true,
			message: "Application submitted successfully",
		});
		expect(bindValues[7]).toMatch(/^[a-f0-9]{64}$/);
		vi.mocked(globalThis.fetch).mockRestore();
	});
});