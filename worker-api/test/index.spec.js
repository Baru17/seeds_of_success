import {
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect } from "vitest";
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
			seeds_of_success: {
				prepare() {
					return {
						bind(...values) {
							boundValues = values;
							return { run: async () => ({ success: true }) };
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
});
