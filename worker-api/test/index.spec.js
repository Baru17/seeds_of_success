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
		vi.spyOn(globalThis, "fetch")
			.mockRejectedValueOnce(new Error("Resend API down"))
			.mockResolvedValueOnce(
				new Response(JSON.stringify({ id: "email-confirmation" }), { status: 200 })
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
			RESEND_API_KEY: "test-key",
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

	it("sends a confirmation email to the contact user on success", async () => {
		const sentEmails = [];
		vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
			sentEmails.push(JSON.parse(init.body));
			return new Response(JSON.stringify({ id: "email-1" }), { status: 200 });
		});

		const request = new Request("http://example.com/api/contact", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				full_name: "Jane Doe",
				email: "jane@example.com",
				subject: "Volunteering question",
				message: "I would like to learn more about volunteering opportunities.",
			}),
		});
		const mockEnv = {
			CONTACT_RECIPIENT_EMAIL: "team@seedsofsuccessngo.org",
			RESEND_API_KEY: "test-key",
			EMAIL_FROM_ADDRESS: "onboarding@resend.dev",
		};

		const response = await worker.fetch(request, mockEnv);
		expect(await response.json()).toEqual({
			success: true,
			message: "Thank you for your message! We'll get back to you soon.",
		});
		expect(sentEmails).toHaveLength(2);
		expect(sentEmails[0].to).toEqual(["team@seedsofsuccessngo.org"]);
		expect(sentEmails[0].subject).toBe("[Contact Form] Volunteering question");
		expect(sentEmails[1].to).toEqual(["jane@example.com"]);
		expect(sentEmails[1].subject).toBe("Thank You for Contacting Seeds of Success");
		expect(sentEmails[1].html).toContain("Hi Jane Doe");
		expect(sentEmails[1].html).toContain("We have successfully received your message.");
		vi.mocked(globalThis.fetch).mockRestore();
	});

	it("still handles a contact submission when the confirmation email fails", async () => {
		let callCount = 0;
		vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
			callCount += 1;
			if (callCount > 1) {
				throw new Error("Resend API down");
			}
			return new Response(JSON.stringify({ id: "email-1" }), { status: 200 });
		});

		const request = new Request("http://example.com/api/contact", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				full_name: "Jane Doe",
				email: "jane@example.com",
				subject: "Volunteering question",
				message: "I would like to learn more about volunteering opportunities.",
			}),
		});
		const mockEnv = {
			CONTACT_RECIPIENT_EMAIL: "team@seedsofsuccessngo.org",
			RESEND_API_KEY: "test-key",
			EMAIL_FROM_ADDRESS: "onboarding@resend.dev",
		};

		const response = await worker.fetch(request, mockEnv);
		expect(await response.json()).toEqual({
			success: true,
			message: "Thank you for your message! We'll get back to you soon.",
		});
		expect(callCount).toBe(2);
		vi.mocked(globalThis.fetch).mockRestore();
	});

	it("sends a confirmation email to the volunteer on successful registration", async () => {
		const sentEmails = [];
		vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
			sentEmails.push(JSON.parse(init.body));
			return new Response(JSON.stringify({ id: "email-1" }), { status: 200 });
		});

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
						bind() {
							return {
								run: async () => ({ success: true }),
								first: async () => null,
							};
						},
					};
				},
			},
			RESEND_API_KEY: "test-key",
			VOLUNTEER_NOTIFICATION_EMAIL: "team@seedsofsuccessngo.org",
			EMAIL_FROM_ADDRESS: "onboarding@resend.dev",
		};

		const response = await worker.fetch(request, mockEnv);
		expect(await response.json()).toEqual({
			success: true,
			message: "Application submitted successfully",
		});
		expect(sentEmails).toHaveLength(2);
		expect(sentEmails[0].to).toEqual(["team@seedsofsuccessngo.org"]);
		expect(sentEmails[0].subject).toBe("New Volunteer Registration - Seeds of Success");
		expect(sentEmails[1].to).toEqual(["volunteer@example.com"]);
		expect(sentEmails[1].subject).toBe("Volunteer Registration Received \u2013 Seeds of Success");
		expect(sentEmails[1].html).toContain("Hi Test Volunteer");
		expect(sentEmails[1].html).toContain("We have successfully received your volunteer application.");
		vi.mocked(globalThis.fetch).mockRestore();
	});

	it("still registers the volunteer when the confirmation email fails", async () => {
		let callCount = 0;
		vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
			callCount += 1;
			if (callCount > 1) {
				throw new Error("Confirmation email failed");
			}
			return new Response(JSON.stringify({ id: "email-1" }), { status: 200 });
		});

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
						bind() {
							return {
								run: async () => ({ success: true }),
								first: async () => null,
							};
						},
					};
				},
			},
			RESEND_API_KEY: "test-key",
			VOLUNTEER_NOTIFICATION_EMAIL: "team@example.com",
			EMAIL_FROM_ADDRESS: "onboarding@resend.dev",
		};

		const response = await worker.fetch(request, mockEnv);
		expect(await response.json()).toEqual({
			success: true,
			message: "Application submitted successfully",
		});
		expect(callCount).toBe(2);
		vi.mocked(globalThis.fetch).mockRestore();
	});

	describe("donations", () => {
		const donationBody = (overrides = {}) => ({
			full_name: "Jane Donor",
			email: "jane@example.com",
			amount: "50.00",
			...overrides,
		});

		const mockDb = ({ onRun, findExisting = null } = {}) => ({
			sos_db: {
				prepare() {
					return {
						bind(...values) {
							return {
								run: onRun ? () => onRun(values) : async () => ({ success: true }),
								first: async () => findExisting,
							};
						},
					};
				},
			},
		});

		it("stores donation amount as integer cents on success", async () => {
			let boundValues = [];
			const response = await worker.fetch(
				new Request("http://example.com/api/donations", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(donationBody()),
				}),
				mockDb({
					onRun: (values) => {
						boundValues = values;
						return { success: true };
					},
				})
			);

			expect(response.status).toBe(201);
			expect(await response.json()).toEqual({
				success: true,
				message: "Donation submission recorded successfully.",
			});
			expect(boundValues[0]).toMatch(/^[a-f0-9-]{36}$/);
			expect(boundValues[1]).toBe("Jane Donor");
			expect(boundValues[2]).toBe("jane@example.com");
			expect(boundValues[3]).toBe(5000);
			expect(typeof boundValues[3]).toBe("number");
			expect(boundValues[4]).toMatch(/^\d{4}-\d{2}-\d{2}T/);
		});

		it("rejects a donation with a missing name", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/donations", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(donationBody({ full_name: "" })),
				}),
				mockDb({
					onRun: () => {
						throw new Error("should not be called");
					},
				})
			);

			expect(response.status).toBe(400);
			expect(await response.json()).toEqual({
				success: false,
				error: "Full name must be between 2 and 50 characters.",
			});
		});

		it("rejects a donation with an invalid email", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/donations", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(donationBody({ email: "not-an-email" })),
				}),
				mockDb({
					onRun: () => {
						throw new Error("should not be called");
					},
				})
			);

			expect(response.status).toBe(400);
			expect(await response.json()).toEqual({
				success: false,
				error: "Please enter a valid email address.",
			});
		});

		it("rejects a donation with a missing amount", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/donations", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(donationBody({ amount: undefined })),
				}),
				mockDb({
					onRun: () => {
						throw new Error("should not be called");
					},
				})
			);

			expect(response.status).toBe(400);
			expect(await response.json()).toEqual({
				success: false,
				error: "Donation amount is required.",
			});
		});

		it("rejects a zero or negative amount", async () => {
			for (const amount of ["0", "-5", "0.00"]) {
				const response = await worker.fetch(
					new Request("http://example.com/api/donations", {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify(donationBody({ amount })),
					}),
					mockDb({
						onRun: () => {
							throw new Error("should not be called");
						},
					})
				);

				expect(response.status).toBe(400);
				const body = await response.json();
				expect(body.success).toBe(false);
				expect(body.error).toMatch(/positive|greater than zero/);
			}
		});

		it("rejects an invalid amount format", async () => {
			for (const amount of ["abc", "5.123", "1,000", "Infinity", "1e3"]) {
				const response = await worker.fetch(
					new Request("http://example.com/api/donations", {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify(donationBody({ amount })),
					}),
					mockDb({
						onRun: () => {
							throw new Error("should not be called");
						},
					})
				);

				expect(response.status).toBe(400);
				const body = await response.json();
				expect(body.success).toBe(false);
				expect(body.error).toBe(
					"Donation amount must be a positive monetary value."
				);
			}
		});

		it("successfully inserts into D1 and returns 201", async () => {
			let runCalled = false;
			const response = await worker.fetch(
				new Request("http://example.com/api/donations", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(donationBody({ amount: "25.5" })),
				}),
				mockDb({
					onRun: () => {
						runCalled = true;
						return { success: true };
					},
				})
			);

			expect(runCalled).toBe(true);
			expect(response.status).toBe(201);
			expect(await response.json()).toEqual({
				success: true,
				message: "Donation submission recorded successfully.",
			});
		});

		it("returns a 500 error when the database insert fails", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/donations", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(donationBody()),
				}),
				mockDb({
					onRun: () => {
						throw new Error("D1 insert failed");
					},
				})
			);

			expect(response.status).toBe(500);
			expect(await response.json()).toEqual({
				success: false,
				error: "Something went wrong. Please try again later.",
			});
		});
	});
});