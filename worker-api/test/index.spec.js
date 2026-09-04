import {
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect, vi, beforeAll } from "vitest";
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
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.message).toBe("Donation submission recorded successfully.");
			expect(typeof body.donation_id).toBe("string");
			expect(body.donation_id).toMatch(/^[a-f0-9-]{36}$/);
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
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.message).toBe("Donation submission recorded successfully.");
			expect(typeof body.donation_id).toBe("string");
			expect(body.donation_id).toMatch(/^[a-f0-9-]{36}$/);
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

	describe("admin authentication", () => {
		// Builds a mock D1 binding driven by a configurable query router.
		// `db.handlers` is an array of [sqlMatch, responder] sets.
		// The responder receives the bound values and returns the query result.
		function mockDb({ handlers = [], onInsert = null, onDelete = null, defaultFirst = null } = {}) {
			const resolveFirst = (values) => {
				const handler = handlers.find(([match]) => match.test(sqlRef));
				return handler ? handler[1](values) : defaultFirst;
			};

			let sqlRef = "";
			const makeStatement = () => {
				const chain = {
					bind(...values) {
						return makeResults(values);
					},
					first() {
						return Promise.resolve(resolveFirst(undefined));
					},
					all() {
						const result = resolveFirst(undefined);
						return Promise.resolve({
							results: Array.isArray(result) ? result : (result ? [result] : []),
							success: true,
						});
					},
					run() {
						if (onInsert && /INSERT INTO admin_sessions/.test(sqlRef)) return Promise.resolve(onInsert(undefined));
						if (onDelete && /DELETE FROM admin_sessions/.test(sqlRef)) return Promise.resolve(onDelete(undefined));
						if (onInsert && /INSERT/.test(sqlRef)) return Promise.resolve(onInsert(undefined));
						return Promise.resolve({ success: true });
					},
				};
				const makeResults = (values) => ({
					first: () => Promise.resolve(resolveFirst(values)),
					all: () => {
						const result = resolveFirst(values);
						return Promise.resolve({
							results: Array.isArray(result) ? result : (result ? [result] : []),
							success: true,
						});
					},
					run: () => {
						if (onInsert && /INSERT INTO admin_sessions/.test(sqlRef)) return Promise.resolve(onInsert(values));
						if (onDelete && /DELETE FROM admin_sessions/.test(sqlRef)) return Promise.resolve(onDelete(values));
						if (onInsert && /INSERT/.test(sqlRef)) return Promise.resolve(onInsert(values));
						return Promise.resolve({ success: true });
					},
				});
				return chain;
			};

			return {
				sos_db: {
					prepare(sql) {
						sqlRef = sql;
						return makeStatement();
					},
				},
			};
		}

		const adminAccount = {
			id: "admin-1",
			full_name: "Admin User",
			email: "admin@example.com",
			role: "admin",
			status: "active",
			password_hash: null, // replaced per-test
		};

		async function hashPw(password) {
			const salt = new Uint8Array(16);
			crypto.getRandomValues(salt);
			const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
			const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, keyMaterial, 256);
			const toB64 = (buf) => {
				const u = new Uint8Array(buf);
				let s = "";
				for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
				return btoa(s);
			};
			return "pbkdf2$SHA256$100000$" + toB64(salt) + "$" + toB64(bits);
		}

		let hashed;
		beforeAll(async () => {
			hashed = await hashPw("secret-pass");
		});

		const validLoginDb = (account = { ...adminAccount, password_hash: hashed }) =>
			mockDb({
				handlers: [
					[/FROM user_accounts\s+WHERE email = \?/, () => account],
				],
			});

		it("logs in an admin with valid credentials and returns a token", async () => {
			let inserted = null;
			const db = mockDb({
				handlers: [[/FROM user_accounts\s+WHERE email = \?/, () => ({ ...adminAccount, password_hash: hashed })]],
				onInsert: (values) => {
					inserted = values;
					return { success: true };
				},
			});

			const response = await worker.fetch(
				new Request("http://example.com/api/admin/login", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email: "admin@example.com", password: "secret-pass" }),
				}),
				db
			);

			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(typeof body.token).toBe("string");
			expect(body.token.length).toBeGreaterThan(0);
			expect(body.admin).toEqual({ id: "admin-1", full_name: "Admin User", email: "admin@example.com" });
			expect(body.admin.password_hash).toBeUndefined();
			expect(inserted[0]).toBeTruthy(); // session id
			expect(inserted[1]).toBe("admin-1"); // user_id
			expect(inserted[2]).toBe(body.token); // token
		});

		it("rejects login with an invalid password", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/login", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email: "admin@example.com", password: "wrong-password" }),
				}),
				validLoginDb()
			);

			expect(response.status).toBe(401);
			expect(await response.json()).toEqual({ success: false, error: "Invalid email or password." });
		});

		it("rejects login when the account is not an admin", async () => {
			const db = mockDb({
				handlers: [[/FROM user_accounts\s+WHERE email = \?/, () => ({ ...adminAccount, role: "tutor" })]],
			});
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/login", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email: "tutor@example.com", password: "secret-pass" }),
				}),
				db
			);

			expect(response.status).toBe(401);
			expect(await response.json()).toEqual({ success: false, error: "Invalid email or password." });
		});

		it("rejects login when the account does not exist", async () => {
			const db = mockDb({
				handlers: [[/FROM user_accounts\s+WHERE email = \?/, () => null]],
			});
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/login", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ email: "nobody@example.com", password: "secret-pass" }),
				}),
				db
			);

			expect(response.status).toBe(401);
			expect(await response.json()).toEqual({ success: false, error: "Invalid email or password." });
		});

		const validSession = {
			session_id: "session-1",
			user_id: "admin-1",
			expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
			role: "admin",
			status: "active",
			email: "admin@example.com",
			full_name: "Admin User",
		};

		const authedDb = (session = validSession) =>
			mockDb({
				handlers: [
					[/FROM admin_sessions s/, () => session],
				],
			});

		it("rejects admin endpoint access without an Authorization header (401)", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/stats"),
				authedDb()
			);
			expect(response.status).toBe(401);
		});

		it("rejects admin endpoint access with an invalid token (401)", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/stats", {
					headers: { "Authorization": "Bearer not-a-real-token" },
				}),
				mockDb({ handlers: [[/FROM admin_sessions s/, () => null]] })
			);
			expect(response.status).toBe(401);
		});

		it("rejects admin endpoint access with an expired token (401)", async () => {
			const expired = {
				...validSession,
				expires_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
			};
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/stats", {
					headers: { "Authorization": "Bearer expired-token" },
				}),
				authedDb(expired)
			);
			expect(response.status).toBe(401);
		});

		it("returns 403 for a valid token on a non-admin, non-active account", async () => {
			const session = {
				...validSession,
				role: "tutor",
			};
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/stats", {
					headers: { "Authorization": "Bearer valid-token" },
				}),
				authedDb(session)
			);
			expect(response.status).toBe(403);
		});

		it("allows an authenticated admin to access an admin endpoint", async () => {
			// /api/admin/stats runs 5 COUNT queries; return a count result for each.
			const db = mockDb({
				handlers: [
					[/FROM admin_sessions s/, () => validSession],
				],
				defaultFirst: () => ({ count: 0 }),
			});

			const response = await worker.fetch(
				new Request("http://example.com/api/admin/stats", {
					headers: { "Authorization": "Bearer valid-token" },
				}),
				db
			);

			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
		});

		it("rejects admin endpoint access without a token (volunteer-applications)", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/volunteer-applications"),
				authedDb()
			);
			expect(response.status).toBe(401);
		});

		it("rejects admin status-change without authentication (401)", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/volunteer-applications/abc/status", {
					method: "PATCH",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ status: "approved" }),
				}),
				authedDb()
			);
			expect(response.status).toBe(401);
		});

		it("logs out an authenticated admin and revokes the session", async () => {
			let deleted = false;
			const db = mockDb({
				handlers: [[/FROM admin_sessions s/, () => validSession]],
				onDelete: (values) => {
					deleted = true;
					expect(values[0]).toBe("abc-token");
					expect(values[1]).toBe("admin-1");
					return { success: true };
				},
			});

			const response = await worker.fetch(
				new Request("http://example.com/api/admin/logout", {
					method: "POST",
					headers: { "Authorization": "Bearer abc-token" },
				}),
				db
			);

			expect(response.status).toBe(200);
			expect(deleted).toBe(true);
			expect(await response.json()).toEqual({ success: true, message: "Logged out successfully." });
		});

		it("keeps the public applications-count endpoint unauthenticated", async () => {
			const db = mockDb({
				handlers: [[/SELECT COUNT\(\*\) as count/, () => ({ count: 3 })]],
			});
			const response = await worker.fetch(
				new Request("http://example.com/api/applications-count"),
				db
			);
			expect(response.status).toBe(200);
			expect((await response.json()).applications).toBe(3);
		});
	});

	describe("admin dashboard endpoints", () => {
		function mockDb({ handlers = [], onRun = null, defaultFirst = null } = {}) {
			let sqlRef = "";
			const resolveFirst = (values) => {
				const handler = handlers.find(([match]) => match.test(sqlRef));
				return handler ? handler[1](values) : defaultFirst;
			};

			const makeStatement = () => {
				const chain = {
					bind(...values) {
						return makeResults(values);
					},
					first() {
						return Promise.resolve(resolveFirst(undefined));
					},
					all() {
						const result = resolveFirst(undefined);
						return Promise.resolve({
							results: Array.isArray(result) ? result : (result ? [result] : []),
							success: true,
						});
					},
					run() {
						if (onRun && /INSERT/.test(sqlRef)) return Promise.resolve(onRun(undefined));
						if (onRun && /UPDATE/.test(sqlRef)) return Promise.resolve(onRun(undefined));
						return Promise.resolve({ success: true });
					},
				};
				const makeResults = (values) => ({
					first: () => Promise.resolve(resolveFirst(values)),
					all: () => {
						const result = resolveFirst(values);
						return Promise.resolve({
							results: Array.isArray(result) ? result : (result ? [result] : []),
							success: true,
						});
					},
					run: () => {
						if (onRun && /INSERT/.test(sqlRef)) return Promise.resolve(onRun(values));
						if (onRun && /UPDATE/.test(sqlRef)) return Promise.resolve(onRun(values));
						return Promise.resolve({ success: true });
					},
				});
				return chain;
			};

			return {
				sos_db: {
					prepare(sql) {
						sqlRef = sql;
						return makeStatement();
					},
				},
			};
		}

		const validSession = {
			session_id: "session-1",
			user_id: "admin-1",
			expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
			role: "admin",
			status: "active",
			email: "admin@example.com",
			full_name: "Admin User",
		};

		const authedDb = (extraHandlers = [], opts = {}) =>
			mockDb({
				handlers: [
					[/FROM admin_sessions s/, () => validSession],
					...extraHandlers,
				],
				defaultFirst: opts.defaultFirst || (() => ({ count: 0 })),
				onRun: opts.onRun,
			});

		const unauthedDb = () =>
			mockDb({
				handlers: [[/FROM admin_sessions s/, () => null]],
			});

		const nonAdminDb = () =>
			mockDb({
				handlers: [[/FROM admin_sessions s/, () => ({ ...validSession, role: "tutor" })]],
			});

		// ---- Tutor applications ----

		it("rejects GET /api/admin/tutor-applications without auth (401)", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/tutor-applications"),
				unauthedDb()
			);
			expect(response.status).toBe(401);
		});

		it("returns 403 for GET /api/admin/tutor-applications with non-admin token", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/tutor-applications", {
					headers: { "Authorization": "Bearer valid-token" },
				}),
				nonAdminDb()
			);
			expect(response.status).toBe(403);
		});

		it("returns tutor applications for authenticated admin", async () => {
			const apps = [
				{ id: "ta-1", full_name: "Alice", email: "alice@test.com", phone: "555-0001", skills: "Math", availability: "Weekends", status: "pending", created_at: "2026-01-01T00:00:00Z" },
			];
			const db = authedDb([
				[/FROM tutor_applications/, () => apps],
			]);
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/tutor-applications", {
					headers: { "Authorization": "Bearer valid-token" },
				}),
				db
			);
			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.applications).toEqual(apps);
		});

		it("PATCH /api/admin/tutor-applications/:id/status rejects without auth (401)", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/tutor-applications/ta-1/status", {
					method: "PATCH",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ status: "approved" }),
				}),
				unauthedDb()
			);
			expect(response.status).toBe(401);
		});

		it("approves a tutor application and sends email", async () => {
			let runCount = 0;
			const sentEmails = [];
			vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
				sentEmails.push(JSON.parse(init.body));
				return new Response(JSON.stringify({ id: "email-1" }), { status: 200 });
			});

			const app = { id: "ta-1", full_name: "Bob", email: "bob@test.com", phone: "555-0002", skills: "Science", availability: "Weekdays", password_hash: null, status: "approved" };
			const db = authedDb([
				[/FROM tutor_applications[\s\S]*WHERE id = \?/, () => app],
			], {
				onRun: () => { runCount++; return { success: true }; },
			});

			const response = await worker.fetch(
				new Request("http://example.com/api/admin/tutor-applications/ta-1/status", {
					method: "PATCH",
					headers: {
						"Content-Type": "application/json",
						"Authorization": "Bearer valid-token",
					},
					body: JSON.stringify({ status: "approved" }),
				}),
				db
			);

			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.application.status).toBe("approved");

			vi.mocked(globalThis.fetch).mockRestore();
		});

		// ---- Volunteer applications ----

		it("rejects GET /api/admin/volunteer-applications without auth (401)", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/volunteer-applications"),
				unauthedDb()
			);
			expect(response.status).toBe(401);
		});

		it("returns volunteer applications for authenticated admin", async () => {
			const apps = [
				{ id: "va-1", full_name: "Carol", email: "carol@test.com", phone: "555-0003", role: "Volunteer", skills: "Art", status: "pending", created_at: "2026-01-01T00:00:00Z" },
			];
			const db = authedDb([
				[/FROM volunteer_applications/, () => apps],
			]);
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/volunteer-applications", {
					headers: { "Authorization": "Bearer valid-token" },
				}),
				db
			);
			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.applications).toEqual(apps);
		});

		// ---- Donations ----

		it("rejects GET /api/admin/donations without auth (401)", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/donations"),
				unauthedDb()
			);
			expect(response.status).toBe(401);
		});

		it("returns donations for authenticated admin", async () => {
			const donations = [
				{ id: "d-1", full_name: "Jane Donor", email: "jane@test.com", amount_cents: 5000, status: "pending", created_at: "2026-01-01T00:00:00Z" },
			];
			const db = authedDb([
				[/FROM donations/, () => donations],
			]);
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/donations", {
					headers: { "Authorization": "Bearer valid-token" },
				}),
				db
			);
			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.donations).toEqual(donations);
		});

		it("PATCH /api/admin/donations/:id/status rejects unauthenticated (401)", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/donations/d-1/status", {
					method: "PATCH",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ status: "verified" }),
				}),
				unauthedDb()
			);
			expect(response.status).toBe(401);
		});

		it("verifies a donation", async () => {
			const donation = { id: "d-1", full_name: "Jane", email: "jane@test.com", amount_cents: 5000, status: "pending" };
			const db = authedDb([
				[/FROM donations[\s\S]*WHERE id = \?/, () => donation],
			]);
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/donations/d-1/status", {
					method: "PATCH",
					headers: {
						"Content-Type": "application/json",
						"Authorization": "Bearer valid-token",
					},
					body: JSON.stringify({ status: "verified" }),
				}),
				db
			);
			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.donation.status).toBe("verified");
		});

		it("rejects a donation", async () => {
			const donation = { id: "d-2", full_name: "Bob", email: "bob@test.com", amount_cents: 1000, status: "pending" };
			const db = authedDb([
				[/FROM donations[\s\S]*WHERE id = \?/, () => donation],
			]);
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/donations/d-2/status", {
					method: "PATCH",
					headers: {
						"Content-Type": "application/json",
						"Authorization": "Bearer valid-token",
					},
					body: JSON.stringify({ status: "rejected" }),
				}),
				db
			);
			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.donation.status).toBe("rejected");
		});

		it("rejects an invalid donation status", async () => {
			const donation = { id: "d-1", full_name: "Jane", email: "jane@test.com", amount_cents: 5000, status: "pending" };
			const db = authedDb([
				[/FROM donations[\s\S]*WHERE id = \?/, () => donation],
			]);
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/donations/d-1/status", {
					method: "PATCH",
					headers: {
						"Content-Type": "application/json",
						"Authorization": "Bearer valid-token",
					},
					body: JSON.stringify({ status: "approved" }),
				}),
				db
			);
			expect(response.status).toBe(400);
			const body = await response.json();
			expect(body.success).toBe(false);
		});

		it("returns 409 when donation is already in the requested status", async () => {
			const donation = { id: "d-1", full_name: "Jane", email: "jane@test.com", amount_cents: 5000, status: "verified" };
			const db = authedDb([
				[/FROM donations[\s\S]*WHERE id = \?/, () => donation],
			]);
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/donations/d-1/status", {
					method: "PATCH",
					headers: {
						"Content-Type": "application/json",
						"Authorization": "Bearer valid-token",
					},
					body: JSON.stringify({ status: "verified" }),
				}),
				db
			);
			expect(response.status).toBe(409);
		});

		it("does not auto-verify donation when a transaction reference is submitted", async () => {
			const donation = { id: "d-1", full_name: "Jane", email: "jane@test.com", amount_cents: 5000, status: "pending", transaction_reference: null };
			const db = mockDb({
				handlers: [
					[/FROM donations[\s\S]*WHERE id = \?/, () => donation],
					[/FROM donations[\s\S]*WHERE transaction_reference = \?/, () => null],
				],
			});
			const response = await worker.fetch(
				new Request("http://example.com/api/donations/d-1/payment-reference", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ transaction_reference: "TXN-12345" }),
				}),
				db
			);
			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.message).toContain("Payment details submitted");
			expect(body.status).toBeUndefined();
		});

		it("reports email warning when email fails after successful DB update", async () => {
			vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Resend API down"));

			const donation = { id: "d-1", full_name: "Jane", email: "jane@test.com", amount_cents: 5000, status: "pending" };
			const db = authedDb([
				[/FROM donations[\s\S]*WHERE id = \?/, () => donation],
			]);

			const response = await worker.fetch(
				new Request("http://example.com/api/admin/donations/d-1/status", {
					method: "PATCH",
					headers: {
						"Content-Type": "application/json",
						"Authorization": "Bearer valid-token",
					},
					body: JSON.stringify({ status: "verified" }),
				}),
				db
			);

			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.email_warning).toBeDefined();
			expect(body.email_warning).toContain("email notification failed");

			vi.mocked(globalThis.fetch).mockRestore();
		});

		// ---- Contacts ----

		it("rejects GET /api/admin/contacts without auth (401)", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/contacts"),
				unauthedDb()
			);
			expect(response.status).toBe(401);
		});

		it("returns contacts for authenticated admin", async () => {
			const contacts = [
				{ id: "c-1", full_name: "Jane", email: "jane@test.com", subject: "Hello", message: "Test message", created_at: "2026-01-01T00:00:00Z" },
			];
			const db = authedDb([
				[/FROM contacts/, () => contacts],
			]);
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/contacts", {
					headers: { "Authorization": "Bearer valid-token" },
				}),
				db
			);
			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.contacts).toEqual(contacts);
		});

		// ---- Dashboard summary ----

		it("rejects GET /api/admin/dashboard-summary without auth (401)", async () => {
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/dashboard-summary"),
				unauthedDb()
			);
			expect(response.status).toBe(401);
		});

		it("returns dashboard summary counts for authenticated admin", async () => {
			const db = authedDb([], {
				defaultFirst: () => ({ count: 5 }),
			});
			const response = await worker.fetch(
				new Request("http://example.com/api/admin/dashboard-summary", {
					headers: { "Authorization": "Bearer valid-token" },
				}),
				db
			);
			expect(response.status).toBe(200);
			const body = await response.json();
			expect(body.success).toBe(true);
			expect(body.summary).toBeDefined();
			expect(typeof body.summary.pending_tutors).toBe("number");
			expect(typeof body.summary.pending_volunteers).toBe("number");
			expect(typeof body.summary.pending_donations).toBe("number");
			expect(typeof body.summary.verified_donations).toBe("number");
			expect(typeof body.summary.total_contacts).toBe("number");
		});
	});

	describe("contact persistence", () => {
		it("persists contact submission to database and sends emails", async () => {
			let insertValues = [];
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
				sos_db: {
					prepare(sql) {
						return {
							bind(...values) {
								if (/INSERT INTO contacts/.test(sql)) insertValues = values;
								return {
									run: async () => ({ success: true }),
									first: async () => null,
								};
							},
						};
					},
				},
				CONTACT_RECIPIENT_EMAIL: "team@seedsofsuccessngo.org",
				RESEND_API_KEY: "test-key",
				EMAIL_FROM_ADDRESS: "onboarding@resend.dev",
			};

			const response = await worker.fetch(request, mockEnv);
			expect(await response.json()).toEqual({
				success: true,
				message: "Thank you for your message! We'll get back to you soon.",
			});
			expect(insertValues.length).toBe(6);
			expect(insertValues[1]).toBe("Jane Doe");
			expect(insertValues[2]).toBe("jane@example.com");
			expect(insertValues[3]).toBe("Volunteering question");
			expect(insertValues[4]).toBe("I would like to learn more about volunteering opportunities.");
			expect(sentEmails).toHaveLength(2);
			expect(sentEmails[0].subject).toBe("[Contact Form] Volunteering question");
			expect(sentEmails[1].subject).toBe("Thank You for Contacting Seeds of Success");
			vi.mocked(globalThis.fetch).mockRestore();
		});
	});
});
