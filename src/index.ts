import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

// Subjects tetap sama
const subjects = createSubjects({
	user: object({
		id: string(),
		email: string(),
	}),
});

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);

		// ============ ENDPOINT TOKEN (untuk tukar code) ============
		if (url.pathname === "/token" && request.method === "POST") {
			try {
				const { code } = await request.json();
				
				// TODO: Validasi code dan generate token
				// Ini sementara, nanti harus validasi code dari KV
				
				// Dapatkan user dari code (simulasi)
				const userId = "dummy-user-id";
				const email = "dummy@example.com";
				
				return new Response(JSON.stringify({
					access_token: "dummy-token-" + Date.now(),
					token_type: "Bearer",
					user: { id: userId, email }
				}), {
					headers: { "Content-Type": "application/json" }
				});
			} catch (err) {
				return new Response(JSON.stringify({ error: "Invalid request" }), { 
					status: 400,
					headers: { "Content-Type": "application/json" }
				});
			}
		}

		// ============ ENDPOINT ME (untuk ambil data user) ============
		if (url.pathname === "/me") {
			const authHeader = request.headers.get("Authorization");
			if (!authHeader || !authHeader.startsWith("Bearer ")) {
				return new Response(JSON.stringify({ error: "Unauthorized" }), { 
					status: 401,
					headers: { "Content-Type": "application/json" }
				});
			}

			const token = authHeader.slice(7);
			
			// TODO: Validasi token, ambil user dari database
			// Ini sementara
			const user = {
				id: "dummy-user-id",
				email: "dummy@example.com"
			};

			return new Response(JSON.stringify(user), {
				headers: { "Content-Type": "application/json" }
			});
		}

		// ============ HANDLE ROOT PATH ============
		if (url.pathname === "/") {
			// Redirect ke room.soeparnocorp dengan redirect_uri yang benar
			url.searchParams.set("redirect_uri", "https://room.soeparnocorp.workers.dev/auth/callback");
			url.searchParams.set("client_id", "readtalk");
			url.searchParams.set("response_type", "code");
			url.pathname = "/authorize";
			return Response.redirect(url.toString());
		}

		// ============ HANDLE CALLBACK ============
		if (url.pathname === "/callback") {
			const code = url.searchParams.get("code");
			// Redirect ke room dengan code
			return Response.redirect(`https://room.soeparnocorp.workers.dev/auth/callback?code=${code}`);
		}

		// ============ OPENATH CORE ============
		return issuer({
			storage: CloudflareStorage({
				namespace: env.AUTH_STORAGE,
			}),
			subjects,
			providers: {
				password: PasswordProvider(
					PasswordUI({
						sendCode: async (email, code) => {
							console.log(`Sending code ${code} to ${email}`);
							// TODO: Implement email sending
						},
						copy: {
							input_code: "Code (check Worker logs)",
						},
					}),
				),
			},
			theme: {
				title: "READTalk - OpenAuth",
				primary: "#ff0000",
				favicon: "https://raw.githubusercontent.com/soeparnocorp/openauth/refs/heads/main/public/favicon.ico",
				logo: {
					dark: "https://raw.githubusercontent.com/soeparnocorp/openauth/refs/heads/main/src/logo-dark.png",
					light: "https://raw.githubusercontent.com/soeparnocorp/openauth/refs/heads/main/src/logo-light.png",
				},
			},
			success: async (ctx, value) => {
				// Simpan user di database
				const result = await env.AUTH_DB.prepare(
					`
					INSERT INTO user (email)
					VALUES (?)
					ON CONFLICT (email) DO UPDATE SET email = email
					RETURNING id;
					`,
				)
					.bind(value.email)
					.first<{ id: string }>();
				
				if (!result) {
					throw new Error(`Unable to process user: ${value.email}`);
				}
				
				// Generate dan simpan code di KV (untuk ditukar nanti)
				const code = crypto.randomUUID();
				await env.AUTH_STORAGE.put(`code:${code}`, result.id, { expirationTtl: 300 }); // 5 menit
				
				// Redirect ke callback dengan code
				return ctx.redirect(`https://room.soeparnocorp.workers.dev/auth/callback?code=${code}`);
			},
		}).fetch(request, env, ctx);
	},
} satisfies ExportedHandler<Env>;
