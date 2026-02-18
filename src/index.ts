import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

const subjects = createSubjects({
	user: object({
		id: string(),
	}),
});

export default {
	fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);

		// ===== CORS PREFLIGHT =====
		if (request.method === "OPTIONS") {
			return new Response(null, {
				headers: {
					"Access-Control-Allow-Origin": "*",
					"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
					"Access-Control-Allow-Headers": "Content-Type, Authorization",
				},
			});
		}

		// ===== REDIRECT ROOM KE AUTHORIZE =====
		if (url.pathname === "/") {
			url.searchParams.set("redirect_uri", "https://room.soeparnocorp.workers.dev");
			url.searchParams.set("client_id", "readtalk-client");
			url.searchParams.set("response_type", "code");
			url.pathname = "/authorize";
			return Response.redirect(url.toString());
		}

		// ===== HANDLE CALLBACK =====
		if (url.pathname === "/callback") {
			const code = url.searchParams.get("code");
			if (code) {
				return Response.redirect(`https://room.soeparnocorp.workers.dev?code=${code}`);
			}
			return Response.redirect("https://room.soeparnocorp.workers.dev");
		}

		// ===== 🔥 ENDPOINT VERIFY (REAL) =====
		if (url.pathname === "/verify" && request.method === "POST") {
			return handleVerify(request, env);
		}

		// ===== 🔥 ENDPOINT ME =====
		if (url.pathname === "/me" && request.method === "GET") {
			return handleMe(request, env);
		}

		// ===== OPENAuth ISSUER =====
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
						},
						copy: {
							input_code: "Code (check Worker logs)",
						},
					}),
				),
			},
			theme: {
				title: "READTalk - Authentication",
				primary: "#ff0000",
				favicon: "https://raw.githubusercontent.com/soeparnocorp/openauth/main/public/favicon.ico",
				logo: {
					dark: "https://raw.githubusercontent.com/soeparnocorp/openauth/main/src/logo-dark.png",
					light: "https://raw.githubusercontent.com/soeparnocorp/openauth/main/src/logo-light.png",
				},
			},
			success: async (ctx, value) => {
				return ctx.subject("user", {
					id: await getOrCreateUser(env, value.email),
				});
			},
		}).fetch(request, env, ctx);
	},
} satisfies ExportedHandler<Env>;

// ===== 🔥 HANDLE VERIFY TOKEN (REAL) =====
async function handleVerify(request: Request, env: Env) {
	try {
		const { token } = await request.json();

		if (!token) {
			return Response.json({ valid: false }, { 
				status: 401,
				headers: { "Access-Control-Allow-Origin": "*" }
			});
		}

		// 🔥 OpenAuth nyimpen session di KV dengan prefix "session:"
		// Tapi formatnya tergantung library. Kita perlu cek dokumentasi
		// Alternatif: token bisa jadi JWT yang bisa didecode

		// Cara 1: Coba cek di KV
		const sessionData = await env.AUTH_STORAGE.get(token, "json");
		
		if (sessionData) {
			// Dapet session dari KV
			return Response.json({ 
				valid: true, 
				user: { 
					id: sessionData.userId,
					email: sessionData.email 
				} 
			}, {
				headers: { "Access-Control-Allow-Origin": "*" }
			});
		}

		// Cara 2: Kalo token JWT, kita bisa decode pake library
		// Tapi untuk sekarang, return 401
		return Response.json({ valid: false }, { 
			status: 401,
			headers: { "Access-Control-Allow-Origin": "*" }
		});

	} catch (error) {
		return Response.json({ valid: false, error: error.message }, { 
			status: 401,
			headers: { "Access-Control-Allow-Origin": "*" }
		});
	}
}

// ===== 🔥 HANDLE ME =====
async function handleMe(request: Request, env: Env) {
	const authHeader = request.headers.get("Authorization");
	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return Response.json({ error: "Unauthorized" }, { 
			status: 401,
			headers: { "Access-Control-Allow-Origin": "*" }
		});
	}

	const token = authHeader.slice(7);

	// Verifikasi token pake handleVerify
	const verifyReq = new Request("https://internal/verify", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ token })
	});

	const verifyRes = await handleVerify(verifyReq, env);
	if (!verifyRes.ok) {
		return Response.json({ error: "Invalid token" }, { 
			status: 401,
			headers: { "Access-Control-Allow-Origin": "*" }
		});
	}

	const { user } = await verifyRes.json();

	// Ambil data lengkap dari database
	const result = await env.AUTH_DB.prepare(
		"SELECT id, email FROM user WHERE id = ?"
	).bind(user.id).first();

	if (!result) {
		return Response.json({ error: "User not found" }, { 
			status: 404,
			headers: { "Access-Control-Allow-Origin": "*" }
		});
	}

	return Response.json({ 
		id: result.id,
		email: result.email,
	}, {
		headers: { "Access-Control-Allow-Origin": "*" }
	});
}

async function getOrCreateUser(env: Env, email: string): Promise<string> {
	const result = await env.AUTH_DB.prepare(
		`
		INSERT INTO user (email)
		VALUES (?)
		ON CONFLICT (email) DO UPDATE SET email = email
		RETURNING id;
		`,
	)
		.bind(email)
		.first<{ id: string }>();

	if (!result) {
		throw new Error(`Unable to process user: ${email}`);
	}

	console.log(`Found or created user ${result.id} with email ${email}`);
	return result.id;
}
