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

		// ===== REDIRECT ROOT KE AUTHORIZE =====
		if (url.pathname === "/") {
			url.searchParams.set("redirect_uri", "https://room.soeparnocorp.workers.dev");
			url.searchParams.set("client_id", "readtalk-client");
			url.searchParams.set("response_type", "code");
			url.pathname = "/authorize";
			return Response.redirect(url.toString());
		}

		// ===== HANDLE CALLBACK - KIRIM CODE KE ROOM =====
		if (url.pathname === "/callback") {
			const code = url.searchParams.get("code");
			if (code) {
				return Response.redirect(`https://room.soeparnocorp.workers.dev?code=${code}`);
			}
			return Response.redirect("https://room.soeparnocorp.workers.dev");
		}

		// ===== 🔥 TAMBAHAN: ENDPOINT VERIFY UNTUK READTALK =====
		if (url.pathname === "/verify" && request.method === "POST") {
			return handleVerify(request, env);
		}

		// ===== 🔥 TAMBAHAN: ENDPOINT AMBIL DATA USER =====
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
							// TODO: Kirim email beneran pake Resend atau email service
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

// ===== 🔥 HANDLE VERIFY TOKEN =====
async function handleVerify(request: Request, env: Env) {
	try {
		const { token } = await request.json();
		
		if (!token) {
			return Response.json({ valid: false, error: "No token" }, { status: 401 });
		}

		// Di OpenAuth, token biasanya JWT yang bisa diverifikasi
		// Tapi karena pake library @openauthjs, kita perlu decode
		
		// Cara sederhana: cek di storage atau decode manual
		// Ini contoh pake verifikasi dasar:
		
		// TODO: Implementasi verifikasi token sesuai library OpenAuth
		// Sementara return dummy dulu
		
		// Seharusnya: const user = await verifyToken(token);
		
		return Response.json({ 
			valid: true, 
			user: { 
				id: "user-123", 
				email: "user@example.com" 
			} 
		});
		
	} catch (error) {
		return Response.json({ valid: false, error: error.message }, { status: 401 });
	}
}

// ===== 🔥 HANDLE DATA USER =====
async function handleMe(request: Request, env: Env) {
	// token header Authorization
	const authHeader = request.headers.get("Authorization");
	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return Response.json({ error: "Unauthorized" }, { status: 401 });
	}
	
	const token = authHeader.slice(7);
	
	// Verifikasi token (panggil handleVerify atau verifikasi langsung)
	// Sederhananya, kita panggil endpoint verify internal
	const verifyReq = new Request("https://internal/verify", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ token })
	});
	
	const verifyRes = await handleVerify(verifyReq, env);
	if (!verifyRes.ok) {
		return Response.json({ error: "Invalid token" }, { status: 401 });
	}
	
	const { user } = await verifyRes.json();
	
	// Ambil data lengkap user dari database
	const result = await env.AUTH_DB.prepare(
		"SELECT id, email FROM user WHERE id = ?",
	).bind(user.id).first();
	
	if (!result) {
		return Response.json({ error: "User not found" }, { status: 404 });
	}
	
	return Response.json({ 
		id: result.id,
		email: result.email,
		// Bisa tambah field lain kalo ada
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
