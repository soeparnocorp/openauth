import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

// Shared subject type
const subjects = createSubjects({
	user: object({
		id: string(),
	}),
});

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);

		// Jika dipanggil langsung oleh Pages function
		if (url.pathname === "/api/token" && request.method === "POST") {
			// Contoh: Pages function panggil OpenAuth via fetch POST
			const body = await request.json().catch(() => ({}));
			const email = body.email || body.user?.email || "demo@readtalk.dev";

			// Gunakan OpenAuth issuer untuk generate code / subject
			const authResponse = await issuer({
				storage: CloudflareStorage({ namespace: env.AUTH_STORAGE }),
				subjects,
				providers: {
					password: PasswordProvider(
						PasswordUI({
							sendCode: async (email, code) => {
								console.log(`Sending code ${code} to ${email}`);
							},
							copy: { input_code: "Code (check Worker logs)" },
						}),
					),
				},
			}).success(ctx, { email });

			return new Response(JSON.stringify(authResponse), { status: 200 });
		}

		// Optional: demo UI / test flow
		if (url.pathname === "/") {
			return Response.redirect(url.origin + "/authorize");
		} else if (url.pathname === "/callback") {
			return Response.json({
				message: "OpenAuth flow complete!",
				params: Object.fromEntries(url.searchParams.entries()),
			});
		}

		// Fallback: panggil normal issuer handler
		return issuer({
			storage: CloudflareStorage({ namespace: env.AUTH_STORAGE }),
			subjects,
			providers: {
				password: PasswordProvider(
					PasswordUI({
						sendCode: async (email, code) => {
							console.log(`Sending code ${code} to ${email}`);
						},
						copy: { input_code: "Code (check Worker logs)" },
					}),
				),
			},
		}).fetch(request, env, ctx);
	},
} satisfies ExportedHandler<Env>;

// Fungsi helper tetap sama
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
	if (!result) throw new Error(`Unable to process user: ${email}`);
	console.log(`Found or created user ${result.id} with email ${email}`);
	return result.id;
}
