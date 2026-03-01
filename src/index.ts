import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

// Subject schema untuk user
const subjects = createSubjects({
	user: object({
		id: string(),
	}),
});

export default {
	fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);

		// Root request → redirect ke /authorize
		if (url.pathname === "/") {
			url.pathname = "/authorize";
			url.searchParams.set("redirect_uri", url.origin + env.AUTH_CALLBACK); // pakai ENV AUTH_CALLBACK
			url.searchParams.set("client_id", "your-client-id");
			url.searchParams.set("response_type", "code");
			return Response.redirect(url.toString(), 302);
		}

		// Callback setelah login → redirect ke AUTH_CALLBACK
		if (url.pathname === "/callback") {
			const callbackUrl = url.origin + env.AUTH_CALLBACK + "?" + url.searchParams.toString();
			return Response.redirect(callbackUrl, 302);
		}

		// Semua route lain → OpenAuth issuer
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
						copy: { input_code: "Code (check Worker logs)" },
					})
				),
			},
			theme: {
				title: "READTalk - OpenAuth",
				primary: "#ff0000",
				favicon: "https://workers.cloudflare.com/favicon.ico",
				logo: {
					dark: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/db1e5c92-d3a6-4ea9-3e72-155844211f00/public",
					light: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/fa5a3023-7da9-466b-98a7-4ce01ee6c700/public",
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

// Helper: insert atau ambil user dari DB
async function getOrCreateUser(env: Env, email: string): Promise<string> {
	const result = await env.AUTH_DB.prepare(
		`
		INSERT INTO user (email)
		VALUES (?)
		ON CONFLICT (email) DO UPDATE SET email = email
		RETURNING id;
		`
	)
		.bind(email)
		.first<{ id: string }>();

	if (!result) throw new Error(`Unable to process user: ${email}`);
	console.log(`Found or created user ${result.id} with email ${email}`);
	return result.id;
}
