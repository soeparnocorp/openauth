import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

// EMAIL SUBJECT
const subjects = createSubjects({
	user: object({
		id: string(),
		email: string(),  // ← EMAIL
	}),
});

export default {
	fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);
		
		// Redirects Demo Version
		if (url.pathname === "/") {
			url.searchParams.set("redirect_uri", url.origin + "/callback");
			url.searchParams.set("client_id", "id-readtalk");  // ← Change
			url.searchParams.set("response_type", "code");
			url.pathname = "/authorize";
			return Response.redirect(url.toString());
		} else if (url.pathname === "/callback") {
			return Response.json({
				message: "OAuth flow complete!",
				params: Object.fromEntries(url.searchParams.entries()),
			});
		}

		return issuer({
			storage: CloudflareStorage({
				namespace: env.AUTH_STORAGE,
			}),
			subjects,  // ← SUBJECTS UPDATE
			
			// CLIENT CONFIGURATION
			clients: [{
				id: "id-readtalk",
				name: "READTalk PWA",
				redirectUris: [
					"https://id-readtalk.pages.dev/callback",
					"http://localhost:5173/callback"
				],
				grantTypes: ["authorization_code"],
				responseTypes: ["code"]
			}],
			
			providers: {
				password: PasswordProvider(
					PasswordUI({
						sendCode: async (email, code) => {
							console.log(`🔐 Login code for ${email}: ${code}`);
						},
						copy: {
							input_code: "Code (check Worker logs)",
						},
					}),
				),
			},
			theme: {
				title: "READTalk OpenAuth",
				primary: "#ff0000",
				favicon: "https://id-readtalk.pages.dev/vite.svg",
				logo: {
					dark: "https://id-readtalk.pages.dev/vite.svg",
					light: "https://id-readtalk.pages.dev/vite.svg",
				},
			},
			
			// INCLUDE EMAIL CALLBACK
			success: async (ctx, value) => {
				const userId = await getOrCreateUser(env, value.email);
				return ctx.subject("user", {
					id: userId,
					email: value.email,  // ← EMAIL
				});
			},
		}).fetch(request, env, ctx);
	},
} satisfies ExportedHandler<Env>;

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
