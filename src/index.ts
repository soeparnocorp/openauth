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

		if (url.pathname === "/") {
			url.searchParams.set("redirect_uri", "https://app-readtalk.pages.dev/api/auth/callback");
			url.searchParams.set("client_id", "readtalk-pages");
			url.searchParams.set("response_type", "code");
			url.pathname = "/authorize";
			return Response.redirect(url.toString());
		}

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
				title: "READTalk - OpenAuth",
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
