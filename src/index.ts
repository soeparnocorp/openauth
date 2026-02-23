// src/index.ts
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

    // Root → redirect /authorize
    if (url.pathname === "/") {
      url.searchParams.set("redirect_uri", "https://app-readtalk.pages.dev/");
      url.searchParams.set("client_id", "your-client-id");
      url.searchParams.set("response_type", "code");
      url.pathname = "/authorize";
      return Response.redirect(url.toString());
    }

    // Callback → redirect ke frontend Pages dengan code
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");
      return Response.redirect(`https://app-readtalk.pages.dev/?code=${code}`);
    }

    // Route baru: /verify → menerima POST email/code dari Pages Function
    if (url.pathname === "/verify" && request.method === "POST") {
      return handleVerify(request, env);
    }

    // Default: gunakan issuer OpenAuth
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

// Handler baru untuk /verify
async function handleVerify(request: Request, env: Env) {
  const { email, code } = await request.json();

  // Contoh validasi sederhana, sesuaikan dengan logika Worker
  const userId = await getOrCreateUser(env, email);

  return new Response(JSON.stringify({ success: true, userId }), {
    headers: { "Content-Type": "application/json" },
  });
}

// Helper: insert/get user di D1
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
