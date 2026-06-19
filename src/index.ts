import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";
import { DashboardHTML } from "../app/dashboard";

const subjects = createSubjects({
  user: object({
    id: string(),
  }),
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    if (url.pathname === "/") {
      url.searchParams.set("redirect_uri", url.origin + "/callback");
      url.searchParams.set("client_id", "your-client-id");
      url.searchParams.set("response_type", "code");
      url.searchParams.set("state", "/dashboard");
      url.pathname = "/authorize";
      return Response.redirect(url.toString());
    }

    if (url.pathname === "/callback") {
      return Response.json({
        message: "OAuth flow complete!",
        params: Object.fromEntries(url.searchParams.entries()),
      });
    }

    if (url.pathname === "/dashboard") {
      const cookieHeader = request.headers.get("Cookie") || "";
      const cookies = Object.fromEntries(
        cookieHeader.split("; ").filter(Boolean).map((c) => {
          const [key, ...val] = c.split("=");
          return [key, val.join("=")];
        })
      );
      const userId = cookies.userId;

      if (!userId) {
        return Response.redirect("/");
      }

      const user = await env.AUTH_DB.prepare(
        "SELECT id, email FROM user WHERE id = ?"
      )
        .bind(userId)
        .first<{ id: string; email: string }>();

      if (!user) {
        return Response.redirect("/");
      }

      return new Response(DashboardHTML(user), {
        headers: { "Content-Type": "text/html" },
      });
    }

    if (url.pathname === "/logout") {
      const headers = new Headers();
      headers.append("Set-Cookie", "userId=; HttpOnly; Max-Age=0; Path=/");
      headers.append("Location", "/");
      return new Response(null, { status: 302, headers });
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
        title: "READTalk OpenAuth",
        primary: "#ff0000",
        favicon: "https://id-readtalk.pages.dev/vite.svg",
        logo: {
          dark: "https://id-readtalk.pages.dev/vite.svg",
          light: "https://id-readtalk.pages.dev/vite.svg",
        },
      },
      success: async (ctx, value) => {
        const userId = await getOrCreateUser(env, value.email);

        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/dashboard",
            "Set-Cookie": `userId=${userId}; HttpOnly; Max-Age=${60 * 60 * 24 * 7}; Path=/`,
          },
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
    `
  )
    .bind(email)
    .first<{ id: string }>();

  if (!result) {
    throw new Error(`Unable to process user: ${email}`);
  }

  console.log(`Found or created user ${result.id} with email ${email}`);
  return result.id;
}
