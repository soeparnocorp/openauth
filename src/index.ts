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
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // ===== / =====
    if (url.pathname === "/") {
      url.searchParams.set("redirect_uri", url.origin + "/callback");
      url.searchParams.set("client_id", "your-client-id");
      url.searchParams.set("response_type", "code");
      url.pathname = "/authorize";
      return Response.redirect(url.toString());
    }

    // ===== /callback =====
    if (url.pathname === "/callback") {
      return Response.json({
        message: "OAuth flow complete!",
        params: Object.fromEntries(url.searchParams.entries()),
      });
    }

    // ===== /dashboard =====
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

      const html = `<!DOCTYPE html>
<html>
<head>
  <title>Dashboard</title>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
  <div class="bg-white p-8 rounded-xl shadow-lg max-w-md w-full">
    <div class="flex items-center gap-4 mb-6">
      <div class="w-12 h-12 bg-blue-500 rounded-full flex items-center justify-center text-white text-xl font-bold">
        ${user.email[0].toUpperCase()}
      </div>
      <div>
        <h1 class="text-2xl font-bold">Welcome!</h1>
        <p class="text-gray-600">${user.email}</p>
      </div>
    </div>
    <div class="border-t pt-4">
      <p class="text-sm text-gray-500">User ID: <span class="font-mono">${user.id}</span></p>
    </div>
    <div class="mt-6">
      <a href="/logout" class="w-full inline-block text-center bg-red-500 text-white px-4 py-2 rounded-lg hover:bg-red-600 transition">
        Logout
      </a>
    </div>
  </div>
</body>
</html>`;

      return new Response(html, {
        headers: { "Content-Type": "text/html" },
      });
    }

    // ===== /logout =====
    if (url.pathname === "/logout") {
      const headers = new Headers();
      headers.append("Set-Cookie", "userId=; HttpOnly; Max-Age=0; Path=/");
      headers.append("Location", "/");
      return new Response(null, {
        status: 302,
        headers,
      });
    }

    // ===== OpenAuth =====
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

        const response = await ctx.subject("user", {
          id: userId,
        });

        // Redirect ke /dashboard
        response.headers.append("Location", "/dashboard");
        response.headers.append(
          "Set-Cookie",
          `userId=${userId}; HttpOnly; Max-Age=${60 * 60 * 24 * 7}; Path=/`
        );

        return new Response(null, {
          status: 302,
          headers: response.headers,
        });
      },
    }).fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;

// ===== getOrCreateUser =====
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
