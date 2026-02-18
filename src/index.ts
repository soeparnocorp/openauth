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

    // ===== REDIRECT ROOT KE AUTHORIZE =====
    if (url.pathname === "/") {
      url.searchParams.set(
        "redirect_uri",
        "https://room.soeparnocorp.workers.dev/callback"
      );
      url.searchParams.set("client_id", "readtalk-client");
      url.searchParams.set("response_type", "code");
      url.pathname = "/authorize";
      return Response.redirect(url.toString());
    }

    // ===== HANDLE CALLBACK (SET COOKIE FIXED) =====
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");

      if (!code) {
        return Response.redirect(
          "https://room.soeparnocorp.workers.dev"
        );
      }

      const cookie = [
        `auth_token=${code}`,
        "Path=/",
        "Domain=.soeparnocorp.workers.dev",
        "HttpOnly",
        "Secure",
        "SameSite=None",
        "Max-Age=604800",
      ].join("; ");

      return new Response(null, {
        status: 302,
        headers: {
          "Set-Cookie": cookie,
          "Location": "https://room.soeparnocorp.workers.dev",
        },
      });
    }

    // ===== VERIFY =====
    if (url.pathname === "/verify" && request.method === "POST") {
      return handleVerify(request, env);
    }

    // ===== ME =====
    if (url.pathname === "/me" && request.method === "GET") {
      return handleMe(request, env);
    }

    // ===== OPENAUTH ISSUER =====
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
          })
        ),
      },
      theme: {
        title: "READTalk - Authentication",
        primary: "#ff0000",
      },
      success: async (ctx, value) => {
        return ctx.subject("user", {
          id: await getOrCreateUser(env, value.email),
        });
      },
    }).fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;

// ===== VERIFY =====
async function handleVerify(request: Request, env: Env) {
  try {
    const { token } = await request.json();

    if (!token) {
      return Response.json({ valid: false }, { status: 401 });
    }

    const sessionData = await env.AUTH_STORAGE.get(token, "json");

    if (sessionData) {
      return Response.json({
        valid: true,
        user: {
          id: sessionData.userId,
          email: sessionData.email,
        },
      });
    }

    return Response.json({ valid: false }, { status: 401 });
  } catch (error: any) {
    return Response.json(
      { valid: false, error: error.message },
      { status: 401 }
    );
  }
}

// ===== ME =====
async function handleMe(request: Request, env: Env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/auth_token=([^;]+)/);

  if (!match) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  const token = match[1];

  const sessionData = await env.AUTH_STORAGE.get(token, "json");

  if (!sessionData) {
    return Response.json({ error: "Invalid session" }, { status: 401 });
  }

  const result = await env.AUTH_DB.prepare(
    "SELECT id, email FROM user WHERE id = ?"
  )
    .bind(sessionData.userId)
    .first();

  if (!result) {
    return Response.json({ error: "User not found" }, { status: 404 });
  }

  return Response.json({
    id: result.id,
    email: result.email,
  });
}

async function getOrCreateUser(
  env: Env,
  email: string
): Promise<string> {
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

  return result.id;
}
