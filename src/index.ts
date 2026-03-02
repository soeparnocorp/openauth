// openauth/index.ts
import { issuer } from "@openauthjs/openauth"
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare"
import { PasswordProvider } from "@openauthjs/openauth/provider/password"
import { PasswordUI } from "@openauthjs/openauth/ui/password"
import { createSubjects } from "@openauthjs/openauth/subject"
import { object, string } from "valibot"

const subjects = createSubjects({
  user: object({
    id: string(),
    email: string(),
    usernameID: string(),
  }),
})

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    // Pages function akan panggil POST /api/token
    if (request.url.endsWith('/api/token') && request.method === 'POST') {
      const body = await request.json().catch(() => ({}))
      const email = body.email || `demo@readtalk.dev`

      const result = await issuer({
        storage: CloudflareStorage({ namespace: env.AUTH_STORAGE }),
        subjects,
        providers: {
          password: PasswordProvider(
            PasswordUI({
              sendCode: async (email, code) => {
                console.log(`Sending code ${code} to ${email}`)
              },
              copy: { input_code: "Code (check Worker logs)" },
            })
          ),
        },
      }).success(ctx, { email })

      // result.user = { id, email, usernameID }
      return new Response(JSON.stringify({ user: result }), { status: 200 })
    }

    // fallback issuer fetch
    return issuer({
      storage: CloudflareStorage({ namespace: env.AUTH_STORAGE }),
      subjects,
      providers: {
        password: PasswordProvider(
          PasswordUI({
            sendCode: async (email, code) => {
              console.log(`Sending code ${code} to ${email}`)
            },
            copy: { input_code: "Code (check Worker logs)" },
          })
        ),
      },
    }).fetch(request, env, ctx)
  },
} satisfies ExportedHandler<Env>
