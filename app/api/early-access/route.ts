import { NextResponse } from "next/server";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

type Payload = {
  name?: unknown;
  email?: unknown;
  role?: unknown;
  message?: unknown;
  company?: unknown; // honeypot
};

const attempts = new Map<string, { count: number; reset: number }>();

function rateLimited(key: string) {
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry || now > entry.reset) {
    attempts.set(key, { count: 1, reset: now + 60_000 });
    return false;
  }
  entry.count += 1;
  return entry.count > 5;
}

export async function POST(request: Request) {
  let payload: Payload;

  try {
    payload = (await request.json()) as Payload;
  } catch {
    return NextResponse.json(
      { status: "invalid", message: "Request body must be JSON." },
      { status: 400 },
    );
  }

  const name = typeof payload.name === "string" ? payload.name.trim().slice(0, 120) : "";
  const email = typeof payload.email === "string" ? payload.email.trim().slice(0, 200) : "";
  const role = typeof payload.role === "string" ? payload.role.trim().slice(0, 80) : "";
  const message =
    typeof payload.message === "string" ? payload.message.trim().slice(0, 1200) : "";
  const honeypot = typeof payload.company === "string" ? payload.company.trim() : "";

  if (honeypot) {
    // Silently accept bots without forwarding anything.
    return NextResponse.json({ status: "ok" }, { status: 202 });
  }

  if (!EMAIL.test(email)) {
    return NextResponse.json(
      { status: "invalid", message: "A valid email address is required." },
      { status: 422 },
    );
  }

  if (name.length < 2) {
    return NextResponse.json(
      { status: "invalid", message: "Please include a name we can reply to." },
      { status: 422 },
    );
  }

  const key =
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "local";
  if (rateLimited(key)) {
    return NextResponse.json(
      { status: "rate_limited", message: "Too many attempts. Try again in a minute." },
      { status: 429 },
    );
  }

  const endpoint = process.env.EARLY_ACCESS_WEBHOOK_URL;

  if (!endpoint) {
    // Honest state: nothing is stored, so we never claim a successful signup.
    return NextResponse.json(
      {
        status: "not_configured",
        message:
          "The early-access list is not connected to a destination yet. Nothing was stored.",
      },
      { status: 503 },
    );
  }

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name,
        email,
        role: role || null,
        message: message || null,
        source: "vibecheck-website",
        submittedAt: new Date().toISOString(),
      }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      return NextResponse.json(
        {
          status: "upstream_error",
          message: "The waitlist destination rejected the request.",
        },
        { status: 502 },
      );
    }
  } catch {
    return NextResponse.json(
      {
        status: "upstream_error",
        message: "Could not reach the waitlist destination.",
      },
      { status: 502 },
    );
  }

  return NextResponse.json({ status: "ok" }, { status: 200 });
}
