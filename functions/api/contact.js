/**
 * Cloudflare Pages Function: /api/contact
 * Handles contact form submissions securely by proxying to Web3Forms.
 * The access_key is retrieved from Cloudflare Pages Environment Variables (Secrets).
 */
export async function onRequestPost(context) {
    try {
        const data = await context.request.json();

        // הגנת ספאם (Honeypot field) - אם בוט מילא את השדה הנסתר
        if (data.botcheck) {
            return new Response(JSON.stringify({
                success: true,
                message: "Spam check triggered"
            }), {
                status: 200,
                headers: { "Content-Type": "application/json; charset=utf-8" }
            });
        }

        // שליפת המפתח הסודי ממשתנה הסביבה של Cloudflare Pages
        const accessKey = context.env.WEB3FORMS_ACCESS_KEY;

        if (!accessKey) {
            return new Response(JSON.stringify({
                success: false,
                message: "שרת: משתנה הסביבה WEB3FORMS_ACCESS_KEY אינו מוגדר ב-Cloudflare Pages"
            }), {
                status: 500,
                headers: { "Content-Type": "application/json; charset=utf-8" }
            });
        }

        // אימות Cloudflare Turnstile (Canonical Server-Side siteverify according to Cloudflare Turnstile standard)
        const turnstileToken = data['cf-turnstile-response'];
        const turnstileSecret = context.env?.TURNSTILE_SECRET || context.env?.TURNSTILE_SECRET_KEY;
        const expectedAction = "contact";
        const expectedHostnames = new Set(
            (context.env?.TURNSTILE_HOSTNAMES ?? "cyber-path.shlomi-sharbet.workers.dev")
                .split(",")
                .map(h => h.trim())
                .filter(Boolean)
        );

        if (turnstileSecret) {
            if (
                typeof turnstileToken !== "string" ||
                turnstileToken.length === 0 ||
                turnstileToken.length > 2048
            ) {
                return new Response(JSON.stringify({
                    success: false,
                    message: "אימות Cloudflare Turnstile חסר או שגוי."
                }), {
                    status: 403,
                    headers: { "Content-Type": "application/json; charset=utf-8" }
                });
            }

            try {
                const clientIp = context.request.headers.get("CF-Connecting-IP") || context.request.headers.get("x-forwarded-for");
                const verifyBody = new URLSearchParams({
                    secret: turnstileSecret,
                    response: turnstileToken
                });
                if (clientIp) verifyBody.set("remoteip", clientIp);

                const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
                    method: "POST",
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                    signal: AbortSignal.timeout(10_000),
                    body: verifyBody
                });

                if (!r.ok) throw new Error(`siteverify returned HTTP ${r.status}`);
                const result = await r.json();

                if (
                    !result.success ||
                    (result.action && result.action !== expectedAction) ||
                    (result.hostname && expectedHostnames.size > 0 && !expectedHostnames.has(result.hostname))
                ) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "אימות Cloudflare Turnstile נכשל. אנא נסה שוב."
                    }), {
                        status: 403,
                        headers: { "Content-Type": "application/json; charset=utf-8" }
                    });
                }
            } catch (turnstileErr) {
                console.error("Turnstile siteverify error:", turnstileErr);
                return new Response(JSON.stringify({
                    success: false,
                    message: "שגיאה במהלך בדיקת האימות מול Cloudflare."
                }), {
                    status: 403,
                    headers: { "Content-Type": "application/json; charset=utf-8" }
                });
            }
        }

        // ניקוי טוקנים טכניים של קאפצ'ה לפני העברה ל-Web3Forms
        const cleanPayload = { ...data };
        delete cleanPayload['cf-turnstile-response'];
        delete cleanPayload['h-captcha-response'];
        delete cleanPayload['g-recaptcha-response'];

        // הרכבת הנתונים עבור Web3Forms
        const payload = {
            ...cleanPayload,
            access_key: accessKey,
            subject: data.subject || "פנייה חדשה מאתר CISO as a Service",
            from_name: "CISO Website"
        };

        // שליחה מאובטחת מצד השרת ל-Web3Forms
        const response = await fetch("https://api.web3forms.com/submit", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        return new Response(JSON.stringify(result), {
            status: response.status,
            headers: { "Content-Type": "application/json; charset=utf-8" }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            message: "אירעה שגיאה בשרת בעת עיבוד הבקשה",
            error: error.message
        }), {
            status: 500,
            headers: { "Content-Type": "application/json; charset=utf-8" }
        });
    }
}
