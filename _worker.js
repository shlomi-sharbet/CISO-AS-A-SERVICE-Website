import { EmailMessage } from "cloudflare:email";

/**
 * Cloudflare Worker entrypoint
 * Hardened Backend-for-Frontend (BFF) Proxy for contact form and secure static asset delivery.
 */

const SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
};

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // ניתוב עבור טופס יצירת הקשר
        if (url.pathname === "/api/contact" && request.method === "POST") {
            try {
                // בדיקת גודל גוף הבקשה למניעת הצפת זיכרון (DoS)
                const contentLength = parseInt(request.headers.get("content-length") || "0", 10);
                if (contentLength > 50000) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "גודל הבקשה חורג מהמותר."
                    }), {
                        status: 413,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                const data = await request.json();

                // הגנת ספאם (Honeypot) - זיהוי בוטים
                if (data.botcheck || data._hp_check) {
                    return new Response(JSON.stringify({
                        success: true,
                        message: "Spam check triggered"
                    }), {
                        status: 200,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                // ולידציית קלט בסיסית וסינון אורך שדות (Input Validation)
                if (typeof data.name !== "string" || !data.name.trim() || data.name.length > 150) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שם מלא אינו תקין או ארוך מדי."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (typeof data.company !== "string" || !data.company.trim() || data.company.length > 150) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שם החברה אינו תקין או ארוך מדי."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (typeof data.phone !== "string" || !data.phone.trim() || data.phone.length > 30) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "מספר טלפון אינו תקין או ארוך מדי."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (typeof data.email !== "string" || !emailRegex.test(data.email.trim()) || data.email.length > 150) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "כתובת דוא״ל אינה תקינה."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.role && (typeof data.role !== "string" || data.role.length > 100)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שדה תפקיד אינו תקין או ארוך מדי."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.employees && (typeof data.employees !== "string" || data.employees.length > 50)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שדה מספר עובדים אינו תקין."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.country && (typeof data.country !== "string" || data.country.length > 100)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שדה מדינה אינו תקין."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.service && (typeof data.service !== "string" || data.service.length > 100)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שדה שירות מבוקש אינו תקין."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.timeline && (typeof data.timeline !== "string" || data.timeline.length > 100)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שדה מועד התחלה אינו תקין."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.message && (typeof data.message !== "string" || data.message.length > 3000)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "תוכן ההודעה ארוך מדי (מקסימום 3000 תווים)."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                // שליפת המפתח הסודי ממשתנה הסביבה של Cloudflare
                const accessKey = env?.WEB3FORMS_ACCESS_KEY;

                if (!accessKey) {
                    console.error("Configuration error: WEB3FORMS_ACCESS_KEY is not defined in Cloudflare environment secrets.");
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שגיאת תצורה בשרת בעת עיבוד הבקשה."
                    }), {
                        status: 500,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                // אימות Cloudflare Turnstile (Canonical Server-Side siteverify)
                const turnstileToken = data['cf-turnstile-response'];
                const turnstileSecret = env?.TURNSTILE_SECRET || env?.TURNSTILE_SECRET_KEY;
                const expectedAction = "contact";
                const expectedHostnames = new Set(
                    (env?.TURNSTILE_HOSTNAMES ?? "cyber-path.shlomi-sharbet.workers.dev")
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
                            headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                        });
                    }

                    try {
                        const clientIp = request.headers.get("CF-Connecting-IP") || request.headers.get("x-forwarded-for");
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

                        const requestHost = (request.headers.get("host") || url.hostname || "").split(":")[0].toLowerCase();
                        const isHostnameValid = !result.hostname || 
                            expectedHostnames.size === 0 || 
                            expectedHostnames.has(result.hostname) || 
                            result.hostname === requestHost || 
                            [...expectedHostnames].some(h => result.hostname.endsWith("." + h) || h.endsWith("." + result.hostname));

                        if (
                            !result.success ||
                            (result.action && result.action !== expectedAction) ||
                            !isHostnameValid
                        ) {
                            return new Response(JSON.stringify({
                                success: false,
                                message: "אימות Cloudflare Turnstile נכשל. אנא נסה שוב."
                            }), {
                                status: 403,
                                headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                            });
                        }
                    } catch (turnstileErr) {
                        console.error("Turnstile siteverify error:", turnstileErr);
                        return new Response(JSON.stringify({
                            success: false,
                            message: "שגיאה במהלך בדיקת האימות מול Cloudflare."
                        }), {
                            status: 403,
                            headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                        });
                    }
                }

                // ניקוי טוקנים טכניים של קאפצ'ה ושדות Honeypot לפני העברה ל-Web3Forms
                const cleanPayload = { ...data };
                delete cleanPayload['cf-turnstile-response'];
                delete cleanPayload['h-captcha-response'];
                delete cleanPayload['g-recaptcha-response'];
                delete cleanPayload['botcheck'];
                delete cleanPayload['_hp_check'];

                // חיטוי קלט למניעת הזרקת HTML (XSS & HTML Injection)
                const sanitize = (val) => typeof val === 'string' ? val.replace(/[<>&"']/g, '').trim() : val;
                cleanPayload.name = sanitize(data.name);
                cleanPayload.company = sanitize(data.company);
                if (cleanPayload.role) cleanPayload.role = sanitize(data.role);
                if (cleanPayload.phone) cleanPayload.phone = sanitize(data.phone);
                if (cleanPayload.message) cleanPayload.message = sanitize(data.message);

                // שליחת התראה בדוא״ל: עדיפות ל-Cloudflare Native (send_email binding)
                let emailSent = false;
                let emailError = null;

                if (env.EMAIL && env.BUSINESS_ALERT_EMAIL) {
                    try {
                        const recipient = env.BUSINESS_ALERT_EMAIL;
                        const sender = env.FROM_EMAIL || `notifications@${url.hostname.replace(/^www\./, '')}`;
                        const emailSubject = `פנייה חדשה מאתר Cyber Path: ${cleanPayload.name} (${cleanPayload.company})`;

                        const htmlBody = `
                          <div dir="rtl" style="font-family: Arial, 'Heebo', sans-serif; line-height: 1.6; color: #1e293b; max-width: 600px; margin: 0 auto; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden;">
                            <div style="background: linear-gradient(135deg, #070d18 0%, #0c1527 100%); padding: 24px; color: #ffffff; text-align: center;">
                              <h1 style="margin: 0; font-size: 22px; color: #38bdf8;">Cyber Path</h1>
                              <p style="margin: 6px 0 0; color: #94a3b8; font-size: 14px;">התקבלה פנייה חדשה מטופס יצירת הקשר באתר</p>
                            </div>
                            <div style="padding: 24px; background: #ffffff;">
                              <table style="width: 100%; border-collapse: collapse; font-size: 15px;">
                                <tr><td style="padding: 8px 0; color: #64748b; width: 140px;"><strong>שם מלא:</strong></td><td style="padding: 8px 0; color: #0f172a;">${cleanPayload.name}</td></tr>
                                <tr><td style="padding: 8px 0; color: #64748b;"><strong>חברה / ארגון:</strong></td><td style="padding: 8px 0; color: #0f172a;">${cleanPayload.company}</td></tr>
                                <tr><td style="padding: 8px 0; color: #64748b;"><strong>תפקיד:</strong></td><td style="padding: 8px 0; color: #0f172a;">${cleanPayload.role || 'לא צוין'}</td></tr>
                                <tr><td style="padding: 8px 0; color: #64748b;"><strong>דוא״ל עסקי:</strong></td><td style="padding: 8px 0; color: #0284c7;"><a href="mailto:${cleanPayload.email}" style="color: #0284c7;">${cleanPayload.email}</a></td></tr>
                                <tr><td style="padding: 8px 0; color: #64748b;"><strong>טלפון:</strong></td><td style="padding: 8px 0; color: #0f172a;"><a href="tel:${cleanPayload.phone}" style="color: #0f172a;">${cleanPayload.phone}</a></td></tr>
                                <tr><td style="padding: 8px 0; color: #64748b;"><strong>מספר עובדים:</strong></td><td style="padding: 8px 0; color: #0f172a;">${cleanPayload.employees || 'לא צוין'}</td></tr>
                                <tr><td style="padding: 8px 0; color: #64748b;"><strong>שירות מבוקש:</strong></td><td style="padding: 8px 0; color: #0f172a;">${cleanPayload.service || 'כללי'}</td></tr>
                                <tr><td style="padding: 8px 0; color: #64748b;"><strong>לוח זמנים:</strong></td><td style="padding: 8px 0; color: #0f172a;">${cleanPayload.timeframe || 'לא צוין'}</td></tr>
                              </table>
                              <div style="margin-top: 16px; padding: 14px; background: #f8fafc; border-right: 4px solid #0284c7; border-radius: 4px;">
                                <strong style="color: #334155; display: block; margin-bottom: 6px;">הודעה / פרטים נוספים:</strong>
                                <div style="color: #475569; white-space: pre-wrap;">${cleanPayload.message || 'לא צורפה הודעה נוספת.'}</div>
                              </div>
                            </div>
                            <div style="padding: 14px; background: #f1f5f9; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #e2e8f0;">
                              הודעה מאובטחת זו נוצרה ונשלחה אוטומטית ע״י שרתי הקצה של Cyber Path
                            </div>
                          </div>
                        `;

                        // מבנה RFC 2822 תואם MIME עם קידוד Base64 UTF-8 לכותרת
                        const rawMime = [
                            `From: "Cyber Path Alerts" <${sender}>`,
                            `To: <${recipient}>`,
                            `Reply-To: <${cleanPayload.email}>`,
                            `Subject: =?utf-8?B?${btoa(unescape(encodeURIComponent(emailSubject)))}?=`,
                            `MIME-Version: 1.0`,
                            `Content-Type: text/html; charset=utf-8`,
                            ``,
                            htmlBody
                        ].join('\r\n');

                        const emailMsg = new EmailMessage(sender, recipient, rawMime);
                        await env.EMAIL.send(emailMsg);
                        emailSent = true;
                    } catch (nativeEmailErr) {
                        console.error("Cloudflare Native send_email error:", nativeEmailErr);
                        emailError = nativeEmailErr;
                    }
                }

                // אם Cloudflare Native לא מוגדר או נכשל, נסה משלוח דרך Web3Forms (Fallback)
                if (!emailSent && accessKey) {
                    try {
                        const payload = {
                            ...cleanPayload,
                            access_key: accessKey,
                            subject: typeof data.subject === "string" && data.subject.length <= 150 ? sanitize(data.subject) : "פנייה חדשה מאתר Cyber Path",
                            from_name: "Cyber Path"
                        };

                        const response = await fetch("https://api.web3forms.com/submit", {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json",
                                "Accept": "application/json"
                            },
                            body: JSON.stringify(payload)
                        });

                        const result = await response.json();
                        if (response.ok && result.success) {
                            emailSent = true;
                        }
                    } catch (w3fErr) {
                        console.error("Web3Forms fallback error:", w3fErr);
                    }
                }

                // סנכרון וגיבוי אוטומטי ל-Google Sheets (Mini-CRM מאובטח עם Secret Token)
                if (env.GOOGLE_SHEETS_WEBHOOK_URL && env.GOOGLE_SHEETS_SECRET_TOKEN) {
                    try {
                        await fetch(env.GOOGLE_SHEETS_WEBHOOK_URL, {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({
                                token: env.GOOGLE_SHEETS_SECRET_TOKEN,
                                timestamp: new Date().toLocaleString("he-IL", { timeZone: "Asia/Jerusalem" }),
                                name: cleanPayload.name,
                                company: cleanPayload.company,
                                role: cleanPayload.role || '',
                                email: cleanPayload.email,
                                phone: cleanPayload.phone,
                                employees: cleanPayload.employees || '',
                                service: cleanPayload.service || '',
                                timeframe: cleanPayload.timeframe || '',
                                message: cleanPayload.message || ''
                            })
                        });
                    } catch (sheetErr) {
                        console.error("Google Sheets sync warning:", sheetErr);
                        // פעולה לא חוסמת: הצלחת המשלוח המרכזי תקפה גם אם סנכרון הגיליון מתעכב
                    }
                }

                if (emailSent) {
                    return new Response(JSON.stringify({
                        success: true,
                        message: "הפנייה התקבלה בהצלחה! ניצור עמך קשר בהקדם."
                    }), {
                        status: 200,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                } else {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שגיאה במשלוח הטופס. אנא ודא כי פרטי ההתקשרות נכונים או פנה ישירות."
                    }), {
                        status: 502,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

            } catch (error) {
                console.error("Contact API Server Error:", error);
                return new Response(JSON.stringify({
                    success: false,
                    message: "אירעה שגיאה בשרת בעת עיבוד הבקשה."
                }), {
                    status: 500,
                    headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                });
            }
        }

        // הגשת קבצים סטטיים (index.html וכו') עם כותרות אבטחה
        if (env.ASSETS) {
            const assetResponse = await env.ASSETS.fetch(request);
            const headers = new Headers(assetResponse.headers);
            for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
                headers.set(key, value);
            }
            return new Response(assetResponse.body, {
                status: assetResponse.status,
                statusText: assetResponse.statusText,
                headers: headers
            });
        }

        return new Response("Not Found", { status: 404, headers: SECURITY_HEADERS });
    }
};
