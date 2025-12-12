/**
 * AI Email Extraction Module
 *
 * This module provides email content analysis using Cloudflare Workers AI.
 * It extracts important information like verification codes, authentication links,
 * service links, and subscription management links from email content.
 */

import { commonParseMail } from "../common";
import { getBooleanValue, getJsonSetting } from "../utils";
import { CONSTANTS } from "../constants";
import { Context } from "hono";
import type { AiExtractSettings } from "../admin_api/ai_extract_settings";

// AI Prompt for email analysis
const PROMPT = `
You are an expert email analyzer. Your task is to first UNDERSTAND the email content, then EXTRACT the most relevant information based on a strict priority order. Your analysis must be precise, extracting only the specified data without fabrication.

# Step 1: UNDERSTAND the Email
Read the entire email carefully, paying close attention to both visible plain text and hidden HTML attributes (specifically `href` in `<a>` tags). Determine its:
- **Overall purpose:** (e.g., account verification, marketing newsletter, system notification, password reset, service update).
- **Key context and situation:** What event or action triggered this email? What is the core message?
- **Sender's intent:** What does the sender want the recipient to do or know?
- **Security sensitivity:** Are there any elements that require careful handling (e.g., authentication codes, sensitive links for account access)?

# Step 2: EXTRACT Based on Priority
After thoroughly understanding the email, extract the most important item according to this strict priority order. For links, **always prioritize extracting from HTML `href` attributes if available**, as these represent the true intended destination. If a link appears in both plain text and HTML, the HTML `href` should be used.

**Priority 1: auth_code (Authentication Code)**
- **Definition:** Numeric or alphanumeric codes used for login verification, one-time passwords, security checks, or confirming an action.
- **Keywords:** verification code, OTP, security code, confirmation code, auth code, passcode, token, 验证码, 校验码, 动态密码.
- **Extraction Rule:** Extract ONLY the code itself. Remove any surrounding text, spaces, hyphens, or other formatting.
- **Example:**
    - From "Your verification code is **123-456**." -> `123456`
    - From "Use code: **789ABC** to complete your login." -> `789ABC`
    - From "您的验证码是：**987654**，请在5分钟内使用。" -> `987654`

**Priority 2: auth_link (Authentication Link)**
- **Definition:** Critical links leading to account-level actions such as login, email verification, account activation, or password reset. These links typically contain unique, time-sensitive tokens.
- **Keywords:** verify, confirm, activate, login, signin, signup, reset password, update password, 验证, 激活, 登录, 重置密码, 更改密码.
- **Extraction Rule:** Must be a real, complete, and valid URL (starts with `http://` or `https://`). **Crucially, when processing HTML emails, prioritize extracting the `href` attribute from `<a>` tags that match the purpose.** If no HTML is available, extract from plain text.
- **Example (HTML):**
    - `<a href="https://myaccount.com/verify?token=abc123XYZ">Verify My Email</a>` -> `https://myaccount.com/verify?token=abc123XYZ`
    - `<a href="https://example.com/reset_password?id=123&hash=xyz">Click here to reset your password</a>` -> `https://example.com/reset_password?id=123&hash=xyz`
- **Example (Plain Text):**
    - "Please verify your email: https://example.com/confirm?id=user123&code=abcd" -> `https://example.com/confirm?id=user123&code=abcd`

**Priority 3: service_link (Service-Specific Action Link)**
- **Definition:** Links related to specific actions or notifications within a particular service, application, or platform (e.g., viewing a pull request on GitHub, reviewing a task in Jira, accessing a specific report). These are for interacting with a service, not for account-level authentication.
- **Keywords:** commit, pull request, issue, repository, deployment, pipeline, code review, view report, review task, deploy, approval, GitHub, GitLab, Jira, Confluence, AWS, Azure, notification, go to.
- **Extraction Rule:** Must be a real, complete, and valid URL. **Prioritize the `href` attribute from `<a>` tags in HTML content.**
- **Example (HTML):**
    - `<a href="https://github.com/org/repo/pull/1234">View Pull Request #1234</a>` -> `https://github.com/org/repo/pull/1234`
    - `<a href="https://jira.company.com/browse/PROJ-567">PROJ-567: Bug Report</a>` -> `https://jira.company.com/browse/PROJ-567`
- **Example (Plain Text):**
    - "Your new deployment is available at: https://app.example.com/dashboard/prod-v1.0" -> `https://app.example.com/dashboard/prod-v1.0`

**Priority 4: subscription_link (Subscription Management Link)**
- **Definition:** Links specifically designed for managing email subscriptions, typically allowing the recipient to unsubscribe or adjust their email preferences. Usually found at the bottom of marketing, newsletter, or informational emails.
- **Keywords:** unsubscribe, opt-out, manage preferences, change preferences, 退订, 取消订阅, 管理偏好设置.
- **Extraction Rule:** Must be a real, complete, and valid URL. **Prioritize the `href` attribute from `<a>` tags in HTML content.**
- **Example (HTML):**
    - `<a href="https://newsletter.com/unsubscribe?user=abc">Unsubscribe</a>` -> `https://newsletter.com/unsubscribe?user=abc`
    - `<a href="https://example.com/manage_subscriptions">Manage your preferences here</a>` -> `https://example.com/manage_subscriptions`
- **Example (Plain Text):**
    - "To unsubscribe from these emails, visit: https://mailinglist.com/optout/123" -> `https://mailinglist.com/optout/123`

**Priority 5: other_link (Other Valuable Link)**
- **Definition:** Any other link that is clearly useful, important, or directly referenced in the email's primary message, but does not fit into any higher-priority categories.
- **Extraction Rule:** Only extract if no higher-priority items exist. Must be a real, complete, and valid URL. **Prioritize the `href` attribute from `<a>` tags in HTML content.**
- **Example (HTML):**
    - `<a href="https://company.com/support">Contact Support</a>` -> `https://company.com/support`
    - `<a href="https://example.com/learn-more">Learn more about our new feature!</a>` -> `https://example.com/learn-more`
- **Example (Plain Text):**
    - "Visit our website for more details: https://www.product.com" -> `https://www.product.com`

**Priority 6: none**
- **Definition:** No relevant codes, links, or valuable actionable content found in the email. The email is purely informational text, or the content is irrelevant for extraction based on the defined priorities.

# Special Case: Markdown Link Format & result_text
If the extracted content is a link, and its surrounding text (either within `[ ]` in plain text or the inner text of an `<a>` tag in HTML) provides a meaningful description:

- **Extract the text inside the brackets or `<a>` tag as `result_text`**.
- If the descriptive text is absent, empty, or generic (e.g., "Click Here", "Link", "More Info"), **analyze the email context and language to generate a concise, meaningful description (2-5 words) for `result_text`**. This description should reflect the link's purpose.
- **Match the email's language** for `result_text` (e.g., Chinese email → Chinese description, English email → English description).

**Example for `result_text`:**
- From `<a href="https://example.com/verify?token=abc123XYZ">Verify My Email Address</a>`
    - `extracted_item`: `https://example.com/verify?token=abc123XYZ`
    - `result_text`: `Verify My Email Address`
- From `<a href="https://github.com/org/repo/pull/1234">PR #1234 - Feature X</a>`
    - `extracted_item`: `https://github.com/org/repo/pull/1234`
    - `result_text`: `PR #1234 - Feature X`
- From `<a href="https://example.com/dashboard">Click Here</a>` (and the email discusses accessing your new dashboard)
    - `extracted_item`: `https://example.com/dashboard`
    - `result_text`: `Access New Dashboard` (or "访问新仪表盘")

# Critical Rules
1.  **Understand First**: Always analyze the email's purpose and full content (including HTML structure and plain text alternatives) before any extraction.
2.  **Single Selection**: Choose ONLY ONE type based on the highest priority match.
3.  **Real Data Only**: Never invent, guess, or fabricate content. **All extracted data (codes or links) MUST exist directly within the email's content.**
4.  **Complete URLs**: All extracted links must be full, valid URLs (starting with `http://` or `https://`) as they appear in the email.
5.  **Clean Extraction**: Return only the raw extracted content for `extracted_item`, without any additional explanatory text.
6.  **HTML `href` Priority**: For any link, if the email contains HTML, **always inspect and prioritize the `href` attribute of `<a>` tags for the most accurate URL.** Only fall back to plain text URL patterns if no relevant HTML `<a>` tags are present or if the `href` attribute is malformed/irrelevant.

# Output Format (JSON only)
{
  "type": "auth_code|auth_link|service_link|subscription_link|other_link|none",
  "result": "the extracted code/link OR empty string",
  "result_text": "the display text from markdown-format links."
}

IMPORTANT: Return ONLY the JSON, no explanations or additional text.
`;

/**
 * Extract important information from email content using Cloudflare Workers AI
 *
 * @param content - The email content to analyze (plain text or HTML)
 * @param env - Cloudflare Workers environment bindings
 * @returns Promise<ExtractResult> - The extracted information
 */
async function extractWithCloudflareAI(
    content: string,
    env: Bindings
): Promise<ExtractResult> {
    // Get the AI model name from environment variable or use default
    const modelName = env.AI_EXTRACT_MODEL || '@cf/meta/llama-3.1-8b-instruct';

    const result = await env.AI.run(modelName as keyof AiModels, {
        messages: [
            { role: 'system', content: PROMPT },
            { role: 'user', content },
        ],
        response_format: {
            type: 'json_schema',
            json_schema: {
                type: 'object',
                properties: {
                    type: {
                        type: 'string',
                        enum: ['auth_code', 'auth_link', 'service_link', 'subscription_link', 'other_link', 'none']
                    },
                    result: { type: 'string' },
                    result_text: { type: 'string' },
                },
                required: ['type', 'result', 'result_text'],
            },
        },
        stream: false,
    });

    // @ts-expect-error result.response
    const response = result.response;

    if (typeof response === 'string') {
        return JSON.parse(response) as ExtractResult;
    }

    if (response && typeof response === 'object') {
        return response as ExtractResult;
    }

    throw new Error('Unexpected response format from Cloudflare AI');
}

/**
 * Main extraction function
 * Checks if AI extraction is enabled, processes the email content, and saves to database
 *
 * @param parsedEmailContext - The parsed email context
 * @param env - Cloudflare Workers environment bindings
 * @param message_id - The email message ID
 * @param address - The recipient email address
 * @returns Promise<void>
 */
export async function extractEmailInfo(
    parsedEmailContext: ParsedEmailContext,
    env: Bindings,
    message_id: string | null,
    address: string
): Promise<void> {
    try {
        // Check if AI extraction is enabled via environment variable
        if (!getBooleanValue(env.ENABLE_AI_EMAIL_EXTRACT)) {
            return;
        }

        // Ensure AI binding is available
        if (!env.AI) {
            console.error('AI binding not available');
            return;
        }

        // Check allowlist if enabled
        const aiSettings = await getJsonSetting<AiExtractSettings>(
            { env: env } as Context<HonoCustomType>,
            CONSTANTS.AI_EXTRACT_SETTINGS_KEY
        );

        if (aiSettings?.enableAllowList && aiSettings.allowList?.length > 0) {
            const isAllowed = aiSettings.allowList.some(pattern => {
                // Support wildcard matching
                if (pattern.includes('*')) {
                    // Escape special regex characters except *
                    const escapedPattern = pattern
                        .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
                        .replace(/\*/g, '.*');
                    const regex = new RegExp('^' + escapedPattern + '$');
                    return regex.test(address);
                }
                // Exact match
                return address === pattern;
            });

            if (!isAllowed) {
                console.log(`AI extraction skipped for ${address}: not in allowlist`);
                return;
            }
        }

        // Parse email to get content
        const parsedEmail = await commonParseMail(parsedEmailContext);
        const emailContent = parsedEmail?.text || parsedEmail?.html || "";

        if (!emailContent) {
            return;
        }

        // Truncate content if too long (max 4000 characters to avoid token limits)
        const truncatedContent = emailContent.length > 4000
            ? emailContent.substring(0, 4000) + '...[truncated]'
            : emailContent;

        const result = await extractWithCloudflareAI(truncatedContent, env);

        // If extraction found something useful, save it to database
        if (result.type !== 'none' && result.result) {
            const metadata = JSON.stringify({
                ai_extract: result,
                extracted_at: new Date().toISOString()
            });

            // Update the raw_mails record with metadata
            await env.DB.prepare(
                `UPDATE raw_mails SET metadata = ? WHERE message_id = ?`
            ).bind(metadata, message_id).run();

            console.log(`AI extraction completed for ${message_id}: ${result.type}`);
        }
    } catch (e) {
        console.error('AI email extraction error:', e);
    }
}

/**
 * Type definition for extraction result
 */
export type ExtractResult = {
    type: 'auth_code' | 'auth_link' | 'service_link' | 'subscription_link' | 'other_link' | 'none';
    result: string;
    result_text: string;
};
