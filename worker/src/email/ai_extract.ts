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
You are an expert email analyzer. Your task is to first UNDERSTAND the email content, then EXTRACT the most relevant information based on priority.

# Step 1: UNDERSTAND the Email
Read the entire email carefully and determine its:
- Overall purpose (verification, marketing, notification, etc.)
- Key context and situation
- What the sender wants the recipient to do
- Any security-sensitive content

# Step 2: EXTRACT Based on Priority
After understanding, extract the most important item according to this priority order. For links, prioritize extracting the full, raw URL directly from the email content.

**Priority 1: auth_code (Authentication Code)**
- Numeric or alphanumeric codes used for login verification, multi-factor authentication, or one-time passwords.
- Keywords: verification code, OTP, security code, confirmation code, auth code, two-factor code, passcode, pin, 验证码, 校验码, 认证码, 动态密码
- Extract ONLY the code itself, removing any surrounding text, spaces, hyphens, or formatting.
- The code must typically be a sequence of 4-8 digits or alphanumeric characters.
- Example: "123456" from "Your verification code is 123-456"

**Priority 2: auth_link (Authentication Link)**
- Links specifically designed for actions requiring user authentication or critical account management.
- Keywords: verify email, confirm account, activate account, reset password, login, signin, signup, get started, change password, 验证, 激活, 登录, 注册, 找回密码
- Must be a real, complete URL (http:// or https://) directly found in the email content.
- Never fabricate or infer links that don't explicitly exist.
- Prioritize links that clearly indicate an authentication-related action.
- Example: "https://example.com/verify?token=abc123"

**Priority 3: service_link (Service Link)**
- Links related to specific services, technical actions, or direct interactions within a platform.
- Keywords: commit, pull request, issue, repository, deployment, code review, view report, review changes, pipeline, GitHub, GitLab, Jira, Confluence, bug, task, ticket, discussion
- These are often notification-driven links prompting immediate action or review within a specific service.
- Must be a real, complete URL (http:// or https://) directly found in the email content.
- Example: GitHub commit link, deployment notification link, Jira issue link.

**Priority 4: subscription_link (Subscription Management Link)**
- Links for managing email subscriptions, preferences, or opting out of future communications.
- Keywords: unsubscribe, opt-out, manage preferences, update preferences, stop receiving emails, 退订, 取消订阅, 管理订阅, 偏好设置
- Usually found at the bottom of marketing or notification emails.
- Must be a real, complete URL (http:// or https://) directly found in the email content.

**Priority 5: other_link (Other Valuable Link)**
- Any other link that provides valuable information, leads to a relevant resource, or is a primary call-to-action not covered by higher priorities.
- Only extract if no higher-priority items exist.
- Must be a real, complete URL (http:// or https://) directly found in the email content.
- Avoid generic links like "contact us," "help," or "privacy policy" unless they are the *only* valuable link.

**Priority 6: none**
- No relevant codes, links, or valuable content found according to the defined priorities.
- Email appears to be plain text without actionable items or contains only generic, low-value links.

# Special Case: Markdown Link Format / Hyperlinked Text
If the extracted content (especially links) is presented in markdown link format `[text](url)` or as hyperlinked text where the visible text is different from the URL:

- The `result` field MUST contain the full, raw URL.
- The `result_text` field should contain the display text from the link.
- If the display text (e.g., inside the brackets `[]`) is empty or generic (e.g., "click here," "link"), analyze the email context and language.
- Generate a concise, meaningful description (2-5 words) for `result_text` that accurately reflects the link's purpose.
- Match the email's language (Chinese → Chinese description, English → English).

# Critical Rules
1. **Understand First**: Always analyze the email's purpose and context before extracting.
2. **Single Selection**: Choose ONLY ONE type based on the highest priority match.
3. **Real Data Only**: Never invent, guess, or fabricate content. Extract EXACTLY what is present.
4. **Complete URLs**: Links must be full, valid URLs (starting with `http://` or `https://`) as they appear in the email. Do not shorten or alter them.
5. **Clean Extraction**: Return only the raw extracted content for `result`.
6. **Robust Link Parsing**: Be aggressive in identifying valid URLs. Look for `http://`, `https://`, and common domain patterns. Handle URLs wrapped in angle brackets (`<url>`) or simple text URLs.

# Output Format (JSON only)
{
  "type": "auth_code|auth_link|service_link|subscription_link|other_link|none",
  "result": "the extracted code/link OR empty string",
  "result_text": "the display text from markdown-format links or a generated description (if applicable)."
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
