# Scam Shield: job listing risk scanner

A first-pass risk scanner that uses real-time search data and rule-based verification. It gives a risk assessment (0-25% Likely Genuine, 26-55% Verify Independently, 56-100% High Risk), never a verdict.

**Demo mode:** the three demo buttons (Obvious Scam, Subtle Scam, Likely Genuine) and the quick scan run fully in the browser, so they work with no API keys. Demo results are labelled as synthetic.

## What the deep scan does
1. If the user uploads a poster or screenshot, Claude reads the visible job/internship text first.
2. Finds up to 5 links in the supplied post and follows redirects hop by hop.
3. Reads the final page without running its scripts: title, forms and requested fields, payment wording, embedded frames and outbound links.
4. Looks up domain registration age through RDAP.
5. Uses **SerpApi** (when `SERPAPI_KEY` is configured) to cross-check:
   - Google Jobs for matching job/company results.
   - Google Jobs Listing for the top matching `job_id` when available.
   - Google Search for company/careers/scam/fraud mentions.
   - Google Maps for a matching company/business presence.
6. Uses **Google Safe Browsing** (when `GOOGLE_SAFE_BROWSING_KEY` is configured) to check all final URLs in one request.
7. Calculates the numeric risk score with the local rule-based engine. Claude explains the evidence but does **not** control the score.
8. Returns the risk level, reasons, safety recommendations and integration status to the existing dashboard.

The scanner never submits forms. It refuses localhost, private IPs and non-standard ports (SSRF protection).

## Environment variables
Set these in Netlify Site configuration → Environment variables. Never paste secret values into `public/index.html` or commit them to GitHub.

- `SERPAPI_KEY` — SerpApi private key.
- `GOOGLE_SAFE_BROWSING_KEY` — Google Safe Browsing API key.
- `ANTHROPIC_API_KEY` — Claude API key for poster OCR and explanations.
- `CLAUDE_MODEL` — optional Claude model override.

A `.env.example` file is included only as a template. It contains placeholders, not real keys.

## Deploy
1. Put this folder in a GitHub repo.
2. On Netlify choose **Add new site → Import from Git**.
3. Add the environment variables above in the site's environment settings.
4. Deploy and open the site.
5. Test **Deep scan with AI** using a sample job post or one of the sample posters.

### Important quota note
A deep scan can make several external lookups. SerpApi's Google Jobs, Google Jobs Listing, Google Search and Google Maps engines are used only when enough job/company context is available. The implementation also relies on SerpApi's normal API-key authentication. Cache and rate limits should be considered before public production use.

## Security notes
- API keys are server-side only; browser code never receives them.
- Supabase's anon key can remain in the browser only with appropriate RLS policies.
- Search results are treated as evidence, not proof that a company is legitimate or fraudulent.
- A new domain, missing Maps result, or missing search result is not by itself proof of a scam.
- The rule-based score is a triage signal, not a guarantee.

## Chatbot
The chat button calls `/api/chat` (`netlify/functions/chat.mjs`). It uses the same `ANTHROPIC_API_KEY`.

## Languages
The language menu offers Hindi, Hinglish, Marathi, Bengali, Tamil, Telugu, Gujarati, Kannada, Malayalam and Punjabi.
- Page text and quick-check results are translated through `/api/translate`.
- Deep-scan explanations and chatbot replies are written directly in the chosen language when Claude is available.

## Limits to mention in the pitch
- Pages built with JavaScript may show less than a real browser does.
- Login-only pages (LinkedIn, Instagram, WhatsApp) cannot be opened, so users paste the text.
- Search-result mentions are not a dedicated scam-report database.
- The score is rule-based triage and should not be presented as a guaranteed real/fake verdict.
- External API quotas and temporary API failures can reduce the available evidence.
