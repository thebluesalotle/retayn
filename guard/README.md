# Retayn Guard

Local monitoring and protection hub for Retayn.

Retayn connects apps, watches for suspicious access and control changes, maps every system required to ship a product, shows pending notifications in a dashboard, and only takes action automatically if an alert is left untouched longer than the dashboard delay.

## Protection Scope

The dashboard's `Protection map` covers:

- Identity and operations
- Source code
- Publisher accounts
- Signing materials
- Cloud and data
- Domains and billing
- Build and release pipelines

Native connectors monitor provider APIs continuously. Systems without a native connector can still be added to the critical-system inventory with their control holders, recovery contact, recovery path, criticality, and independent backup status. Coverage gaps and missing recovery controls lower the security score.

Protection Map entries do not give Retayn API access by themselves. They are manual business-continuity records for systems Retayn cannot connect to yet, such as domains, app stores, signing keys, cloud accounts, DNS, billing, or release pipelines. Adding one lets Retayn show coverage gaps, flag missing recovery contacts or backups, keep the system in the owner's recovery record, and make future recovery work faster. Native connectors are what perform live monitoring.

## Current Connectors

- GitHub repositories
- Shopify stores
- Slack workspaces
- Google Workspace domains
- Airtable bases
- Zendesk Support accounts

More connectors are expected later, so the UI is structured around `Overview` and `Connect an app` instead of a GitHub-only console.

All six connectors establish a baseline and then poll continuously. Google Workspace, Airtable, and Zendesk OAuth credentials refresh automatically. Automatic remediation remains disabled for providers that do not expose a narrowly scoped, reversible action.

## Current Monitoring

- GitHub: repository visibility, collaborators and roles, default branch protection, deploy keys, and webhooks
- Shopify: store identity, domains, account email, plan, and API reachability
- Slack: members, administrators, owners, reactivated accounts, and API reachability
- Google Workspace: directory users, administrators, suspension state, organization units, and API reachability
- Airtable: base collaborators, permission changes, base reachability, tables, fields, and schema removal/addition
- Zendesk: agents, administrators, role changes, suspension state, and API reachability

Retayn creates a connection-health notification when provider access is interrupted and resolves it automatically after access is restored.

## GitHub Monitoring

Retayn watches:

- New collaborators
- Collaborator permission escalation
- Private repositories becoming public
- Default branch protection being removed
- Write-capable deploy keys
- New webhooks

## Per-App Settings

These live under `My apps` for each connected app:

- Take supported action if untouched
- Untouched delay in minutes
- Windows notifications
- Monitoring interval
- Allowed people or accounts
- Allowed webhook URLs
- Allowed write deploy key titles

Keep `.env` for secrets only.

## Persistent Storage

Retayn stores sign-ins, connected apps, baselines, alerts, Protection Map records, recovery cases, OAuth tokens, and uploaded recovery evidence in SQLite files and upload folders under `RETAYN_DATA_DIR`.

For Render, this must be a Persistent Disk mounted at `/data`, with:

```text
RETAYN_DATA_DIR=/data
```

The included `render.yaml` defines this disk. If the service was created manually or the disk is not attached to the Guard service, Render redeploys will erase the container filesystem and Retayn will look like it forgot everything. Keep one instance/worker while using SQLite, and migrate to managed Postgres/object storage before scaling horizontally.

## Adding Providers

The connector catalog in `retayn_app.py` is provider-neutral. Each connector declares:

- The customer-facing install fields
- The protection categories it covers
- The signals Retayn monitors
- The actions the provider safely supports

A production connector then adds an OAuth start/callback pair, a baseline collector, a comparison scan, and explicit remediation handlers. This keeps Apple Developer, Google Play, npm, GitLab, AWS, GCP, Azure, Cloudflare, registrars, payment providers, and CI/CD systems inside the same dashboard and event model.

The hosted build encrypts provider OAuth tokens with `RETAYN_TOKEN_ENCRYPTION_KEY`, validates provider webhooks, requires Google authentication, and isolates each user's SQLite database and uploads. Before scaling beyond one instance, add a managed audit log, move polling jobs into a durable worker queue, and migrate SQLite/uploads to managed database and object-storage services.

## Connector App Setup

Retayn is a retail product, so customers should not be asked to create API tokens. The right flow is:

1. Retayn creates one provider app/bot per platform.
2. The dashboard shows `Open install`.
3. The customer approves Retayn in Shopify, Slack, Google Workspace, Airtable, Zendesk, or GitHub.
4. The provider redirects back to Retayn.
5. Retayn stores the resulting server-side credential.
6. The customer enters only a simple identifier when needed, such as a shop domain, Workspace domain, base URL, or Zendesk subdomain.

This local prototype now has OAuth start/callback routes and stores returned tokens in SQLite. Set `RETAYN_PUBLIC_BASE_URL` to your current ngrok origin, for example:

```env
RETAYN_PUBLIC_BASE_URL=https://e798-2a00-f29-228-e317-a553-2428-9bd6-e47.ngrok-free.app
```

Register these callback URLs with providers:

- Shopify: `https://your-ngrok-domain/oauth/shopify/callback`
- Slack: `https://your-ngrok-domain/oauth/slack/callback`
- Google Workspace: `https://your-ngrok-domain/oauth/google-workspace/callback`
- Airtable: `https://your-ngrok-domain/oauth/airtable/callback`
- Zendesk: `https://your-ngrok-domain/oauth/zendesk/callback`

Add provider app credentials to `.env`:

```env
SHOPIFY_CLIENT_ID=
SHOPIFY_CLIENT_SECRET=
SLACK_CLIENT_ID=
SLACK_CLIENT_SECRET=
GOOGLE_WORKSPACE_CLIENT_ID=
GOOGLE_WORKSPACE_CLIENT_SECRET=
AIRTABLE_CLIENT_ID=
AIRTABLE_CLIENT_SECRET=
ZENDESK_CLIENT_ID=
ZENDESK_CLIENT_SECRET=
```

### Shopify

Retayn setup:

1. Log in to the Shopify store as the store owner or an admin.
2. Open `Settings`.
3. Open `Apps and sales channels`.
4. Click `Develop apps`.
5. If prompted, enable custom app development.
6. Click `Create an app`.
7. Name it `Retayn Guard`.
8. Open `Configuration`.
9. Under `Admin API integration`, add scopes:
   - `read_shopify_payments_accounts` if available for your store
   - `read_users` if available on your plan
   - `read_locations`
   - `read_merchant_managed_fulfillment_orders` only if you later monitor fulfillment paths
10. Click `Save`.
11. Open `API credentials`.
12. Click `Install app`.
13. Reveal and copy the `Admin API access token`.
14. For local testing, set `SHOPIFY_ADMIN_TOKEN` in `guard/.env`.
15. For the dashboard install button, set `SHOPIFY_INSTALL_URL` to the Shopify app install URL once the app is public/custom-installable.

Customer flow:

1. In Retayn, choose `Shopify`.
2. Click `Open Shopify install`.
3. Approve Retayn in Shopify.
4. Return to Retayn.
5. Enter only `your-store.myshopify.com`.
6. Click `Finish connection`.

### Slack

Retayn setup:

1. Go to `https://api.slack.com/apps`.
2. Click `Create New App`.
3. Choose `From scratch`.
4. Name it `Retayn Guard` and select your workspace.
5. Open `OAuth & Permissions`.
6. Under `Bot Token Scopes`, add:
   - `team:read`
   - `users:read`
   - `users:read.email` if you want emails in future checks
   - `auditlogs:read` only on Enterprise Grid if you later monitor audit events
7. Click `Install to Workspace`.
8. Approve the install.
9. Copy the `Bot User OAuth Token`, which starts with `xoxb-`.
10. For local testing, set `SLACK_BOT_TOKEN` in `guard/.env`.
11. Set `SLACK_INSTALL_URL` to the Slack OAuth/install URL for the Retayn Slack app.

Customer flow:

1. In Retayn, choose `Slack`.
2. Click `Open Slack install`.
3. Approve Retayn in Slack.
4. Return to Retayn.
5. Enter the workspace name or URL.
6. Click `Finish connection`.

### Google Workspace

Retayn setup:

1. Go to Google Cloud Console.
2. Create or select a project for Retayn.
3. Open `APIs & Services` > `Library`.
4. Enable `Admin SDK API`.
5. Open `IAM & Admin` > `Service Accounts`.
6. Create a service account named `retayn-guard`.
7. Open the service account.
8. Copy its `Unique ID`; you need this for domain-wide delegation.
9. Open `Keys`.
10. Create a JSON key and download it.
11. Put the JSON file in `guard/`, for example `google-workspace-service-account.json`.
12. In Google Admin Console, open `Security` > `Access and data control` > `API controls`.
13. Open `Domain-wide delegation`.
14. Add a new API client using the service account `Unique ID`.
15. Add this OAuth scope:
    - `https://www.googleapis.com/auth/admin.directory.user.readonly`
16. For local testing, set `GOOGLE_WORKSPACE_ADMIN_EMAIL` and `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON_PATH` in `guard/.env`.
17. Set `GOOGLE_WORKSPACE_INSTALL_URL` to the Workspace Marketplace/admin consent URL once the Retayn app is published.

Customer flow:

1. In Retayn, choose `Google Workspace`.
2. Click `Open Google Workspace install`.
3. Approve Retayn as a Workspace admin.
4. Return to Retayn.
5. Enter only the Workspace domain.
6. Click `Finish connection`.

### Airtable

Retayn setup:

1. Go to `https://airtable.com/create/tokens`.
2. Click `Create token`.
3. Name it `Retayn Guard`.
4. Add scopes:
   - `schema.bases:read`
   - `data.records:read` only if you later want Retayn to inspect records
5. Add access to the specific base you want to monitor. Retayn uses this to read base collaborators, their permission levels, and the base schema.
6. Create the token and copy it.
7. For local testing, set `AIRTABLE_PERSONAL_ACCESS_TOKEN` in `guard/.env`.
8. Set `AIRTABLE_INSTALL_URL` to the Airtable OAuth authorization URL once the Retayn OAuth app is configured.

Customer flow:

1. In Retayn, choose `Airtable`.
2. Click `Open Airtable install`.
3. Approve Retayn in Airtable.
4. Return to Retayn.
5. Enter the Airtable base URL or the base ID, which starts with `app`.
6. Click `Finish connection`.

Retayn's normal Airtable connector monitors collaborators on the connected base. Full company-wide Airtable user and audit-log monitoring needs Airtable Enterprise Scale plus Enterprise API access.

## Recover

`Recover` creates a durable outreach case for access that is already lost. The owner provides the account facts, lockout history, contacts, ownership proof, and supporting documents. Before the case is saved, a permissive abuse review checks the typed fields and contacts for obvious spam, harassment, threats, trolling, extortion, or mass solicitation. It does not read document contents, and it should allow normal business disputes even when details are messy.

DeepSeek drafts the first message, then a second factual review checks the draft against the saved case. If either AI call fails or the factual review finds an unsupported claim, Retayn uses a deterministic message built only from the owner's fields.

The first message is never sent until the owner reviews it and clicks `Approve and start outreach`. Contacts are owner-supplied and capped at 30 per case. Retayn does not discover or message unrelated people.

Supported delivery adapters:

- Email through Retayn's SMTP support mailbox
- Telegram through Telethon/MTProto from a signed-in Retayn Telegram agent account
- Optional Telegram Bot API fallback, after the contact has started the bot and Retayn has their chat ID. This is not needed for normal MTProto account outreach.
- WhatsApp Cloud API, using an approved first-contact template. This path is prepared, but WhatsApp first-contact rules make it more fragile than email or Telegram.
- Support portals, phone calls, and other channels as tracked manual outreach

Incoming Telegram and WhatsApp webhooks are added to the matching contact conversation. Routine replies can receive one fact-locked AI response. Requests for proof create a draft and notify the owner before anything is sent. Access offers and received files stop automation, notify the owner, and make the files available from the case dashboard.

Recovery channel settings belong in `guard/.env`. Use the matching keys in `.env.example`. Public webhook URLs are:

```text
https://YOUR_DOMAIN/webhooks/recovery/YOUR_PRIVATE_WEBHOOK_TOKEN/telegram
https://YOUR_DOMAIN/webhooks/recovery/YOUR_PRIVATE_WEBHOOK_TOKEN/whatsapp
```

Telegram account setup:

1. Create a Telegram API app at `https://my.telegram.org`.
2. Put its `api_id` and `api_hash` in `RECOVERY_TELEGRAM_MTPROTO_API_ID` and `RECOVERY_TELEGRAM_MTPROTO_API_HASH`.
3. Keep `RECOVERY_TELEGRAM_MTPROTO_SESSION_PATH=recovery_telegram.session` for local testing.
4. Run `python setup_telegram_session.py` from the `guard` folder and complete the Telegram login prompts.
5. In recovery contacts, use a Telegram username, phone, chat, or entity that the signed-in agent account can message.
6. Use `Sync Telegram replies` in the Recover dashboard to pull recent replies from that signed-in Telegram account into the case conversations.

Email setup:

1. Create a mailbox for the recovery agent, such as `recovery@retayn.com`.
2. Put the SMTP host, username, password, sender email, port, and TLS setting in `guard/.env`.
3. Use the `Support email` contact channel for publisher support, developers, agencies, hosts, registrars, and other email contacts.

Evidence files are limited to 20 MB each and stored locally in `guard/recovery_uploads`. Production deployment should replace this with encrypted object storage and authenticated downloads.

### Zendesk

Retayn setup:

1. Open Zendesk Admin Center.
2. Go to `Apps and integrations` > `APIs` > `Zendesk API`.
3. Enable `Token access`.
4. Click `Add API token`.
5. Name it `Retayn Guard`.
6. Copy the token once it is shown.
7. For local testing, set `ZENDESK_EMAIL` and `ZENDESK_API_TOKEN` in `guard/.env`.
8. Set `ZENDESK_INSTALL_URL` to the Zendesk OAuth/app install URL once the Retayn app is configured.

Customer flow:

1. In Retayn, choose `Zendesk`.
2. Click `Open Zendesk install`.
3. Approve Retayn in Zendesk.
4. Return to Retayn.
5. Enter only your subdomain, for example `yourcompany` from `yourcompany.zendesk.com`.
6. Click `Finish connection`.

## Run The App

```powershell
cd C:\Users\ASUS\Downloads\retayn\guard
pip install -r requirements.txt
python retayn_app.py
```

Open `http://127.0.0.1:8787`.

## Quick Bot Token Setup

The local prototype currently reads a token from `.env`:

```env
GITHUB_TOKEN=github_pat_or_installation_token
GITHUB_APP_SLUG=retayn-guard-local
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY_PATH=retayn-guard-local.private-key.pem
AI_API_KEY=
AI_BASE_URL=https://api.deepseek.com
AI_MODEL=deepseek-chat
```

`GITHUB_APP_SLUG` is the slug in a GitHub App install URL like `https://github.com/apps/retayn-guard-local/installations/new`. It powers the dashboard's `Open GitHub install` button.

`GITHUB_APP_ID` is on the GitHub App settings page near the top. Generate a private key on that same page, download the `.pem`, place it in `guard/`, and set `GITHUB_PRIVATE_KEY_PATH` to the filename.

For a retail flow, the user pastes the GitHub repo URL, clicks `Open GitHub install`, approves/install Retayn in GitHub, returns to Retayn, then clicks `Finish connection`. The backend uses the GitHub App ID and private key to mint an installation token for that exact repo.

For a quick local test, use a fine-grained personal access token from a machine user with access only to the repos you want to monitor.

Minimum repository permissions for current features:

- `Metadata`: read
- `Administration`: read/write
- `Contents`: read

## GitHub App Setup

For a production-style Retayn connector, create a GitHub App:

1. Go to GitHub `Settings`.
2. Open `Developer settings`.
3. Open `GitHub Apps`.
4. Click `New GitHub App`.
5. Set `GitHub App name` to something like `Retayn Guard Local`.
6. Set `Homepage URL` to your Retayn site URL, or `http://127.0.0.1:8787` for local testing.
7. For `Callback URL`, use `http://127.0.0.1:8787/github/callback` for now. The current local app does not complete OAuth yet, but this keeps the app registration ready.
8. Turn `Expire user authorization tokens` on.
9. Turn `Request user authorization (OAuth) during installation` off for now.
10. Under `Webhook`, leave it inactive for this polling prototype. When you deploy a public webhook endpoint, activate it and use a strong random webhook secret.
11. Under `Repository permissions`, set:
    - `Administration`: read/write
    - `Contents`: read
    - `Metadata`: read-only, always included by GitHub
12. Optional future permissions:
    - `Actions`: read, if Retayn will monitor workflow runs and Actions abuse
    - `Deployments`: read, if Retayn will monitor deployment changes
    - `Secrets`: read, if available for the exact alerting surface you build
13. Under `Subscribe to events`, when webhooks are active, select:
    - `Branch protection rule`
    - `Member`
    - `Public`
    - `Repository`
    - `Repository ruleset`
    - `Deploy key`
    - `Repository vulnerability alert`, if you add vulnerability monitoring
    - `Workflow run`, if you add Actions monitoring
14. Click `Create GitHub App`.
15. On the app page, click `Generate a private key` and store the `.pem` securely.
16. Click `Install App`.
17. Install it only on selected repositories.
18. For this local prototype, either continue using a fine-grained PAT or mint a GitHub App installation access token externally and put that token in `GITHUB_TOKEN`.

The app registration is the right long-term route because GitHub Apps support granular repository installation and webhook delivery. This local prototype still uses a single token value for API calls.

Retayn initializes each app baseline from the repo's current users, webhook URLs, and write deploy keys. You can see and edit that baseline under `My apps`.

## Dashboard Actions

- `Approve`: mark the notification as safe and update the baseline.
- `Take action`: immediately run the supported connector action.
- `Ignore`: close the notification without changing the app.

If `Take supported action if untouched` is enabled, Retayn waits for the dashboard delay before taking supported actions automatically.
