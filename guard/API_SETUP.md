# Retayn Connector API Setup

Retayn is meant to be retail-simple for customers: they click `Open install`, approve Retayn, then return to the dashboard. These steps are for Retayn's owner/developer to create the provider apps behind that install button.

For every connector:

1. Create a Retayn-owned app, OAuth app, marketplace app, service account, or API integration in the provider's developer console.
2. Add the callback URL if OAuth is supported: `https://YOUR_RETAYN_DOMAIN/oauth/CONNECTOR/callback`.
3. Request the smallest read-only scopes that can list admins, owners, users, roles, domains, webhooks, deploy keys, app credentials, projects, billing contacts, and release controls.
4. Add the client ID, client secret, install URL, API key, or service-account details to `guard/.env`.
5. Implement the connector's OAuth start/callback, token exchange, encrypted token storage, baseline collector, scan function, and safe actions.
6. Test with a real customer-like account, then remove `coming_soon` from that connector in `retayn_app.py`.

## Live Or Partially Live Connectors

### GitHub

1. Open GitHub `Settings > Developer settings > GitHub Apps`.
2. Create a GitHub App named Retayn.
3. Add callback URL `https://YOUR_RETAYN_DOMAIN/oauth/github/callback` if you later add GitHub OAuth.
4. Add webhook URL `https://YOUR_RETAYN_DOMAIN/webhooks/github`.
5. Give repository permissions for metadata, contents read, administration read/write if actions are enabled, members read/write if actions are enabled, webhooks read/write if actions are enabled, deploy keys read/write if actions are enabled, and actions read.
6. Subscribe to repository, member, team, branch protection, deployment key, and webhook events where available.
7. Generate a private key and set `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, and either `GITHUB_PRIVATE_KEY_PATH` or `GITHUB_PRIVATE_KEY`.
8. Customers install the GitHub App on selected repositories.

### Slack

1. Open `https://api.slack.com/apps`.
2. Create a Retayn Slack app.
3. Add OAuth redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/slack/callback`.
4. Add bot scopes such as `users:read`, `users:read.email`, `team:read`, and any admin scopes Slack approves for your app.
5. Install the app to a test workspace.
6. Put `SLACK_CLIENT_ID` and `SLACK_CLIENT_SECRET` in `.env`.
7. Customers click `Open install` and approve Retayn in Slack.

### Airtable

1. Open Airtable Developer Hub.
2. Create an OAuth integration for Retayn.
3. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/airtable/callback`.
4. Request scopes for reading bases, schemas, and collaborators where Airtable exposes them.
5. Add the required base access setting for customer-selected bases.
6. Put `AIRTABLE_CLIENT_ID` and `AIRTABLE_CLIENT_SECRET` in `.env`.
7. Customers approve Retayn and then paste the base URL.

### Zendesk

1. In Zendesk Admin Center, open `Apps and integrations > APIs > Zendesk API > OAuth Clients`.
2. Create a Retayn OAuth client.
3. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/zendesk/callback`.
4. Copy the unique identifier, client ID, and secret.
5. Put `ZENDESK_CLIENT_ID` and `ZENDESK_CLIENT_SECRET` in `.env`.
6. Customers authorize Retayn from their Zendesk subdomain.

### Shopify

1. Create a Shopify app in the Shopify Partner dashboard.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/shopify/callback`.
3. Request the least read-only Admin API scopes available for shop identity, domains, locations, users if available, and app reachability.
4. Put `SHOPIFY_CLIENT_ID` and `SHOPIFY_CLIENT_SECRET` in `.env`.
5. Customers install Retayn from the Shopify OAuth install flow and enter their `myshopify.com` domain.

## Prepared Connectors

### Google Workspace

1. Create a Google Cloud project.
2. Configure OAuth consent for Retayn.
3. Create a Web OAuth client.
4. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/google-workspace/callback`.
5. Enable Admin SDK API.
6. Request Admin SDK Directory read-only scopes for users and roles.
7. Put `GOOGLE_WORKSPACE_CLIENT_ID` and `GOOGLE_WORKSPACE_CLIENT_SECRET` in `.env`.

### Meta / Facebook

1. Open Meta for Developers and create a Retayn app.
2. Add Facebook Login or Facebook Login for Business.
3. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/meta-facebook/callback`.
4. Add your Retayn domain in app basic settings.
5. Request Page, Business, and Instagram professional-account permissions such as `pages_show_list`, `pages_read_engagement`, `business_management`, and `instagram_basic`.
6. Submit App Review before using it with customers outside test roles.
7. Put `META_FACEBOOK_CLIENT_ID` and `META_FACEBOOK_CLIENT_SECRET` in `.env`.

### Instagram

1. Use the same Meta app as Meta / Facebook.
2. Require customers to connect a Business or Creator Instagram account to a Facebook Page.
3. Request Instagram Graph API permissions such as `instagram_basic` plus Page permissions needed to discover linked assets.
4. Baseline the Instagram professional account, linked Page, Page admins, and publishing permissions.
5. Use `INSTAGRAM_INSTALL_URL` only if you split Instagram into a separate customer install entry.

### LinkedIn

1. Open LinkedIn Developer Apps and create a Retayn app.
2. In the Auth tab, add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/linkedin/callback`.
3. Add OpenID Connect scopes for sign-in identity: `openid`, `profile`, `email`.
4. Request organization/Page administration access through LinkedIn's approved products when available.
5. Put `LINKEDIN_CLIENT_ID` and `LINKEDIN_CLIENT_SECRET` in `.env`.

### GitLab

1. Create a GitLab OAuth application.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/gitlab/callback`.
3. Request `read_api` first.
4. Baseline groups, projects, members, deploy keys, protected branches, webhooks, and project access tokens where available.
5. Add `GITLAB_INSTALL_URL` when the OAuth route is implemented.

### Bitbucket

1. Create a Bitbucket OAuth consumer.
2. Add callback URL `https://YOUR_RETAYN_DOMAIN/oauth/bitbucket/callback`.
3. Request read permissions for account, workspace, repositories, webhooks, and pull requests.
4. Baseline workspace members, repo permissions, branch restrictions, webhooks, and app passwords where available.

### Microsoft 365

1. Create a Microsoft Entra app registration.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/microsoft-365/callback`.
3. Add Microsoft Graph permissions for reading users, groups, directory roles, apps, and organization data.
4. Use admin consent for tenant-wide monitoring.
5. Baseline users, admins, groups, guests, app registrations, and recovery ownership.

### Microsoft Teams

1. Use the Microsoft Entra app registration.
2. Add Graph permissions for reading Teams, channels, members, owners, and guests.
3. Baseline team owners, members, guests, external access, and connected apps.
4. Add `TEAMS_INSTALL_URL` after the Teams-specific OAuth route exists.

### Apple Developer

1. Open App Store Connect `Users and Access > Integrations`.
2. Create an App Store Connect API key.
3. Record issuer ID, key ID, and private key.
4. Invite the Retayn integration with the least role that can read users, certificates, identifiers, profiles, and apps.
5. Baseline team members, roles, certificates, profiles, bundle IDs, and app records.

### Google Play Console

1. Create a Google Cloud service account for Retayn.
2. In Play Console, invite the service account under Users and permissions.
3. Give least read-only app and account permissions.
4. Enable the Google Play Developer API.
5. Baseline users, app permissions, service accounts, release tracks, and package access.

### npm

1. Create an npm organization or package automation token for Retayn testing.
2. Prefer OAuth or granular access tokens when npm exposes the needed monitoring path.
3. Baseline package maintainers, organization owners, publish tokens, and trusted publishing.
4. Treat write tokens as signing/release material and store only encrypted metadata.

### PyPI

1. Create or use a PyPI project API token for testing.
2. Prefer Trusted Publishing metadata where available.
3. Baseline project owners, maintainers, publishing methods, and API tokens.
4. Alert on owner/maintainer changes or new publish methods.

### Docker Hub

1. Create a Docker Hub personal access token or organization integration for Retayn.
2. Request organization and repository read access.
3. Baseline organization owners, teams, repositories, webhooks, and access tokens where visible.

### AWS

1. Create an IAM role for Retayn with external ID.
2. Give read-only IAM, Organizations, billing-contact, CloudTrail, Route 53, and resource-inventory permissions as needed.
3. Customer authorizes by creating the role from a CloudFormation template.
4. Baseline IAM users, roles, root safety, access keys, billing contacts, Route 53 zones, and production resources.

### Azure

1. Create a multi-tenant Microsoft Entra app registration.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/azure/callback`.
3. Request Graph and Azure Resource Manager read scopes.
4. Customer grants tenant/admin consent.
5. Baseline subscriptions, role assignments, app registrations, groups, and resource groups.

### Google Cloud

1. Create a Google Cloud OAuth client or service-account onboarding flow.
2. Enable Cloud Resource Manager, IAM, Service Usage, Billing, and Cloud Asset APIs as needed.
3. Customer grants Retayn read-only project/folder/org access.
4. Baseline IAM bindings, service accounts, projects, billing account links, and deploy resources.

### Cloudflare

1. Create a Cloudflare OAuth app or API token template.
2. Request read scopes for account members, zones, DNS, Workers, Pages, registrar, and billing where available.
3. Baseline account members, zones, DNS records, registrar lock, Workers, Pages, and API tokens where visible.

### Vercel

1. Create a Vercel integration.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/vercel/callback`.
3. Request read access for teams, projects, deployments, domains, env vars metadata, and webhooks.
4. Baseline team members, projects, domains, production deployments, env access, and integrations.

### Netlify

1. Create a Netlify OAuth app.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/netlify/callback`.
3. Request read access for accounts, members, sites, deploys, domains, hooks, and environment metadata.
4. Baseline teams, sites, collaborators, domains, deploy hooks, and build settings.

### Supabase

1. Create a Supabase access token or OAuth integration when available.
2. Request organization and project read access.
3. Baseline organization members, projects, database roles, API keys metadata, and auth settings.

### Firebase

1. Use the Google Cloud app/service account path.
2. Enable Firebase Management API and related Google Cloud APIs.
3. Baseline project users, service accounts, hosting sites, app distribution, and app registrations.

### Stripe

1. Create a Stripe app in Stripe Apps.
2. Add the OAuth redirect URL if using OAuth.
3. Request read access to team roles, account data, API keys metadata, webhooks, payout settings, and connected accounts as needed.
4. Baseline users, roles, webhooks, API key metadata, payout settings, and account ownership.

### PayPal

1. Create a PayPal REST app in the PayPal Developer dashboard.
2. Configure OAuth/app credentials.
3. Request business account read scopes available for users, apps, webhooks, and payouts.
4. Baseline business users, API apps, webhook endpoints, payout access, and account contacts.

### GoDaddy

1. Create GoDaddy API keys.
2. Request read access for domains, DNS, contacts, and renewals where available.
3. Baseline domains, DNS records, registrar lock, delegated access, contacts, and renewal state.

### Namecheap

1. Enable Namecheap API access for the Retayn account.
2. Add the server IP allowlist required by Namecheap.
3. Request domain, DNS, contacts, and security status reads.
4. Baseline domains, DNS records, contacts, renewal status, and account security.

### Squarespace

1. Use Squarespace developer/API access where available.
2. Prefer OAuth or an approved app integration.
3. Baseline contributors, domains, billing state, store access, and site ownership.

### Webflow

1. Create a Webflow app.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/webflow/callback`.
3. Request read scopes for sites, workspaces, users, domains, and publishing.
4. Baseline workspace members, site roles, domains, publishing access, and integrations.

### CircleCI

1. Create a CircleCI OAuth app or use API token setup for the prototype.
2. Request read access to organizations, projects, contexts, environment-variable metadata, and pipelines.
3. Baseline organization users, projects, contexts, env var metadata, and pipeline settings.

### Buildkite

1. Create a Buildkite OAuth app.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/buildkite/callback`.
3. Request read scopes for organizations, teams, agents, pipelines, and secrets metadata.
4. Baseline members, teams, agents, pipelines, and deployment control.

### Heroku

1. Create a Heroku OAuth client.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/heroku/callback`.
3. Request read access for teams, apps, collaborators, pipelines, config var metadata, and add-ons.
4. Baseline teams, apps, collaborators, pipelines, add-ons, and deployment settings.

### DigitalOcean

1. Create a DigitalOcean OAuth app.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/digitalocean/callback`.
3. Request read access to account, teams, projects, droplets, databases, domains, and tokens metadata.
4. Baseline team members, projects, resources, domains, and API token metadata.

### Twilio

1. Create a Twilio API key for Retayn or an OAuth app where available.
2. Request account read access.
3. Baseline users, subaccounts, API keys metadata, phone numbers, messaging services, and billing access.

### SendGrid

1. Create a SendGrid API key with least read access.
2. Request access to users, API keys metadata, senders, verified domains, and webhooks.
3. Baseline users, keys, sender authentication, domains, and mail settings.

### Mailchimp

1. Create a Mailchimp OAuth app.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/mailchimp/callback`.
3. Request account, user, audience, API key metadata, and domain read scopes.
4. Baseline account users, audiences, sending domains, connected sites, and integrations.

### HubSpot

1. Create a HubSpot public app.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/hubspot/callback`.
3. Request read scopes for users, settings, CRM objects, forms, domains, and integrations as needed.
4. Baseline super admins, users, connected apps, domains, forms, and CRM ownership.

### Intercom

1. Create an Intercom app.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/intercom/callback`.
3. Request read scopes for admins, teammates, teams, conversations, and app settings.
4. Baseline admins, teammates, inboxes, connected apps, and support ownership.

### Calendly

1. Create a Calendly OAuth app.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/calendly/callback`.
3. Request organization, users, event types, routing forms, and webhook read scopes.
4. Baseline organization admins, users, integrations, routing forms, and booking ownership.

### Notion

1. Create a Notion public integration.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/notion/callback`.
3. Request workspace and user capabilities available to public integrations.
4. Baseline workspace owners, members, shared pages, databases, and integrations where visible.

### Linear

1. Create a Linear OAuth application.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/linear/callback`.
3. Request read scopes for organization, users, teams, and integrations.
4. Baseline admins, members, teams, and connected integrations.

### Asana

1. Create an Asana OAuth app.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/asana/callback`.
3. Request read scopes for workspaces, users, teams, projects, and guests.
4. Baseline workspace admins, members, guests, teams, and critical projects.

### Jira / Atlassian

1. Create an Atlassian OAuth 2.0 app.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/jira/callback`.
3. Request read scopes for users, groups, projects, apps, and site administration where approved.
4. Baseline site admins, groups, project admins, connected apps, and workflow ownership.

### WordPress

1. For WordPress.com, create an OAuth app.
2. For self-hosted WordPress, build a Retayn plugin that exposes a secure signed monitoring endpoint.
3. Baseline administrators, users, plugins, themes, domains, webhooks, and site health.
4. Customers install the plugin or approve OAuth, then paste the site URL.

### Wix

1. Create a Wix app in the Wix Developers Center.
2. Add redirect URL `https://YOUR_RETAYN_DOMAIN/oauth/wix/callback`.
3. Request read scopes for sites, collaborators, domains, business settings, and stores.
4. Baseline collaborators, domains, business settings, store access, and publishing ownership.
