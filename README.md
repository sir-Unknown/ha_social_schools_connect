# Social Schools Connect

Unofficial custom integration for Home Assistant that connects to Social Schools (`socialschools.eu`) and exposes sensors for your account.

## What do you get?

- A sensor for the logged-in user (with `email` and `roles` as attributes)
- A sensor for community posts (count + details of the latest posts)

The integration uses an OAuth2 login flow (PKCE) and stores only a `refresh_token` in Home Assistant. Your username and password are only used during setup and reauthentication.

## Installation

### HACS (custom repository)

1. Go to HACS → Integrations → ⋮ → Custom repositories
2. Add `sir-Unknown/ha_social_schools_connect` as type `Integration`
3. Install and restart Home Assistant

### Manual

Copy `custom_components/social_schools_connect` to your Home Assistant `config/custom_components/` and restart Home Assistant.

## Configuration

Go to Settings → Devices & services → Add integration → `Social Schools`.

Enter your Social Schools username and password. If authentication expires, Home Assistant will ask you to sign in again (reauth).

## Entities

### User

- State: `displayName` (or `username`)
- Attributes: `email`, `roles`

### Community posts

- State: `totalCount`
- Attributes:
  - `totalCount`
  - `latest_id`, `latest_title`, `latest_created`, `latest_body` (max 500 characters), `latest_community`, `latest_author`
  - `posts` (compact list of posts for templates and automations)

Note: the posts sensor can include (parts of) message content as attributes. Be careful when sharing screenshots/logs.

## Polling interval

By default, the integration polls every 5 minutes.

## Troubleshooting

Enable debug logging in `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.social_schools_connect: debug
```

## Disclaimer

This integration is not affiliated with Social Schools and uses an unofficial login/API. Changes to the website/API can break the integration.

## Translations

Home Assistant UI translations are included for English and Dutch.

## License

MIT (see `LICENSE`).
