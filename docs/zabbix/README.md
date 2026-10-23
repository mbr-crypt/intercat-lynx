# Zabbix integration

Zabbix **pulls** the numbers from Lynx (HTTP agent items). Lynx needs no access to Zabbix.

## 1. Follow products and create a token

1. In Lynx open **My Products** and follow the vendors and products you run.
2. In the card **API access** create a token (name e.g. `zabbix`). It is shown **once**, copy it.
   The token is read-only: it can only call the three `/api/v1/zabbix/` endpoints below, nothing else.
   It reports the products of the user who created it.

## 2. Import the template

Import `InterCat_Lynx_by_HTTP.yaml` in Zabbix (Data collection > Templates > Import), link it to a host
and set the host macros:

| Macro | Value |
|---|---|
| `{$LYNX.URL}` | base address of Lynx, e.g. `https://lynx.example.org` (no trailing slash) |
| `{$LYNX.TOKEN}` | the token (type *Secret text*) |
| `{$LYNX.INTERVAL}` | polling interval, default `5m` |

> The template was written by hand against the Zabbix 6.0 export format and has not been imported into a
> live Zabbix yet. If the import complains, the endpoints below are all you need to build the items yourself.

It creates: counters for all followed products, one item set per followed product (found automatically
through low-level discovery, refreshed hourly), and triggers for new critical CVEs and actively exploited
CVEs.

## Endpoints

All need `Authorization: Bearer lynx_...`.

| Path | Content |
|---|---|
| `GET /api/v1/zabbix/summary` | totals over all followed products |
| `GET /api/v1/zabbix/products` | `{"items": [...]}`, same counters per followed product |
| `GET /api/v1/zabbix/discovery` | `{"data": [{"{#KEY}", "{#VENDOR}", "{#PRODUCT}", "{#LABEL}"}]}` for low-level discovery |

Counters: `new_24h`, `critical_24h`, `high_24h`, `exploited_24h`, `new_7d`, `critical_7d`, `high_7d`,
`exploited_7d`, `max_cvss_7d`. "New" means published in that window. Test by hand:

```
curl -H "Authorization: Bearer lynx_..." https://lynx.example.org/api/v1/zabbix/summary
```

## Internal Zabbix server

If Zabbix reaches Lynx over a private network nothing special is needed here. (The setting
`WEBHOOK_ALLOW_PRIVATE_NETWORKS` is only for the opposite direction: Lynx pushing a *webhook* to an
internal address.)
