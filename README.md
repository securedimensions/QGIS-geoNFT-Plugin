# geoNFT plugin for QGIS (experimental)

Sign QGIS in to the geoNFT portal, map the observations of the drone deployments you hold a license for, and
verify them against the deployment NFT on the ledger.

Requires QGIS 4.0 or newer, a geoNFT portal account (https://portal.geonft.eu) and a license for each deployment
you want to open.

## Use

1. Plugins › geoNFT plugin › geoNFT plugin (or the toolbar button) opens the geoNFT panel.
2. **Sign in** opens your system browser. The first time, the plugin asks you to accept the terms of use.
3. **Refresh** lists your licensed deployments; **Show observations** draws the selected one on an OpenStreetMap
   base map. Click a dot to see its telemetry or picture.
4. **Verify against ledger** checks the deployment against its NFT; results go into the `chain_check` column.

## Settings

Stored in the QGIS settings group `geonft` (Settings › Options › Advanced):

| Key | Default |
|---|---|
| `issuer` | `https://portal.geonft.eu/realms/customers` |
| `portal_url` | derived from the issuer |
| `cs_url` | `https://cs.geonft.eu` |
| `ledger_url` | `https://ledger.geonft.eu` |
| `indy_resolver_url` | `https://resolver.geonft.eu` |

Settings of the earlier *Certificate review* plugin (group `cs_review`) are moved on first start.

## Privacy, terms, cookies

See [docs/privacy.html](docs/privacy.html), [docs/terms.html](docs/terms.html) and
[docs/cookies.html](docs/cookies.html), also shown in Plugins › geoNFT plugin. The plugin contains no analytics or
tracking and connects only after the terms are accepted.

## Development

Unit tests run with plain Python, without QGIS:

    cd geonft_plugin && python3 -m unittest discover -p 'test_*.py'

Build the release zip (tests and fixtures are left out) with `python3 ../build.py`.

## License

GNU General Public License, version 2 or later. See [LICENSE](LICENSE).
