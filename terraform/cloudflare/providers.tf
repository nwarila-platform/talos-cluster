# The API token is read from CLOUDFLARE_API_TOKEN; it is never written to files.
# Scopes it needs: Account > Cloudflare Tunnel: Edit, Zone > DNS: Edit on the
# zone, Zone > Zone: Read.
provider "cloudflare" {}
