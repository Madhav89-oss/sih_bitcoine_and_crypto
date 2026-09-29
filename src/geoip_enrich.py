"""
Offline GeoIP enrichment using MaxMind's GeoLite2 database format (.mmdb).

This module looks for database files in this priority order:
  1. A path passed explicitly to GeoIPEnricher(city_db_path=..., asn_db_path=...)
  2. ./geoip_data/GeoLite2-City.mmdb and ./geoip_data/GeoLite2-ASN.mmdb next to this file
     (drop your own free-tier MaxMind downloads here for the most current data)
  3. The GeoLite2-City database bundled by the `maxminddb-geolite2` pip package, as an
     offline fallback so the pipeline works out-of-the-box with zero manual setup.

To get current data instead of the bundled fallback:
  1. Create a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
  2. Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb
  3. Place both files in geoip_data/ next to this script

No network access is required at runtime either way — this is a pure local file lookup.
"""
import os

import maxminddb

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_CITY_DB = os.path.join(THIS_DIR, "geoip_data", "GeoLite2-City.mmdb")
LOCAL_ASN_DB = os.path.join(THIS_DIR, "geoip_data", "GeoLite2-ASN.mmdb")


def _bundled_city_db_fallback():
    try:
        import geolite2
        return geolite2.geolite2_database()
    except Exception:
        return None


class GeoIPEnricher:
    def __init__(self, city_db_path: str = None, asn_db_path: str = None):
        city_path = city_db_path or (LOCAL_CITY_DB if os.path.exists(LOCAL_CITY_DB) else None)
        if city_path is None:
            city_path = _bundled_city_db_fallback()
        asn_path = asn_db_path or (LOCAL_ASN_DB if os.path.exists(LOCAL_ASN_DB) else None)

        self.city_reader = maxminddb.open_database(city_path) if city_path else None
        self.asn_reader = maxminddb.open_database(asn_path) if asn_path else None
        self.using_bundled_fallback = city_db_path is None and not os.path.exists(LOCAL_CITY_DB)

    def lookup(self, ip: str) -> dict:
        """Returns {country_iso, country_name, latitude, longitude, asn, asn_org}.
        Any field defaults to None if not resolvable (private/reserved IP, no ASN db, etc)."""
        result = {
            "country_iso": None, "country_name": None,
            "latitude": None, "longitude": None,
            "asn": None, "asn_org": None,
        }
        if self.city_reader is not None:
            try:
                rec = self.city_reader.get(ip)
            except (ValueError, Exception):
                rec = None
            if rec:
                country = rec.get("country", {}) or rec.get("registered_country", {})
                result["country_iso"] = country.get("iso_code")
                result["country_name"] = (country.get("names") or {}).get("en")
                loc = rec.get("location", {})
                result["latitude"] = loc.get("latitude")
                result["longitude"] = loc.get("longitude")

        if self.asn_reader is not None:
            try:
                rec = self.asn_reader.get(ip)
            except (ValueError, Exception):
                rec = None
            if rec:
                result["asn"] = rec.get("autonomous_system_number")
                result["asn_org"] = rec.get("autonomous_system_organization")

        return result

    def enrich_dataframe(self, df, ip_column: str = "src_ip"):
        """Adds country_iso, country_name, asn, asn_org columns derived from ip_column."""
        lookups = df[ip_column].apply(self.lookup)
        df = df.copy()
        df["country_iso"] = lookups.apply(lambda r: r["country_iso"])
        df["country_name"] = lookups.apply(lambda r: r["country_name"])
        df["asn"] = lookups.apply(lambda r: r["asn"])
        df["asn_org"] = lookups.apply(lambda r: r["asn_org"])
        return df


if __name__ == "__main__":
    enricher = GeoIPEnricher()
    print("Using bundled fallback DB:", enricher.using_bundled_fallback)
    for test_ip in ["8.8.8.8", "1.1.1.1", "203.0.113.5", "10.0.0.1"]:
        print(test_ip, "->", enricher.lookup(test_ip))
