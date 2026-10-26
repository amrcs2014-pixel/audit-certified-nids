"""Create a Zenodo DRAFT for audit-certified-nids v0.1.0: upload the zip, set the metadata, reserve the DOI.
It never publishes. Review the draft on zenodo.org and press Publish there yourself.

The token is read from the ZENODO_TOKEN environment variable (or release/.zenodo_token, used once then deleted,
or a hidden prompt) and is never printed. Create one at
https://zenodo.org/account/settings/applications/tokens/new/ with scopes deposit:write and deposit:actions.

  python release/zenodo_upload.py [--creator "Family, Given"] [--affiliation "..."] [--orcid 0000-...]
"""
import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://zenodo.org/api"
HERE = os.path.dirname(os.path.abspath(__file__))
ZIP = os.path.join(HERE, "audit-certified-nids-v0.1.0.zip")
REPO = "https://github.com/amrcs2014-pixel/audit-certified-nids"
VERSION = "0.1.0"


def call(method, url, token, data=None, raw=None, ctype="application/json"):
    body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        sys.exit(f"Zenodo API error {e.code} on {method} {url.split('?')[0]}: {e.read().decode()[:800]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--creator", default="Abdelhaliem, Amr H.", help='"Family, Given"')
    ap.add_argument("--affiliation", default="Irbid National University")
    ap.add_argument("--orcid", default=None)
    a = ap.parse_args()
    if not os.path.exists(ZIP):
        sys.exit(f"missing {ZIP}; build it first:\n"
                 f"  git archive --format=zip --prefix=audit-certified-nids-v{VERSION}/ v{VERSION} "
                 f"-o {os.path.basename(ZIP)}")
    tok_file = os.path.join(HERE, ".zenodo_token")
    token = os.environ.get("ZENODO_TOKEN")
    if not token and os.path.exists(tok_file):
        token = open(tok_file, encoding="utf-8-sig").read().strip()
        os.remove(tok_file)                       # used once, never left on disk
        print("token read from release/.zenodo_token (file deleted)")
    if not token:
        token = getpass.getpass("Zenodo token (hidden): ")
    meta_src = json.load(open(os.path.join(os.path.dirname(HERE), ".zenodo.json"), encoding="utf8"))
    creator = {"name": a.creator}
    if a.affiliation:
        creator["affiliation"] = a.affiliation
    if a.orcid:
        creator["orcid"] = a.orcid

    dep = call("POST", f"{API}/deposit/depositions", token, data={})
    print("draft created, id", dep["id"])
    with open(ZIP, "rb") as f:
        call("PUT", f"{dep['links']['bucket']}/{os.path.basename(ZIP)}", token, raw=f.read(),
             ctype="application/octet-stream")
    print("uploaded", os.path.basename(ZIP))
    metadata = {
        "upload_type": "software",
        "title": meta_src["title"],
        "description": meta_src["description"],
        "creators": [creator],
        "version": VERSION,
        "license": "mit",
        "keywords": meta_src["keywords"],
        "related_identifiers": [{"identifier": f"{REPO}/tree/v{VERSION}", "relation": "isSupplementTo",
                                 "resource_type": "software"}],
        "prereserve_doi": True,
    }
    out = call("PUT", f"{API}/deposit/depositions/{dep['id']}", token, data={"metadata": metadata})
    doi = out.get("metadata", {}).get("prereserve_doi", {}).get("doi")
    print("metadata set; reserved DOI:", doi)
    print("review and publish the draft here:", out.get("links", {}).get("html"))
    json.dump({"id": dep["id"], "doi": doi, "html": out.get("links", {}).get("html")},
              open(os.path.join(HERE, "zenodo_draft.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
