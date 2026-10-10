"""Make LiveKit access tokens for the EVT2 test app (standard library only).

The API key and secret are read from the environment, never from the command line or the repo:

    set LIVEKIT_API_KEY=APIxxxxxxxx
    set LIVEKIT_API_SECRET=xxxxxxxxxxxxxxxx
    py -3 tools/make_token.py --room evt2-test phone1 phone2

Each identity gets one token (valid --hours, default 24) that may join, publish, subscribe, send data and set its
own attributes in --room.
Paste the token into the app's "URL & Token" tab together with the project URL (wss://<project>.livekit.cloud).
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(api_key: str, api_secret: str, identity: str, room: str, ttl_s: int) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {
        "iss": api_key,
        "sub": identity,
        "name": identity,
        "nbf": now - 10,
        "exp": now + ttl_s,
        "video": {
            "room": room,
            "roomJoin": True,
            "canPublish": True,
            "canSubscribe": True,
            "canPublishData": True,
            # the app publishes its E2EE mode as a participant attribute (mode mismatch warning)
            "canUpdateOwnMetadata": True,
        },
    }
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode())
                     + "." + b64url(json.dumps(claims, separators=(",", ":")).encode()))
    sig = hmac.new(api_secret.encode(), signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + b64url(sig)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("identities", nargs="+", help="participant identities, one token each")
    ap.add_argument("--room", default="evt2-test")
    ap.add_argument("--hours", type=float, default=24.0)
    args = ap.parse_args()

    api_key = os.environ.get("LIVEKIT_API_KEY")
    api_secret = os.environ.get("LIVEKIT_API_SECRET")
    if not api_key or not api_secret:
        print("Set LIVEKIT_API_KEY and LIVEKIT_API_SECRET first.", file=sys.stderr)
        return 1

    for identity in args.identities:
        print(f"{identity}: {make_token(api_key, api_secret, identity, args.room, int(args.hours * 3600))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
